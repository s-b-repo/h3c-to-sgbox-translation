"""
SGBox-Compatible GPG Encryption Module

Provides GPG encryption at rest for translated log files, matching
SGBox's encryption scheme:

    - At rest: Logs are encrypted using GPG (GNU Privacy Guard) before
      being written to disk.
    - Supports both symmetric (passphrase) and asymmetric (key-based)
      encryption.
    - Async-friendly: encrypt/decrypt run in executor to avoid blocking
      the event loop.

SGBox stores raw logs on the filesystem in GPG-encrypted format.
This module replicates that behaviour so translated logs are stored
identically.

Dependencies: python-gnupg (wrapper around the gpg CLI)
"""

import asyncio
import os
from pathlib import Path

import gnupg
import structlog

logger = structlog.get_logger(__name__)


class SGBoxEncryption:
    """
    GPG encryption/decryption engine compatible with SGBox's at-rest scheme.

    Supports:
        - Symmetric encryption (passphrase-based, AES256)
        - Asymmetric encryption (recipient key-based)
        - Batch encrypt/decrypt for log rotation
        - Async wrappers for non-blocking I/O

    Usage:
        enc = SGBoxEncryption(config)
        # Encrypt a single log line or block
        ciphertext = await enc.encrypt("proto=TCP src=10.1.1.10 ...")
        # Decrypt
        plaintext = await enc.decrypt(ciphertext)
        # Encrypt an entire log file at rest
        await enc.encrypt_file("/var/log/h3c-translator/translated.log")
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Parsed config dict. Reads from [encryption] section:
                - enabled: true/false
                - gpg_home: GPG keyring directory (default: ~/.gnupg)
                - gpg_binary: Path to gpg binary (default: gpg)
                - mode: symmetric | asymmetric (default: symmetric)
                - passphrase: For symmetric mode
                - recipient: GPG key ID or email for asymmetric mode
                - cipher_algo: GPG cipher (default: AES256)
                - armor: true/false — ASCII-armored output (default: false)
                - encrypt_output: true/false — encrypt forwarded logs
                - encrypted_log_dir: Where to store encrypted logs
        """
        enc_config = config.get("encryption", {})
        self.enabled = enc_config.get("enabled", "false").lower() == "true"

        if not self.enabled:
            logger.info("encryption.disabled")
            self._gpg = None
            return

        gpg_home = enc_config.get("gpg_home", os.path.expanduser("~/.gnupg"))
        gpg_binary = enc_config.get("gpg_binary", "gpg")

        self._gpg = gnupg.GPG(
            gnupghome=gpg_home,
            gpgbinary=gpg_binary,
            use_agent=False,
        )

        self._mode = enc_config.get("mode", "symmetric").lower()
        self._passphrase = enc_config.get("passphrase", "")
        self._recipient = enc_config.get("recipient", "")
        self._cipher_algo = enc_config.get("cipher_algo", "AES256")
        self._armor = enc_config.get("armor", "false").lower() == "true"
        self._encrypt_output = enc_config.get("encrypt_output", "false").lower() == "true"
        self._encrypted_log_dir = enc_config.get(
            "encrypted_log_dir", "/var/log/h3c-translator/encrypted"
        )

        # Validate config
        if self._mode == "symmetric" and not self._passphrase:
            raise ValueError(
                "[encryption] mode=symmetric requires a 'passphrase' in config"
            )
        if self._mode == "asymmetric" and not self._recipient:
            raise ValueError(
                "[encryption] mode=asymmetric requires a 'recipient' key ID in config"
            )

        # Ensure encrypted log directory exists
        os.makedirs(self._encrypted_log_dir, exist_ok=True)

        logger.info("encryption.enabled",
                     mode=self._mode,
                     cipher=self._cipher_algo,
                     armor=self._armor,
                     log_dir=self._encrypted_log_dir)

    # ── Core encrypt/decrypt ───────────────────────────────────────

    def encrypt_sync(self, plaintext: str) -> str:
        """
        Encrypt plaintext using GPG (synchronous).

        Returns encrypted data as a string (armored or binary depending on config).
        """
        if not self.enabled or not self._gpg:
            return plaintext

        if self._mode == "symmetric":
            result = self._gpg.encrypt(
                plaintext,
                recipients=None,
                symmetric=self._cipher_algo,
                passphrase=self._passphrase,
                armor=self._armor,
            )
        else:
            result = self._gpg.encrypt(
                plaintext,
                recipients=[self._recipient],
                armor=self._armor,
            )

        if not result.ok:
            logger.error("encryption.encrypt_failed",
                          status=result.status,
                          stderr=result.stderr)
            raise RuntimeError(f"GPG encryption failed: {result.status}")

        return str(result)

    def decrypt_sync(self, ciphertext: str) -> str:
        """
        Decrypt GPG-encrypted data (synchronous).

        Returns the plaintext string.
        """
        if not self.enabled or not self._gpg:
            return ciphertext

        result = self._gpg.decrypt(
            ciphertext,
            passphrase=self._passphrase if self._mode == "symmetric" else None,
        )

        if not result.ok:
            logger.error("encryption.decrypt_failed",
                          status=result.status,
                          stderr=result.stderr)
            raise RuntimeError(f"GPG decryption failed: {result.status}")

        return str(result)

    # ── Async wrappers ─────────────────────────────────────────────

    async def encrypt(self, plaintext: str) -> str:
        """Async encrypt — runs GPG in executor to avoid blocking the loop."""
        if not self.enabled:
            return plaintext
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.encrypt_sync, plaintext)

    async def decrypt(self, ciphertext: str) -> str:
        """Async decrypt — runs GPG in executor to avoid blocking the loop."""
        if not self.enabled:
            return ciphertext
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.decrypt_sync, ciphertext)

    # ── File-level operations ──────────────────────────────────────

    async def encrypt_file(self, input_path: str,
                           output_path: str | None = None) -> str:
        """
        Encrypt an entire log file at rest (SGBox-compatible).

        Args:
            input_path: Path to the plaintext log file.
            output_path: Where to write the encrypted file.
                         Defaults to <encrypted_log_dir>/<basename>.gpg

        Returns:
            Path to the encrypted file.
        """
        if not self.enabled or not self._gpg:
            return input_path

        if not output_path:
            basename = Path(input_path).name
            output_path = os.path.join(self._encrypted_log_dir, f"{basename}.gpg")

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._encrypt_file_sync, input_path, output_path
        )

        logger.info("encryption.file_encrypted",
                     input=input_path, output=output_path)
        return output_path

    def _encrypt_file_sync(self, input_path: str, output_path: str):
        """Synchronous file encryption."""
        with open(input_path, "rb") as f:
            if self._mode == "symmetric":
                result = self._gpg.encrypt_file(
                    f,
                    recipients=None,
                    symmetric=self._cipher_algo,
                    passphrase=self._passphrase,
                    armor=self._armor,
                    output=output_path,
                )
            else:
                result = self._gpg.encrypt_file(
                    f,
                    recipients=[self._recipient],
                    armor=self._armor,
                    output=output_path,
                )

        if not result.ok:
            raise RuntimeError(
                f"GPG file encryption failed: {result.status} — {result.stderr}"
            )

    async def decrypt_file(self, input_path: str,
                           output_path: str | None = None) -> str:
        """
        Decrypt a GPG-encrypted log file.

        Args:
            input_path: Path to the .gpg encrypted file.
            output_path: Where to write the decrypted file.
                         Defaults to input_path without .gpg extension.

        Returns:
            Path to the decrypted file.
        """
        if not self.enabled or not self._gpg:
            return input_path

        if not output_path:
            if input_path.endswith(".gpg"):
                output_path = input_path[:-4]
            else:
                output_path = input_path + ".decrypted"

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._decrypt_file_sync, input_path, output_path
        )

        logger.info("encryption.file_decrypted",
                     input=input_path, output=output_path)
        return output_path

    def _decrypt_file_sync(self, input_path: str, output_path: str):
        """Synchronous file decryption."""
        with open(input_path, "rb") as f:
            result = self._gpg.decrypt_file(
                f,
                passphrase=self._passphrase if self._mode == "symmetric" else None,
                output=output_path,
            )

        if not result.ok:
            raise RuntimeError(
                f"GPG file decryption failed: {result.status} — {result.stderr}"
            )

    # ── Utility ────────────────────────────────────────────────────

    def list_keys(self) -> list[dict]:
        """List available GPG keys in the keyring."""
        if not self._gpg:
            return []
        return self._gpg.list_keys()

    @property
    def is_enabled(self) -> bool:
        return self.enabled
