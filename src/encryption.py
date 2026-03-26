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
        ciphertext = await enc.encrypt("proto=TCP src=10.1.1.10 ...")
        plaintext = await enc.decrypt(ciphertext)
        await enc.encrypt_file("/var/log/h3c-translator/translated.log")
    """

    def __init__(self, config: dict):
        enc_config = config.get("encryption", {})
        self.enabled = enc_config.get("enabled", "false").lower() == "true"

        match self.enabled:
            case False:
                print(f"[ENCRYPTION] Disabled (encryption.enabled = false)")
                logger.info("encryption.disabled")
                self._gpg = None
                return
            case True:
                print(f"[ENCRYPTION] Enabled — initializing GPG...")

        gpg_home = enc_config.get("gpg_home", os.path.expanduser("~/.gnupg"))
        gpg_binary = enc_config.get("gpg_binary", "gpg")

        # MED-05: Validate GPG binary against known safe paths
        _ALLOWED_GPG_BINARIES = (
            "gpg", "gpg2",
            "/usr/bin/gpg", "/usr/bin/gpg2",
            "/usr/local/bin/gpg", "/usr/local/bin/gpg2",
        )
        if gpg_binary not in _ALLOWED_GPG_BINARIES:
            print(f"[ENCRYPTION] ✗ FATAL: Untrusted gpg_binary path: {gpg_binary}")
            raise ValueError(
                f"gpg_binary '{gpg_binary}' is not in the allowed list: "
                f"{_ALLOWED_GPG_BINARIES}. This prevents command injection."
            )

        print(f"[ENCRYPTION]   GPG home:   {gpg_home}")
        print(f"[ENCRYPTION]   GPG binary: {gpg_binary}")

        try:
            self._gpg = gnupg.GPG(
                gnupghome=gpg_home,
                gpgbinary=gpg_binary,
                use_agent=False,
            )
            print(f"[ENCRYPTION] ✓ GPG initialized")
        except Exception as e:
            print(f"[ENCRYPTION] ✗ GPG initialization FAILED: {e}")
            raise

        self._mode = enc_config.get("mode", "symmetric").lower()
        self._cipher_algo = enc_config.get("cipher_algo", "AES256")
        self._armor = enc_config.get("armor", "false").lower() == "true"
        self._encrypt_output = enc_config.get("encrypt_output", "false").lower() == "true"
        self._encrypted_log_dir = enc_config.get(
            "encrypted_log_dir", "/var/log/h3c-translator/encrypted"
        )

        # CRIT-02: Read passphrase from env var first, then config as fallback
        self._passphrase = os.environ.get(
            "GPG_PASSPHRASE",
            enc_config.get("passphrase", ""),
        )
        self._recipient = enc_config.get("recipient", "")

        print(f"[ENCRYPTION]   Mode:       {self._mode}")
        print(f"[ENCRYPTION]   Cipher:     {self._cipher_algo}")
        print(f"[ENCRYPTION]   Armor:      {self._armor}")
        print(f"[ENCRYPTION]   Log dir:    {self._encrypted_log_dir}")
        if os.environ.get("GPG_PASSPHRASE"):
            print(f"[ENCRYPTION]   Passphrase: loaded from GPG_PASSPHRASE env var")
        else:
            print(f"[ENCRYPTION]   Passphrase: loaded from config file")

        # Validate config
        _INSECURE_PASSPHRASES = ("", "CHANGE_ME_USE_A_STRONG_PASSPHRASE", "changeme")
        match self._mode:
            case "symmetric":
                if self._passphrase in _INSECURE_PASSPHRASES:
                    print(f"[ENCRYPTION] ✗ FATAL: symmetric mode requires a real passphrase")
                    print(f"[ENCRYPTION]   Set GPG_PASSPHRASE env var or update [encryption] passphrase in config")
                    raise ValueError(
                        "[encryption] mode=symmetric requires a real passphrase. "
                        "Set GPG_PASSPHRASE env var or update config."
                    )
                print(f"[ENCRYPTION] ✓ Symmetric mode with passphrase")
            case "asymmetric":
                if not self._recipient:
                    print(f"[ENCRYPTION] ✗ FATAL: asymmetric mode requires a recipient")
                    raise ValueError(
                        "[encryption] mode=asymmetric requires a 'recipient' key ID in config"
                    )
                print(f"[ENCRYPTION] ✓ Asymmetric mode, recipient: {self._recipient}")
            case _:
                print(f"[ENCRYPTION] ✗ Unknown mode '{self._mode}'")
                raise ValueError(f"Unknown encryption mode: {self._mode}")

        # Ensure encrypted log directory exists
        os.makedirs(self._encrypted_log_dir, exist_ok=True)
        print(f"[ENCRYPTION] ✓ Encryption ready")

        logger.info("encryption.enabled",
                     mode=self._mode,
                     cipher=self._cipher_algo,
                     armor=self._armor,
                     log_dir=self._encrypted_log_dir)

    # ── Core encrypt/decrypt ───────────────────────────────────────

    def encrypt_sync(self, plaintext: str) -> str:
        """Encrypt plaintext using GPG (synchronous)."""
        if not self.enabled or not self._gpg:
            return plaintext

        print(f"[ENCRYPTION] Encrypting {len(plaintext)} bytes ({self._mode}/{self._cipher_algo})...")

        match self._mode:
            case "symmetric":
                result = self._gpg.encrypt(
                    plaintext,
                    recipients=None,
                    symmetric=self._cipher_algo,
                    passphrase=self._passphrase,
                    armor=self._armor,
                )
            case "asymmetric":
                result = self._gpg.encrypt(
                    plaintext,
                    recipients=[self._recipient],
                    armor=self._armor,
                )
            case _:
                print(f"[ENCRYPTION] ✗ Unknown mode: {self._mode}")
                return plaintext

        match result.ok:
            case True:
                output = str(result)
                print(f"[ENCRYPTION] ✓ Encrypted: {len(plaintext)}B → {len(output)}B")
                return output
            case False:
                print(f"[ENCRYPTION] ✗ Encryption FAILED: {result.status}")
                print(f"[ENCRYPTION]   stderr: {result.stderr}")
                logger.error("encryption.encrypt_failed",
                              status=result.status,
                              stderr=result.stderr)
                raise RuntimeError(f"GPG encryption failed: {result.status}")

    def decrypt_sync(self, ciphertext: str) -> str:
        """Decrypt GPG-encrypted data (synchronous)."""
        if not self.enabled or not self._gpg:
            return ciphertext

        print(f"[ENCRYPTION] Decrypting {len(ciphertext)} bytes...")

        match self._mode:
            case "symmetric":
                result = self._gpg.decrypt(
                    ciphertext,
                    passphrase=self._passphrase,
                )
            case _:
                result = self._gpg.decrypt(
                    ciphertext,
                    passphrase=None,
                )

        match result.ok:
            case True:
                output = str(result)
                print(f"[ENCRYPTION] ✓ Decrypted: {len(ciphertext)}B → {len(output)}B")
                return output
            case False:
                print(f"[ENCRYPTION] ✗ Decryption FAILED: {result.status}")
                print(f"[ENCRYPTION]   stderr: {result.stderr}")
                logger.error("encryption.decrypt_failed",
                              status=result.status,
                              stderr=result.stderr)
                raise RuntimeError(f"GPG decryption failed: {result.status}")

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
        """Encrypt an entire log file at rest (SGBox-compatible)."""
        if not self.enabled or not self._gpg:
            return input_path

        if not output_path:
            basename = Path(input_path).name
            output_path = os.path.join(self._encrypted_log_dir, f"{basename}.gpg")

        # HIGH-09: Block path traversal
        self._validate_path(output_path)

        print(f"[ENCRYPTION] Encrypting file: {input_path} → {output_path}")

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._encrypt_file_sync, input_path, output_path
        )

        print(f"[ENCRYPTION] ✓ File encrypted: {output_path}")
        logger.info("encryption.file_encrypted",
                     input=input_path, output=output_path)
        return output_path

    def _encrypt_file_sync(self, input_path: str, output_path: str):
        """Synchronous file encryption."""
        with open(input_path, "rb") as f:
            match self._mode:
                case "symmetric":
                    result = self._gpg.encrypt_file(
                        f,
                        recipients=None,
                        symmetric=self._cipher_algo,
                        passphrase=self._passphrase,
                        armor=self._armor,
                        output=output_path,
                    )
                case _:
                    result = self._gpg.encrypt_file(
                        f,
                        recipients=[self._recipient],
                        armor=self._armor,
                        output=output_path,
                    )

        match result.ok:
            case True:
                print(f"[ENCRYPTION] ✓ File encryption done: {output_path}")
            case False:
                print(f"[ENCRYPTION] ✗ File encryption FAILED: {result.status} — {result.stderr}")
                raise RuntimeError(
                    f"GPG file encryption failed: {result.status} — {result.stderr}"
                )

    async def decrypt_file(self, input_path: str,
                           output_path: str | None = None) -> str:
        """Decrypt a GPG-encrypted log file."""
        if not self.enabled or not self._gpg:
            return input_path

        match output_path:
            case None if input_path.endswith(".gpg"):
                output_path = input_path[:-4]
            case None:
                output_path = input_path + ".decrypted"
            case _:
                pass

        # HIGH-09: Block path traversal
        self._validate_path(output_path)

        print(f"[ENCRYPTION] Decrypting file: {input_path} → {output_path}")

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, self._decrypt_file_sync, input_path, output_path
        )

        print(f"[ENCRYPTION] ✓ File decrypted: {output_path}")
        logger.info("encryption.file_decrypted",
                     input=input_path, output=output_path)
        return output_path

    def _decrypt_file_sync(self, input_path: str, output_path: str):
        """Synchronous file decryption."""
        with open(input_path, "rb") as f:
            match self._mode:
                case "symmetric":
                    result = self._gpg.decrypt_file(
                        f,
                        passphrase=self._passphrase,
                        output=output_path,
                    )
                case _:
                    result = self._gpg.decrypt_file(
                        f,
                        passphrase=None,
                        output=output_path,
                    )

        match result.ok:
            case True:
                print(f"[ENCRYPTION] ✓ File decryption done: {output_path}")
            case False:
                print(f"[ENCRYPTION] ✗ File decryption FAILED: {result.status} — {result.stderr}")
                raise RuntimeError(
                    f"GPG file decryption failed: {result.status} — {result.stderr}"
                )

    # ── Utility ────────────────────────────────────────────────────

    def list_keys(self) -> list[dict]:
        """List available GPG keys in the keyring."""
        if not self._gpg:
            print(f"[ENCRYPTION] No GPG instance — cannot list keys")
            return []
        keys = self._gpg.list_keys()
        print(f"[ENCRYPTION] Found {len(keys)} keys in keyring")
        return keys

    def _validate_path(self, path: str) -> None:
        """HIGH-09: Validate path is within the encrypted log directory."""
        real = os.path.realpath(path)
        allowed = os.path.realpath(self._encrypted_log_dir)
        if not real.startswith(allowed + os.sep) and real != allowed:
            raise ValueError(
                f"Path traversal blocked: {path} resolves outside {self._encrypted_log_dir}"
            )

    @property
    def is_enabled(self) -> bool:
        return self.enabled
