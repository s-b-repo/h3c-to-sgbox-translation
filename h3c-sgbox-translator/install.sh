#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# H3C-to-SGBox Translator — Debian 13 (Trixie) Install Script
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="/opt/h3c-sgbox-translator"
CONFIG_DIR="/etc/h3c-translator"
LOG_DIR="/var/log/h3c-translator"
CERT_DIR="${CONFIG_DIR}/certs"

echo "═══════════════════════════════════════════════════════════"
echo "  H3C-to-SGBox Translator v2.0.0 — Debian 13 Installer"
echo "═══════════════════════════════════════════════════════════"

# ── Check we're on Debian 13+ ──────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "[*] Detected: ${PRETTY_NAME:-Unknown}"
fi

# ── Install system dependencies ────────────────────────────────────
echo "[*] Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    python3-aiohttp \
    python3-uvloop \
    python3-openssl \
    openssl

# ── Create service user ───────────────────────────────────────────
if ! id -u h3c-translator &>/dev/null; then
    echo "[*] Creating service user 'h3c-translator'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin h3c-translator
fi

# ── Create directories ────────────────────────────────────────────
echo "[*] Creating directories..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}" "${CERT_DIR}"

# ── Copy application ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[*] Installing application to ${INSTALL_DIR}..."
cp -r "${SCRIPT_DIR}/src" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/pyproject.toml" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"

# ── Create venv and install Python deps ────────────────────────────
echo "[*] Creating virtual environment..."
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip wheel
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

# ── Install config (don't overwrite existing) ──────────────────────
if [ ! -f "${CONFIG_DIR}/translator.config" ]; then
    echo "[*] Installing default config..."
    cp "${SCRIPT_DIR}/translator.config" "${CONFIG_DIR}/translator.config"
else
    echo "[*] Config already exists, skipping (${CONFIG_DIR}/translator.config)"
fi

# ── Generate self-signed TLS certs if missing ──────────────────────
if [ ! -f "${CERT_DIR}/server.crt" ]; then
    echo "[*] Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "${CERT_DIR}/server.key" \
        -out "${CERT_DIR}/server.crt" \
        -days 365 \
        -subj "/CN=h3c-translator/O=H3C-SGBox/C=ZA" \
        2>/dev/null
    chmod 600 "${CERT_DIR}/server.key"
    echo "    Certificate: ${CERT_DIR}/server.crt"
    echo "    Private key: ${CERT_DIR}/server.key"
fi

# ── Install systemd service ───────────────────────────────────────
echo "[*] Installing systemd service..."
cp "${SCRIPT_DIR}/systemd/h3c-translator.service" /lib/systemd/system/
systemctl daemon-reload
systemctl enable h3c-translator.service

# ── Set permissions ────────────────────────────────────────────────
chown -R h3c-translator:h3c-translator "${INSTALL_DIR}" "${LOG_DIR}"
chown -R h3c-translator:h3c-translator "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"
chmod 640 "${CONFIG_DIR}/translator.config"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Installation complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Config:  ${CONFIG_DIR}/translator.config"
echo "  Certs:   ${CERT_DIR}/"
echo "  Logs:    ${LOG_DIR}/"
echo "  Service: systemctl start h3c-translator"
echo ""
echo "  ⚠  Edit the config before starting:"
echo "     nano ${CONFIG_DIR}/translator.config"
echo ""
echo "  Then:  systemctl start h3c-translator"
echo "         systemctl status h3c-translator"
echo ""
