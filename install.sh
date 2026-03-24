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
    openssl \
    curl \
    ca-certificates

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

# ── Fetch trusted CA bundle for outbound TLS to SGBox ──────────────
echo "[*] Fetching Google Trust Services root CAs..."
GOOGLE_ROOTS="${CERT_DIR}/google-roots.pem"
CA_BUNDLE="${CERT_DIR}/ca-bundle.pem"

if curl -sSL --retry 3 --retry-delay 2 --max-time 30 \
    "https://pki.goog/roots.pem" \
    -o "${GOOGLE_ROOTS}" 2>/dev/null; then
    # Validate the downloaded file is actually PEM
    if grep -q "BEGIN CERTIFICATE" "${GOOGLE_ROOTS}" 2>/dev/null; then
        echo "    ✓ Downloaded and validated: ${GOOGLE_ROOTS}"
    else
        echo "    ⚠  Downloaded file is not a valid PEM certificate — discarding"
        rm -f "${GOOGLE_ROOTS}"
    fi
else
    echo "    ⚠  Failed to download Google roots (network error)"
    echo "       The installer will use system CAs only"
    rm -f "${GOOGLE_ROOTS}"
fi

echo "[*] Building merged CA bundle (Google roots + system CAs)..."
: > "${CA_BUNDLE}"

# Add Google roots if download succeeded
if [ -f "${GOOGLE_ROOTS}" ] && [ -s "${GOOGLE_ROOTS}" ]; then
    cat "${GOOGLE_ROOTS}" >> "${CA_BUNDLE}"
fi

# Append system CA bundle
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    cat /etc/ssl/certs/ca-certificates.crt >> "${CA_BUNDLE}"
elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
    cat /etc/pki/tls/certs/ca-bundle.crt >> "${CA_BUNDLE}"
else
    echo "    ⚠  No system CA bundle found at /etc/ssl/certs/ca-certificates.crt"
    echo "       Install the ca-certificates package: apt install ca-certificates"
fi

# Verify the final bundle is non-empty and valid
if [ -s "${CA_BUNDLE}" ] && grep -q "BEGIN CERTIFICATE" "${CA_BUNDLE}" 2>/dev/null; then
    CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "${CA_BUNDLE}")
    echo "    ✓ CA bundle created: ${CA_BUNDLE} (${CERT_COUNT} certificates)"
else
    echo "    ✗ ERROR: CA bundle is empty or invalid!"
    echo "       TLS verification to SGBox will fail."
    echo "       Manually fix: curl -sSL https://pki.goog/roots.pem > ${CA_BUNDLE}"
    # Don't exit — the service can still start, it just won't verify certs
fi

# ── Generate self-signed TLS cert for inbound listener (H3C → translator) ──
if [ ! -f "${CERT_DIR}/server.crt" ]; then
    echo "[*] Generating self-signed TLS certificate (inbound listener)..."
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
