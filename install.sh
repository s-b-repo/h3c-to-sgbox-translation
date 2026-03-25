#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# H3C-to-SGBox Translator — Debian 13 (Trixie) Install Script
#
# Must be run as root:
#   sudo bash install.sh
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

INSTALL_DIR="/opt/h3c-sgbox-translator"
CONFIG_DIR="/etc/h3c-translator"
LOG_DIR="/var/log/h3c-translator"
CERT_DIR="${CONFIG_DIR}/certs"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  H3C-to-SGBox Translator v2.0.0 — Debian 13 Installer"
echo "═══════════════════════════════════════════════════════════"

# ── Root check ─────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo ""
    echo "  ✗ ERROR: This script must be run as root."
    echo ""
    echo "  Usage:"
    echo "    sudo bash install.sh"
    echo ""
    exit 1
fi

echo ""

# ── Detect OS ──────────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "[*] Detected: ${PRETTY_NAME:-Unknown}"
else
    echo "[*] OS detection: /etc/os-release not found"
fi

# ── Install system dependencies ────────────────────────────────────
echo ""
echo "[*] Installing system packages..."
echo "    apt-get update + install python3, pip, venv, openssl, curl, ca-certificates"
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
    ca-certificates \
    gnupg
echo "    ✓ System packages installed"

# ── Create service user ───────────────────────────────────────────
echo ""
if ! id -u h3c-translator &>/dev/null; then
    echo "[*] Creating service user 'h3c-translator'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin h3c-translator
    echo "    ✓ User created"
else
    echo "[*] Service user 'h3c-translator' already exists"
fi

# ── Create directories ────────────────────────────────────────────
echo ""
echo "[*] Creating directories..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}" "${CERT_DIR}"
echo "    ✓ ${INSTALL_DIR}"
echo "    ✓ ${CONFIG_DIR}"
echo "    ✓ ${LOG_DIR}"
echo "    ✓ ${CERT_DIR}"

# ── Copy application ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo ""
echo "[*] Installing application to ${INSTALL_DIR}..."
cp -r "${SCRIPT_DIR}/src" "${INSTALL_DIR}/"
echo "    ✓ Copied src/"

if [ -f "${SCRIPT_DIR}/pyproject.toml" ]; then
    cp "${SCRIPT_DIR}/pyproject.toml" "${INSTALL_DIR}/"
    echo "    ✓ Copied pyproject.toml"
fi

cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
echo "    ✓ Copied requirements.txt"

# ── Create venv and install Python deps ────────────────────────────
echo ""
VENV_PIP="${INSTALL_DIR}/venv/bin/pip"
VENV_PYTHON="${INSTALL_DIR}/venv/bin/python3"
PIP_FLAGS="--no-cache-dir --disable-pip-version-check --break-system-packages --quiet"

if [ -f "${VENV_PYTHON}" ]; then
    echo "[*] Virtual environment already exists at ${INSTALL_DIR}/venv"
else
    echo "[*] Creating Python virtual environment..."
    python3 -m venv "${INSTALL_DIR}/venv"
    echo "    ✓ Venv created at ${INSTALL_DIR}/venv"

    echo ""
    echo "[*] Upgrading pip inside venv..."
    "${VENV_PIP}" install ${PIP_FLAGS} --upgrade pip wheel setuptools
    echo "    ✓ pip upgraded"
fi

# Check if all requirements are already satisfied
echo ""
echo "[*] Checking if Python dependencies are already installed..."
if "${VENV_PIP}" install ${PIP_FLAGS} --dry-run -r "${INSTALL_DIR}/requirements.txt" 2>&1 \
    | grep -q "Would install"; then
    echo "    Some packages missing or outdated — installing..."
    "${VENV_PIP}" install ${PIP_FLAGS} -r "${INSTALL_DIR}/requirements.txt"
    echo "    ✓ Python dependencies installed"
else
    echo "    ✓ All Python dependencies already satisfied — skipping pip install"
fi

# Verify key imports work
echo ""
echo "[*] Verifying Python imports..."
"${INSTALL_DIR}/venv/bin/python3" -c "
import sys
errors = []
for mod in ['aiohttp', 'uvloop', 'structlog', 'tenacity', 'gnupg']:
    try:
        __import__(mod)
        print(f'    ✓ {mod}')
    except ImportError as e:
        print(f'    ✗ {mod}: {e}')
        errors.append(mod)
if errors:
    print(f'    WARNING: {len(errors)} module(s) failed to import')
    sys.exit(1)
print('    ✓ All modules verified')
"

# ── Install config (don't overwrite existing) ──────────────────────
echo ""
if [ ! -f "${CONFIG_DIR}/translator.config" ]; then
    echo "[*] Installing default config..."
    cp "${SCRIPT_DIR}/translator.config" "${CONFIG_DIR}/translator.config"
    echo "    ✓ Config installed at ${CONFIG_DIR}/translator.config"
else
    echo "[*] Config already exists, skipping: ${CONFIG_DIR}/translator.config"
fi

# ── Fetch trusted CA bundle for outbound TLS to SGBox ──────────────
echo ""
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
        echo "    ✗ Downloaded file is not a valid PEM certificate — discarding"
        rm -f "${GOOGLE_ROOTS}"
    fi
else
    echo "    ✗ Failed to download Google roots (network error)"
    echo "      The installer will use system CAs only"
    rm -f "${GOOGLE_ROOTS}"
fi

echo ""
echo "[*] Building merged CA bundle (Google roots + system CAs)..."
: > "${CA_BUNDLE}"

# Add Google roots if download succeeded
if [ -f "${GOOGLE_ROOTS}" ] && [ -s "${GOOGLE_ROOTS}" ]; then
    cat "${GOOGLE_ROOTS}" >> "${CA_BUNDLE}"
fi

# Append system CA bundle
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    cat /etc/ssl/certs/ca-certificates.crt >> "${CA_BUNDLE}"
    echo "    ✓ Appended system CAs from /etc/ssl/certs/ca-certificates.crt"
elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
    cat /etc/pki/tls/certs/ca-bundle.crt >> "${CA_BUNDLE}"
    echo "    ✓ Appended system CAs from /etc/pki/tls/certs/ca-bundle.crt"
else
    echo "    ✗ No system CA bundle found"
    echo "      Install: apt install ca-certificates"
fi

# Verify the final bundle
if [ -s "${CA_BUNDLE}" ] && grep -q "BEGIN CERTIFICATE" "${CA_BUNDLE}" 2>/dev/null; then
    CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "${CA_BUNDLE}")
    echo "    ✓ CA bundle: ${CA_BUNDLE} (${CERT_COUNT} certificates)"
else
    echo "    ✗ CA bundle is empty or invalid!"
    echo "      TLS verification to SGBox may fail."
    echo "      Fix: curl -sSL https://pki.goog/roots.pem > ${CA_BUNDLE}"
fi

# ── Generate TLS certificates (CA + translator + SGBox) ────────────
echo ""
echo "[*] Running certificate generation..."
echo "    This is interactive — you will be prompted at each step."
echo ""
if [ -f "${SCRIPT_DIR}/generate_certs.sh" ]; then
    bash "${SCRIPT_DIR}/generate_certs.sh" \
        --cert-dir "${CERT_DIR}" \
        --config "${CONFIG_DIR}/translator.config"
else
    echo "    ✗ generate_certs.sh not found at ${SCRIPT_DIR}"
    echo "      Falling back to basic self-signed certificate..."
    if [ ! -f "${CERT_DIR}/server.crt" ]; then
        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout "${CERT_DIR}/server.key" \
            -out "${CERT_DIR}/server.crt" \
            -days 365 \
            -subj "/CN=h3c-translator/O=H3C-SGBox/C=ZA" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
            2>/dev/null
        chmod 600 "${CERT_DIR}/server.key"
        echo "    ✓ Fallback cert: ${CERT_DIR}/server.crt"
    else
        echo "    ✓ TLS certificate already exists, skipping"
    fi
fi

# ── Install systemd service ───────────────────────────────────────
echo ""
if [ -f "${SCRIPT_DIR}/systemd/h3c-translator.service" ]; then
    echo "[*] Installing systemd service..."
    cp "${SCRIPT_DIR}/systemd/h3c-translator.service" /lib/systemd/system/
    systemctl daemon-reload
    systemctl enable h3c-translator.service
    echo "    ✓ Service installed and enabled"
else
    echo "[*] systemd service file not found, skipping"
    echo "    Expected: ${SCRIPT_DIR}/systemd/h3c-translator.service"
fi

# ── Set permissions ────────────────────────────────────────────────
echo ""
echo "[*] Setting file permissions..."
chown -R h3c-translator:h3c-translator "${INSTALL_DIR}" "${LOG_DIR}"
chown -R h3c-translator:h3c-translator "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"
chmod 640 "${CONFIG_DIR}/translator.config"
echo "    ✓ Ownership set to h3c-translator"
echo "    ✓ Config permissions: 640"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ Installation complete!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  Config:  ${CONFIG_DIR}/translator.config"
echo "  Certs:   ${CERT_DIR}/"
echo "  Logs:    ${LOG_DIR}/"
echo "  Venv:    ${INSTALL_DIR}/venv/"
echo "  Service: systemctl start h3c-translator"
echo ""
echo "  ⚠  NEXT STEPS:"
echo "     1. Edit the config:"
echo "        nano ${CONFIG_DIR}/translator.config"
echo ""
echo "     2. Set your SGBox host/port and allowed_ips"
echo ""
echo "     3. Start the service:"
echo "        systemctl start h3c-translator"
echo "        systemctl status h3c-translator"
echo ""
echo "     4. Check logs:"
echo "        journalctl -u h3c-translator -f"
echo ""
