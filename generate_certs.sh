#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# H3C-to-SGBox Translator — Certificate Generation Script
#
# Generates a private CA and TLS certificates for both the Translator
# and SGBox. Each step checks for existing files and prompts the user
# before overwriting.
#
# Usage:
#   sudo bash generate_certs.sh                             # interactive
#   sudo bash generate_certs.sh --cert-dir /path/to/certs   # custom dir
#   sudo bash generate_certs.sh --cert-dir /path --config /path/translator.config
#
# Generated files:
#   ca.key          — CA private key (root of trust)
#   ca.crt          — CA certificate (signs both server certs)
#   server.key      — Translator private key
#   server.crt      — Translator certificate (signed by CA)
#   sgbox.key       — SGBox private key
#   sgbox.crt       — SGBox certificate (signed by CA)
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
CERT_DIR="/etc/h3c-translator/certs"
CONFIG_FILE=""
KEY_SIZE=4096
CA_DAYS=3650       # 10 years
CERT_DAYS=365      # 1 year

# ── Color helpers ─────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[CERTS]${NC} $*"; }
success() { echo -e "${CYAN}[CERTS]${NC} ${GREEN}✓${NC} $*"; }
warn()    { echo -e "${CYAN}[CERTS]${NC} ${YELLOW}⚠${NC} $*"; }
fail()    { echo -e "${CYAN}[CERTS]${NC} ${RED}✗${NC} $*"; }

# ── Parse arguments ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cert-dir)
            CERT_DIR="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--cert-dir DIR] [--config FILE]"
            echo ""
            echo "Options:"
            echo "  --cert-dir DIR     Directory to store certificates (default: /etc/h3c-translator/certs)"
            echo "  --config FILE      Path to translator.config (used to read SGBox host)"
            echo "  -h, --help         Show this help"
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Header ────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  H3C-to-SGBox — TLS Certificate Generator${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
info "Certificate directory: ${CERT_DIR}"
info "Key size:              ${KEY_SIZE}-bit RSA"
info "CA validity:           ${CA_DAYS} days (≈10 years)"
info "Cert validity:         ${CERT_DAYS} days (1 year)"
echo ""

# ── Ensure openssl is available ──────────────────────────────────────
if ! command -v openssl &>/dev/null; then
    fail "openssl is not installed. Install it with: apt install openssl"
    exit 1
fi

# ── Create cert directory ────────────────────────────────────────────
mkdir -p "${CERT_DIR}"

# ── Read SGBox host from config (if available) ───────────────────────
SGBOX_HOST=""
if [ -n "${CONFIG_FILE}" ] && [ -f "${CONFIG_FILE}" ]; then
    # Parse the [sgbox] host = <value> from the INI config
    SGBOX_HOST=$(grep -A20 '^\[sgbox\]' "${CONFIG_FILE}" \
        | grep -E '^\s*host\s*=' \
        | head -1 \
        | sed 's/.*=\s*//' \
        | tr -d '[:space:]')
    if [ -n "${SGBOX_HOST}" ]; then
        info "Read SGBox host from config: ${SGBOX_HOST}"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# Helper: prompt user when a file already exists
#   Returns 0 = proceed (generate), 1 = skip
# ══════════════════════════════════════════════════════════════════════
ask_overwrite() {
    local filepath="$1"
    local description="$2"

    if [ -f "${filepath}" ]; then
        echo ""
        warn "File already exists: ${filepath}"

        # Show cert info if it's a certificate
        if [[ "${filepath}" == *.crt ]]; then
            local subject issuer expiry
            subject=$(openssl x509 -in "${filepath}" -noout -subject 2>/dev/null || echo "unknown")
            issuer=$(openssl x509 -in "${filepath}" -noout -issuer 2>/dev/null || echo "unknown")
            expiry=$(openssl x509 -in "${filepath}" -noout -enddate 2>/dev/null || echo "unknown")
            echo "         ${subject}"
            echo "         ${issuer}"
            echo "         ${expiry}"
        fi

        while true; do
            read -rp "  → ${description}: [O]verwrite / [S]kip? [S]: " choice
            case "${choice,,}" in
                o|overwrite)
                    info "Overwriting ${filepath}..."
                    return 0
                    ;;
                s|skip|"")
                    info "Skipping ${description}"
                    return 1
                    ;;
                *)
                    echo "  Please enter O (overwrite) or S (skip)"
                    ;;
            esac
        done
    fi
    return 0
}

# ── Detect machine IP (for SANs) ────────────────────────────────────
MACHINE_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
if [ -n "${MACHINE_IP}" ]; then
    info "Detected machine IP: ${MACHINE_IP}"
fi

# ══════════════════════════════════════════════════════════════════════
#  STEP 1: Generate Private CA
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}── Step 1/3: Private Certificate Authority ──────────────${NC}"

CA_KEY="${CERT_DIR}/ca.key"
CA_CRT="${CERT_DIR}/ca.crt"
GENERATE_CA=true

if ! ask_overwrite "${CA_KEY}" "CA private key"; then
    GENERATE_CA=false
fi

if [ "${GENERATE_CA}" = true ] && [ -f "${CA_CRT}" ]; then
    if ! ask_overwrite "${CA_CRT}" "CA certificate"; then
        GENERATE_CA=false
    fi
fi

if [ "${GENERATE_CA}" = true ]; then
    info "Generating ${KEY_SIZE}-bit CA key..."
    openssl genrsa -out "${CA_KEY}" ${KEY_SIZE} 2>/dev/null
    chmod 600 "${CA_KEY}"
    success "CA key: ${CA_KEY} (mode 600)"

    info "Generating self-signed CA certificate (${CA_DAYS} days)..."
    openssl req -x509 -new -nodes \
        -key "${CA_KEY}" \
        -sha256 \
        -days ${CA_DAYS} \
        -out "${CA_CRT}" \
        -subj "/CN=H3C-SGBox Private CA/O=H3C-SGBox Translator/C=ZA" \
        2>/dev/null
    success "CA cert: ${CA_CRT}"
else
    info "Using existing CA"
fi

# Verify CA exists before proceeding
if [ ! -f "${CA_KEY}" ] || [ ! -f "${CA_CRT}" ]; then
    fail "CA key/cert not found. Cannot sign certificates without a CA."
    fail "Re-run and allow CA generation, or place ca.key + ca.crt in ${CERT_DIR}"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════
#  STEP 2: Generate Translator Server Certificate
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}── Step 2/3: Translator Server Certificate ──────────────${NC}"

SRV_KEY="${CERT_DIR}/server.key"
SRV_CRT="${CERT_DIR}/server.crt"
SRV_CSR="${CERT_DIR}/server.csr"
GENERATE_SRV=true

if ! ask_overwrite "${SRV_KEY}" "Translator private key"; then
    GENERATE_SRV=false
fi

if [ "${GENERATE_SRV}" = true ] && [ -f "${SRV_CRT}" ]; then
    if ! ask_overwrite "${SRV_CRT}" "Translator certificate"; then
        GENERATE_SRV=false
    fi
fi

if [ "${GENERATE_SRV}" = true ]; then
    # Build SAN extension
    SRV_SAN="DNS:localhost,IP:127.0.0.1"
    if [ -n "${MACHINE_IP}" ]; then
        SRV_SAN="${SRV_SAN},IP:${MACHINE_IP}"
    fi

    # Ask for additional SANs
    echo ""
    info "Default SANs: ${SRV_SAN}"
    read -rp "  → Add extra hostnames/IPs? (comma-separated, or Enter to skip): " extra_sans
    if [ -n "${extra_sans}" ]; then
        # Parse each entry and prefix with DNS: or IP: as appropriate
        IFS=',' read -ra ENTRIES <<< "${extra_sans}"
        for entry in "${ENTRIES[@]}"; do
            entry=$(echo "${entry}" | tr -d '[:space:]')
            if [[ "${entry}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                SRV_SAN="${SRV_SAN},IP:${entry}"
            else
                SRV_SAN="${SRV_SAN},DNS:${entry}"
            fi
        done
    fi

    info "Generating translator key + CSR..."
    openssl genrsa -out "${SRV_KEY}" ${KEY_SIZE} 2>/dev/null
    chmod 600 "${SRV_KEY}"

    openssl req -new \
        -key "${SRV_KEY}" \
        -out "${SRV_CSR}" \
        -subj "/CN=h3c-translator/O=H3C-SGBox Translator/C=ZA" \
        2>/dev/null

    info "Signing with CA (${CERT_DAYS} days, SANs: ${SRV_SAN})..."
    openssl x509 -req \
        -in "${SRV_CSR}" \
        -CA "${CA_CRT}" \
        -CAkey "${CA_KEY}" \
        -CAcreateserial \
        -out "${SRV_CRT}" \
        -days ${CERT_DAYS} \
        -sha256 \
        -extfile <(echo "subjectAltName=${SRV_SAN}") \
        2>/dev/null

    rm -f "${SRV_CSR}"
    # LOW-03: Clean up serial file left by -CAcreateserial
    rm -f "${CERT_DIR}/ca.srl"
    success "Translator key:  ${SRV_KEY} (mode 600)"
    success "Translator cert: ${SRV_CRT}"
else
    info "Using existing translator certificate"
fi

# ══════════════════════════════════════════════════════════════════════
#  STEP 3: Generate SGBox Server Certificate
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}── Step 3/3: SGBox Server Certificate ───────────────────${NC}"

SGB_KEY="${CERT_DIR}/sgbox.key"
SGB_CRT="${CERT_DIR}/sgbox.crt"
SGB_CSR="${CERT_DIR}/sgbox.csr"
GENERATE_SGB=true

if ! ask_overwrite "${SGB_KEY}" "SGBox private key"; then
    GENERATE_SGB=false
fi

if [ "${GENERATE_SGB}" = true ] && [ -f "${SGB_CRT}" ]; then
    if ! ask_overwrite "${SGB_CRT}" "SGBox certificate"; then
        GENERATE_SGB=false
    fi
fi

if [ "${GENERATE_SGB}" = true ]; then
    # Determine SGBox hostname/IP
    DEFAULT_HOST="${SGBOX_HOST:-192.168.1.100}"
    echo ""
    read -rp "  → SGBox hostname or IP [${DEFAULT_HOST}]: " sgbox_input
    sgbox_input="${sgbox_input:-${DEFAULT_HOST}}"

    # Build SAN extension
    if [[ "${sgbox_input}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SGB_SAN="IP:${sgbox_input}"
        SGB_CN="${sgbox_input}"
    else
        SGB_SAN="DNS:${sgbox_input}"
        SGB_CN="${sgbox_input}"
    fi

    # Ask for additional SANs
    info "Default SAN: ${SGB_SAN}"
    read -rp "  → Add extra hostnames/IPs? (comma-separated, or Enter to skip): " extra_sans
    if [ -n "${extra_sans}" ]; then
        IFS=',' read -ra ENTRIES <<< "${extra_sans}"
        for entry in "${ENTRIES[@]}"; do
            entry=$(echo "${entry}" | tr -d '[:space:]')
            if [[ "${entry}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                SGB_SAN="${SGB_SAN},IP:${entry}"
            else
                SGB_SAN="${SGB_SAN},DNS:${entry}"
            fi
        done
    fi

    info "Generating SGBox key + CSR..."
    openssl genrsa -out "${SGB_KEY}" ${KEY_SIZE} 2>/dev/null
    chmod 600 "${SGB_KEY}"

    openssl req -new \
        -key "${SGB_KEY}" \
        -out "${SGB_CSR}" \
        -subj "/CN=${SGB_CN}/O=SGBox SIEM/C=ZA" \
        2>/dev/null

    info "Signing with CA (${CERT_DAYS} days, SANs: ${SGB_SAN})..."
    openssl x509 -req \
        -in "${SGB_CSR}" \
        -CA "${CA_CRT}" \
        -CAkey "${CA_KEY}" \
        -CAcreateserial \
        -out "${SGB_CRT}" \
        -days ${CERT_DAYS} \
        -sha256 \
        -extfile <(echo "subjectAltName=${SGB_SAN}") \
        2>/dev/null

    rm -f "${SGB_CSR}"
    success "SGBox key:  ${SGB_KEY} (mode 600)"
    success "SGBox cert: ${SGB_CRT}"
else
    info "Using existing SGBox certificate"
fi

# ══════════════════════════════════════════════════════════════════════
#  STEP 4: Update CA Bundle
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}── Updating CA Bundle ───────────────────────────────────${NC}"

CA_BUNDLE="${CERT_DIR}/ca-bundle.pem"

if [ -f "${CA_BUNDLE}" ]; then
    # Check if the CA is already in the bundle
    CA_FINGERPRINT=$(openssl x509 -in "${CA_CRT}" -noout -fingerprint -sha256 2>/dev/null || echo "")
    if grep -q "H3C-SGBox Private CA" "${CA_BUNDLE}" 2>/dev/null; then
        info "CA already present in ${CA_BUNDLE} — replacing..."
        # Remove old CA block and re-append
        # Safer: rebuild by filtering out our CA and re-appending
        TEMP_BUNDLE=$(mktemp)
        # Copy everything except our CA cert
        awk '/^# H3C-SGBox Private CA$/,/^-----END CERTIFICATE-----$/{next}1' \
            "${CA_BUNDLE}" > "${TEMP_BUNDLE}" 2>/dev/null || cp "${CA_BUNDLE}" "${TEMP_BUNDLE}"
        cp "${TEMP_BUNDLE}" "${CA_BUNDLE}"
        rm -f "${TEMP_BUNDLE}"
    fi
fi

# Append the CA cert with a marker
{
    echo "# H3C-SGBox Private CA"
    cat "${CA_CRT}"
    echo ""
} >> "${CA_BUNDLE}"

BUNDLE_COUNT=$(grep -c "BEGIN CERTIFICATE" "${CA_BUNDLE}" 2>/dev/null || echo "0")
success "CA bundle updated: ${CA_BUNDLE} (${BUNDLE_COUNT} certificates)"

# ══════════════════════════════════════════════════════════════════════
#  Verify Certificate Chain
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}── Verification ─────────────────────────────────────────${NC}"

verify_cert() {
    local cert_path="$1"
    local label="$2"
    if [ -f "${cert_path}" ]; then
        if openssl verify -CAfile "${CA_CRT}" "${cert_path}" &>/dev/null; then
            success "${label}: chain valid ✓"
        else
            fail "${label}: chain verification FAILED"
        fi

        local expiry
        expiry=$(openssl x509 -in "${cert_path}" -noout -enddate 2>/dev/null \
            | sed 's/notAfter=//')
        info "  Expires: ${expiry}"
    fi
}

verify_cert "${SRV_CRT}" "Translator cert"
verify_cert "${SGB_CRT}" "SGBox cert"

# ══════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  ✓ Certificate Generation Complete${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Generated files in ${CERT_DIR}/:"
echo ""
echo "    CA (root of trust):"
echo "      ${CA_KEY}"
echo "      ${CA_CRT}"
echo ""
echo "    Translator (used by this service):"
echo "      ${SRV_KEY}"
echo "      ${SRV_CRT}"
echo ""
echo "    SGBox (upload to SGBox appliance):"
echo "      ${SGB_KEY}"
echo "      ${SGB_CRT}"
echo ""
echo "    CA Bundle (trust store):"
echo "      ${CA_BUNDLE}"
echo ""
echo -e "  ${YELLOW}⚠  NEXT STEP — Upload to SGBox:${NC}"
echo ""
echo "     1. Open the SGBox web console"
echo "     2. Navigate to: SCM → Action → Upload custom certificate"
echo "     3. Upload these files:"
echo "          Certificate:      ${SGB_CRT}"
echo "          Private key:      ${SGB_KEY}"
echo "          Chain certificate: ${CA_CRT}"
echo ""
echo "     4. SGBox will restart its web server (30–60s downtime)"
echo ""
echo "     5. Verify from this machine:"
echo "          openssl s_client -connect <SGBOX_IP>:6154 \\"
echo "            -CAfile ${CA_BUNDLE} </dev/null"
echo ""
