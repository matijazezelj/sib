#!/bin/bash
# SIB Client Certificate Generator
# Generates a client certificate for a specific fleet host
#
# Usage:
#   ./scripts/generate-client-cert.sh <hostname>
#   ./scripts/generate-client-cert.sh fleet-host-1
#   ./scripts/generate-client-cert.sh 192.168.1.100

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="${PROJECT_ROOT}/certs"

# Certificate settings
CERT_VALIDITY_DAYS="${CERT_VALIDITY_DAYS:-365}"
KEY_SIZE="${KEY_SIZE:-4096}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Print usage
usage() {
    echo "SIB Client Certificate Generator"
    echo ""
    echo "Usage: $0 <hostname>"
    echo ""
    echo "Arguments:"
    echo "  hostname    The hostname or identifier for the fleet agent"
    echo ""
    echo "Environment variables:"
    echo "  CERT_VALIDITY_DAYS   Certificate validity (default: 365)"
    echo "  KEY_SIZE             RSA key size (default: 4096)"
    echo ""
    echo "Examples:"
    echo "  $0 fleet-host-1"
    echo "  $0 web-server-prod"
    echo "  $0 192.168.1.100"
    echo ""
    echo "Output files:"
    echo "  certs/clients/<hostname>.key  - Private key"
    echo "  certs/clients/<hostname>.crt  - Certificate"
}

generate_client_cert() {
    local CLIENT_NAME="$1"
    local CLIENT_DIR="${CERTS_DIR}/clients"

    info "Generating client certificate for '${CLIENT_NAME}'..."

    # Check CA exists
    if [ ! -f "${CERTS_DIR}/ca/ca.key" ] || [ ! -f "${CERTS_DIR}/ca/ca.crt" ]; then
        error "CA not found. Run 'make generate-certs' or './scripts/generate-certs.sh ca' first."
    fi

    # Check if cert already exists
    if [ -f "${CLIENT_DIR}/${CLIENT_NAME}.crt" ]; then
        warn "Certificate for '${CLIENT_NAME}' already exists"
        read -p "Overwrite? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Keeping existing certificate"
            exit 0
        fi
    fi

    # Ensure client directory exists
    mkdir -p "${CLIENT_DIR}"

    # Generate client private key
    info "Generating private key..."
    openssl genrsa -out "${CLIENT_DIR}/${CLIENT_NAME}.key" ${KEY_SIZE} 2>/dev/null
    # Falco runs as root inside its privileged sensor container.
    chmod 600 "${CLIENT_DIR}/${CLIENT_NAME}.key"

    # Generate client CSR
    info "Generating certificate signing request..."
    openssl req -new \
        -key "${CLIENT_DIR}/${CLIENT_NAME}.key" \
        -out "${CLIENT_DIR}/${CLIENT_NAME}.csr" \
        -subj "/CN=${CLIENT_NAME}/O=SIEM-in-a-Box/OU=Fleet-Agent"

    # Sign client certificate with CA
    info "Signing certificate with CA..."
    openssl x509 -req \
        -in "${CLIENT_DIR}/${CLIENT_NAME}.csr" \
        -CA "${CERTS_DIR}/ca/ca.crt" \
        -CAkey "${CERTS_DIR}/ca/ca.key" \
        -CAcreateserial \
        -out "${CLIENT_DIR}/${CLIENT_NAME}.crt" \
        -days ${CERT_VALIDITY_DAYS} \
        -sha256 \
        2>/dev/null

    # Clean up CSR
    rm -f "${CLIENT_DIR}/${CLIENT_NAME}.csr"

    # Verify the certificate
    if openssl verify -CAfile "${CERTS_DIR}/ca/ca.crt" "${CLIENT_DIR}/${CLIENT_NAME}.crt" >/dev/null 2>&1; then
        local EXPIRY; EXPIRY=$(openssl x509 -in "${CLIENT_DIR}/${CLIENT_NAME}.crt" -noout -enddate | cut -d= -f2)
        success "Client certificate generated successfully"
        echo ""
        echo "Certificate details:"
        echo "  Hostname:     ${CLIENT_NAME}"
        echo "  Private key:  ${CLIENT_DIR}/${CLIENT_NAME}.key"
        echo "  Certificate:  ${CLIENT_DIR}/${CLIENT_NAME}.crt"
        echo "  Expires:      ${EXPIRY}"
        echo ""
        echo "To deploy this certificate to the fleet host, run:"
        echo "  make deploy-fleet LIMIT=${CLIENT_NAME}"
    else
        error "Certificate verification failed"
    fi
}

# Main
main() {
    if [ $# -lt 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "help" ]; then
        usage
        exit 0
    fi

    local HOSTNAME="$1"

    # Validate hostname (basic sanitization)
    if [[ ! "$HOSTNAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        error "Invalid hostname. Use only alphanumeric characters, dots, underscores, and hyphens."
    fi

    echo "========================================"
    echo "   SIB Client Certificate Generator"
    echo "========================================"
    echo ""

    generate_client_cert "$HOSTNAME"

    echo "========================================"
}

main "$@"
