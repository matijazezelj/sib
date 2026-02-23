#!/bin/bash
# SIB mTLS Certificate Generation Script
# Generates CA, server, and initial client certificates for mTLS communication
#
# Usage:
#   ./scripts/generate-certs.sh           # Generate all (CA + server + local client)
#   ./scripts/generate-certs.sh ca        # Generate CA only
#   ./scripts/generate-certs.sh server    # Generate server certs (requires CA)
#   ./scripts/generate-certs.sh client    # Generate local client cert (requires CA)

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="${PROJECT_ROOT}/certs"

# Certificate settings (can be overridden via environment)
CA_VALIDITY_DAYS="${CA_VALIDITY_DAYS:-1825}"          # 5 years
CERT_VALIDITY_DAYS="${CERT_VALIDITY_DAYS:-365}"       # 1 year
KEY_SIZE="${KEY_SIZE:-4096}"
CA_SUBJECT="${CA_SUBJECT:-/CN=SIB-CA/O=SIEM-in-a-Box/OU=Security}"
SERVER_CN="${SERVER_CN:-sib-server}"

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

# Create directory structure
create_directories() {
    info "Creating certificate directory structure..."
    mkdir -p "${CERTS_DIR}/ca"
    mkdir -p "${CERTS_DIR}/server"
    mkdir -p "${CERTS_DIR}/clients"
    success "Directory structure created at ${CERTS_DIR}"
}

# Generate Certificate Authority
generate_ca() {
    info "Generating Certificate Authority..."

    if [ -f "${CERTS_DIR}/ca/ca.key" ]; then
        warn "CA already exists at ${CERTS_DIR}/ca/"
        read -p "Overwrite existing CA? This will invalidate ALL existing certificates! [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Keeping existing CA"
            return 0
        fi
        warn "Regenerating CA - all existing certificates will need to be regenerated!"
    fi

    # Generate CA private key
    openssl genrsa -out "${CERTS_DIR}/ca/ca.key" ${KEY_SIZE} 2>/dev/null
    chmod 600 "${CERTS_DIR}/ca/ca.key"

    # Generate CA certificate
    openssl req -x509 -new -nodes \
        -key "${CERTS_DIR}/ca/ca.key" \
        -sha256 \
        -days ${CA_VALIDITY_DAYS} \
        -out "${CERTS_DIR}/ca/ca.crt" \
        -subj "${CA_SUBJECT}"

    success "CA certificate generated (valid for ${CA_VALIDITY_DAYS} days)"
    echo "  Private key: ${CERTS_DIR}/ca/ca.key"
    echo "  Certificate: ${CERTS_DIR}/ca/ca.crt"
}

# Generate server certificate for Falcosidekick and storage services
generate_server_certs() {
    info "Generating server certificates..."

    if [ ! -f "${CERTS_DIR}/ca/ca.key" ]; then
        error "CA not found. Run '$0 ca' first."
    fi

    # Detect server IP addresses for SANs
    local SERVER_IPS=""
    local SERVER_IP_SANS=""

    # Try to get IP from environment or detect it
    if [ -n "${SIB_SERVER_IP}" ]; then
        SERVER_IPS="${SIB_SERVER_IP}"
    else
        # Detect local IPs (excluding loopback and docker)
        SERVER_IPS=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | grep -v '^172\.' | head -5 || hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' | head -5 || echo "")
    fi

    # Build IP SANs
    local IP_COUNT=1
    for ip in ${SERVER_IPS}; do
        SERVER_IP_SANS="${SERVER_IP_SANS}IP.${IP_COUNT} = ${ip}\n"
        ((IP_COUNT++))
    done

    # Always include localhost
    SERVER_IP_SANS="${SERVER_IP_SANS}IP.${IP_COUNT} = 127.0.0.1\n"

    info "Server IPs for certificate SANs:"
    echo -e "${SERVER_IP_SANS}" | grep -v '^$' | sed 's/^/  /'

    # Create OpenSSL config for server cert with SANs
    cat > "${CERTS_DIR}/server/server.cnf" << EOF
[req]
default_bits = ${KEY_SIZE}
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = ${SERVER_CN}
O = SIEM-in-a-Box
OU = Server

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = sib-sidekick
DNS.3 = sib-victorialogs
DNS.4 = sib-victoriametrics
DNS.5 = sib-loki
DNS.6 = sib-prometheus
DNS.7 = ${SERVER_CN}
$(echo -e "${SERVER_IP_SANS}")
EOF

    # Generate server private key
    openssl genrsa -out "${CERTS_DIR}/server/server.key" ${KEY_SIZE} 2>/dev/null
    # Note: 644 needed for Docker container access (runs as non-root user)
    chmod 644 "${CERTS_DIR}/server/server.key"

    # Generate server CSR
    openssl req -new \
        -key "${CERTS_DIR}/server/server.key" \
        -out "${CERTS_DIR}/server/server.csr" \
        -config "${CERTS_DIR}/server/server.cnf"

    # Sign server certificate with CA
    openssl x509 -req \
        -in "${CERTS_DIR}/server/server.csr" \
        -CA "${CERTS_DIR}/ca/ca.crt" \
        -CAkey "${CERTS_DIR}/ca/ca.key" \
        -CAcreateserial \
        -out "${CERTS_DIR}/server/server.crt" \
        -days ${CERT_VALIDITY_DAYS} \
        -sha256 \
        -extensions req_ext \
        -extfile "${CERTS_DIR}/server/server.cnf" \
        2>/dev/null

    # Clean up CSR
    rm -f "${CERTS_DIR}/server/server.csr"

    success "Server certificate generated (valid for ${CERT_VALIDITY_DAYS} days)"
    echo "  Private key:  ${CERTS_DIR}/server/server.key"
    echo "  Certificate:  ${CERTS_DIR}/server/server.crt"
    echo "  Config:       ${CERTS_DIR}/server/server.cnf"
}

# Generate local client certificate (for SIB server's own Falco)
generate_local_client() {
    info "Generating local client certificate..."

    if [ ! -f "${CERTS_DIR}/ca/ca.key" ]; then
        error "CA not found. Run '$0 ca' first."
    fi

    local CLIENT_NAME="local"
    local CLIENT_DIR="${CERTS_DIR}/clients"

    # Generate client private key
    openssl genrsa -out "${CLIENT_DIR}/${CLIENT_NAME}.key" ${KEY_SIZE} 2>/dev/null
    # Note: 644 needed for Docker container access (runs as non-root user)
    chmod 644 "${CLIENT_DIR}/${CLIENT_NAME}.key"

    # Generate client CSR
    openssl req -new \
        -key "${CLIENT_DIR}/${CLIENT_NAME}.key" \
        -out "${CLIENT_DIR}/${CLIENT_NAME}.csr" \
        -subj "/CN=${CLIENT_NAME}/O=SIEM-in-a-Box/OU=Fleet-Agent"

    # Sign client certificate with CA
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

    success "Local client certificate generated"
    echo "  Private key:  ${CLIENT_DIR}/${CLIENT_NAME}.key"
    echo "  Certificate:  ${CLIENT_DIR}/${CLIENT_NAME}.crt"
}

# Verify certificate chain
verify_certs() {
    info "Verifying certificate chain..."

    local ERRORS=0

    # Check CA
    if [ -f "${CERTS_DIR}/ca/ca.crt" ]; then
        if openssl x509 -in "${CERTS_DIR}/ca/ca.crt" -noout 2>/dev/null; then
            local CA_EXPIRY=$(openssl x509 -in "${CERTS_DIR}/ca/ca.crt" -noout -enddate | cut -d= -f2)
            success "CA certificate valid (expires: ${CA_EXPIRY})"
        else
            warn "CA certificate is invalid"
            ERRORS=$((ERRORS + 1))
        fi
    else
        warn "CA certificate not found"
        ERRORS=$((ERRORS + 1))
    fi

    # Check server cert
    if [ -f "${CERTS_DIR}/server/server.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/ca/ca.crt" "${CERTS_DIR}/server/server.crt" >/dev/null 2>&1; then
            local SERVER_EXPIRY=$(openssl x509 -in "${CERTS_DIR}/server/server.crt" -noout -enddate | cut -d= -f2)
            success "Server certificate valid (expires: ${SERVER_EXPIRY})"
        else
            warn "Server certificate verification failed"
            ERRORS=$((ERRORS + 1))
        fi
    else
        warn "Server certificate not found"
    fi

    # Check client certs
    for cert in "${CERTS_DIR}/clients"/*.crt; do
        [ -f "$cert" ] || continue
        local CLIENT_NAME=$(basename "$cert" .crt)
        if openssl verify -CAfile "${CERTS_DIR}/ca/ca.crt" "$cert" >/dev/null 2>&1; then
            local CLIENT_EXPIRY=$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)
            success "Client '${CLIENT_NAME}' certificate valid (expires: ${CLIENT_EXPIRY})"
        else
            warn "Client '${CLIENT_NAME}' certificate verification failed"
            ERRORS=$((ERRORS + 1))
        fi
    done

    if [ ${ERRORS} -gt 0 ]; then
        error "Certificate verification completed with ${ERRORS} error(s)"
    fi

    success "All certificates verified successfully"
}

# Print usage
usage() {
    echo "SIB mTLS Certificate Generator"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  all      Generate CA, server, and local client certificates (default)"
    echo "  ca       Generate Certificate Authority only"
    echo "  server   Generate server certificates (requires CA)"
    echo "  client   Generate local client certificate (requires CA)"
    echo "  verify   Verify all certificates"
    echo "  help     Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  CA_VALIDITY_DAYS     CA certificate validity (default: 1825 = 5 years)"
    echo "  CERT_VALIDITY_DAYS   Certificate validity (default: 365 = 1 year)"
    echo "  KEY_SIZE             RSA key size (default: 4096)"
    echo "  SIB_SERVER_IP        Server IP for certificate SANs"
    echo ""
    echo "Examples:"
    echo "  $0                           # Generate all certificates"
    echo "  $0 ca                        # Generate CA only"
    echo "  SIB_SERVER_IP=10.0.0.1 $0    # Generate with specific server IP"
}

# Main
main() {
    echo "========================================"
    echo "   SIB mTLS Certificate Generator"
    echo "========================================"
    echo ""

    local COMMAND="${1:-all}"

    case "$COMMAND" in
        all)
            create_directories
            generate_ca
            generate_server_certs
            generate_local_client
            echo ""
            verify_certs
            ;;
        ca)
            create_directories
            generate_ca
            ;;
        server)
            generate_server_certs
            ;;
        client)
            generate_local_client
            ;;
        verify)
            verify_certs
            ;;
        help|--help|-h)
            usage
            exit 0
            ;;
        *)
            error "Unknown command: $COMMAND"
            usage
            exit 1
            ;;
    esac

    echo ""
    echo "========================================"
    echo -e "   ${GREEN}Certificate generation complete${NC}"
    echo "========================================"
}

main "$@"
