#!/bin/bash
# SIB Fleet Certificate Generator
# Generates client certificates for all hosts defined in Ansible inventory
#
# Usage:
#   ./scripts/generate-fleet-certs.sh
#   ./scripts/generate-fleet-certs.sh --force    # Overwrite existing certs

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="${PROJECT_ROOT}/certs"
INVENTORY_FILE="${PROJECT_ROOT}/ansible/inventory/hosts.yml"

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

# Parse command line
FORCE=false
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
    FORCE=true
fi

# Print usage
usage() {
    echo "SIB Fleet Certificate Generator"
    echo ""
    echo "Usage: $0 [--force]"
    echo ""
    echo "Options:"
    echo "  --force, -f    Overwrite existing certificates without prompting"
    echo ""
    echo "This script reads the Ansible inventory at:"
    echo "  ${INVENTORY_FILE}"
    echo ""
    echo "And generates client certificates for each host in the 'fleet' group."
}

# Extract hostnames from Ansible inventory
get_fleet_hosts() {
    if [ ! -f "${INVENTORY_FILE}" ]; then
        error "Inventory file not found: ${INVENTORY_FILE}"
    fi

    # Parse YAML to get hostnames under fleet.hosts
    # Supports both flat (fleet: at root) and nested (all.children.fleet:) inventory formats
    local IN_FLEET=false
    local IN_HOSTS=false
    local FLEET_INDENT=""
    local HOSTS=()

    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Detect fleet section at any indentation level
        if echo "$line" | grep -qE '^[[:space:]]*fleet:'; then
            IN_FLEET=true
            FLEET_INDENT=$(echo "$line" | sed 's/fleet:.*//' )
            continue
        fi

        if ! $IN_FLEET; then
            continue
        fi

        # Check if we've left fleet section (same or lesser indentation, non-empty)
        local line_indent=$(echo "$line" | sed 's/[^ ].*//')
        if [ ${#line_indent} -le ${#FLEET_INDENT} ] && echo "$line" | grep -qE '[a-zA-Z]'; then
            IN_FLEET=false
            IN_HOSTS=false
            continue
        fi

        # Detect hosts: subsection within fleet
        if echo "$line" | grep -qE '^[[:space:]]*hosts:'; then
            IN_HOSTS=true
            continue
        fi

        # Detect leaving hosts section (sibling key like vars:)
        if $IN_HOSTS && echo "$line" | grep -qE "^${FLEET_INDENT}  [a-z]+:" && ! echo "$line" | grep -qE "^${FLEET_INDENT}    "; then
            IN_HOSTS=false
            continue
        fi

        # Extract hostname (first key under hosts with expected indentation)
        if $IN_HOSTS; then
            local hostname=$(echo "$line" | grep -oP '^\s+\K[a-zA-Z0-9_-]+(?=:)' | head -1)
            # Skip known sub-keys (ansible_host, host_labels, etc.)
            if [ -n "$hostname" ] && ! echo "$hostname" | grep -qE '^(ansible_|host_labels|role|environment)'; then
                HOSTS+=("$hostname")
            fi
        fi
    done < "${INVENTORY_FILE}"

    echo "${HOSTS[@]}"
}

main() {
    if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "help" ]; then
        usage
        exit 0
    fi

    echo "========================================"
    echo "   SIB Fleet Certificate Generator"
    echo "========================================"
    echo ""

    # Check CA exists
    if [ ! -f "${CERTS_DIR}/ca/ca.key" ] || [ ! -f "${CERTS_DIR}/ca/ca.crt" ]; then
        error "CA not found. Run 'make generate-certs' first."
    fi

    # Get fleet hosts
    info "Reading fleet inventory from ${INVENTORY_FILE}..."
    HOSTS=$(get_fleet_hosts)

    if [ -z "$HOSTS" ]; then
        warn "No hosts found in fleet group"
        echo "Make sure your inventory has hosts under 'fleet.hosts:'"
        exit 0
    fi

    info "Found fleet hosts: ${HOSTS}"
    echo ""

    # Generate certificates for each host
    local COUNT=0
    local SKIPPED=0
    local GENERATED=0

    for hostname in $HOSTS; do
        COUNT=$((COUNT + 1))

        if [ -f "${CERTS_DIR}/clients/${hostname}.crt" ] && [ "$FORCE" != "true" ]; then
            warn "[${COUNT}] Skipping '${hostname}' - certificate already exists"
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        info "[${COUNT}] Generating certificate for '${hostname}'..."

        # Generate using the client cert script
        "${SCRIPT_DIR}/generate-client-cert.sh" "$hostname" <<< "y" >/dev/null 2>&1 || {
            # If interactive prompt fails, generate directly
            mkdir -p "${CERTS_DIR}/clients"

            openssl genrsa -out "${CERTS_DIR}/clients/${hostname}.key" 4096 2>/dev/null
            chmod 600 "${CERTS_DIR}/clients/${hostname}.key"

            openssl req -new \
                -key "${CERTS_DIR}/clients/${hostname}.key" \
                -out "${CERTS_DIR}/clients/${hostname}.csr" \
                -subj "/CN=${hostname}/O=SIEM-in-a-Box/OU=Fleet-Agent" 2>/dev/null

            openssl x509 -req \
                -in "${CERTS_DIR}/clients/${hostname}.csr" \
                -CA "${CERTS_DIR}/ca/ca.crt" \
                -CAkey "${CERTS_DIR}/ca/ca.key" \
                -CAcreateserial \
                -out "${CERTS_DIR}/clients/${hostname}.crt" \
                -days 365 \
                -sha256 2>/dev/null

            rm -f "${CERTS_DIR}/clients/${hostname}.csr"
        }

        if [ -f "${CERTS_DIR}/clients/${hostname}.crt" ]; then
            success "Generated certificate for '${hostname}'"
            GENERATED=$((GENERATED + 1))
        else
            warn "Failed to generate certificate for '${hostname}'"
        fi
    done

    echo ""
    echo "========================================"
    echo "   Summary"
    echo "========================================"
    echo "  Total hosts:  ${COUNT}"
    echo "  Generated:    ${GENERATED}"
    echo "  Skipped:      ${SKIPPED}"
    echo ""

    if [ ${GENERATED} -gt 0 ]; then
        success "Fleet certificates generated successfully"
        echo ""
        echo "Next steps:"
        echo "  1. Deploy certificates with fleet: make deploy-fleet"
        echo "  2. Or distribute manually to /etc/sib/certs/ on each host"
    fi

    echo "========================================"
}

main "$@"
