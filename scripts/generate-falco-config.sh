#!/bin/bash
# Generate Falco configuration with driver auto-detection and optional mTLS settings
#
# Usage: ./scripts/generate-falco-config.sh [--mtls] [--driver modern_ebpf|ebpf|kmod]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEMPLATE="${PROJECT_ROOT}/detection/config/falco.yaml.template"
OUTPUT="${PROJECT_ROOT}/detection/config/falco.yaml"
ENV_FILE="${PROJECT_ROOT}/.env"

# -----------------------------------------------
# Parse flags
# -----------------------------------------------
MTLS_ENABLED="${MTLS_ENABLED:-false}"
DRIVER_OVERRIDE=""

for arg in "$@"; do
    case "$arg" in
        --mtls)         MTLS_ENABLED="true" ;;
        --driver=*)     DRIVER_OVERRIDE="${arg#--driver=}" ;;
    esac
done

# -----------------------------------------------
# Auto-detect best Falco driver
# -----------------------------------------------
detect_driver() {
    # Explicit override wins (CLI flag or env var)
    if [ -n "$DRIVER_OVERRIDE" ]; then
        echo "$DRIVER_OVERRIDE"
        return
    fi
    if [ -n "${FALCO_DRIVER_TYPE:-}" ]; then
        echo "$FALCO_DRIVER_TYPE"
        return
    fi

    # modern_ebpf uses CO-RE (Compile Once, Run Everywhere) and is embedded in
    # Falco — no kernel headers or pre-compiled probes needed. Works on kernel
    # >= 5.8 including VMs (KVM, VMware, etc.). The legacy ebpf driver requires
    # a pre-compiled probe file that may not be available in the container.
    local kernel_version
    kernel_version=$(uname -r 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+' || echo "0.0")
    local major minor
    major=$(echo "$kernel_version" | cut -d. -f1)
    minor=$(echo "$kernel_version" | cut -d. -f2)
    if [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 8 ]; }; then
        echo "modern_ebpf"
    else
        echo "ebpf"
    fi
}

# -----------------------------------------------
# Build engine config block
# -----------------------------------------------
build_engine_config() {
    local driver="$1"
    case "$driver" in
        ebpf)
            cat << 'EOF'
# Use ebpf driver (compatible with VMs/KVM where modern_ebpf fails)
engine:
  kind: ebpf
  ebpf:
    probe: ${HOME}/.falco/falco-bpf.o
    buf_size_preset: 4
    drop_failed_exit: false
EOF
            ;;
        kmod)
            cat << 'EOF'
# Use kmod driver (kernel module, fallback for older kernels)
engine:
  kind: kmod
  kmod:
    buf_size_preset: 4
    drop_failed_exit: false
EOF
            ;;
        *)
            cat << 'EOF'
# Use modern_ebpf driver (no kernel headers required, best for bare metal)
engine:
  kind: modern_ebpf
  modern_ebpf:
    cpus_for_each_buffer: 2
    buf_size_preset: 4
EOF
            ;;
    esac
}

# -----------------------------------------------
# Persist driver type to .env so compose picks it up
# -----------------------------------------------
update_env_driver() {
    local driver="$1"
    if [ ! -f "$ENV_FILE" ]; then
        return
    fi
    if grep -q "^FALCO_DRIVER_TYPE=" "$ENV_FILE"; then
        sed -i "s|^FALCO_DRIVER_TYPE=.*|FALCO_DRIVER_TYPE=${driver}|" "$ENV_FILE"
    else
        echo "FALCO_DRIVER_TYPE=${driver}" >> "$ENV_FILE"
    fi
}

# -----------------------------------------------
# Main
# -----------------------------------------------

# Verify template exists
if [ ! -f "$TEMPLATE" ]; then
    echo "Error: Template not found at $TEMPLATE" >&2
    exit 1
fi

DRIVER=$(detect_driver)
echo "  Falco driver: ${DRIVER}"
update_env_driver "$DRIVER"

# Write engine config to a temp file for awk injection
ENGINE_TMP=$(mktemp)
build_engine_config "$DRIVER" > "$ENGINE_TMP"

# Generate config using awk:
#   1. Replace __ENGINE_CONFIG__ with the engine block
#   2. Replace __SIDEKICK_URL__ with http or https URL
#   3. Optionally append mTLS settings after user_agent line
if [ "$MTLS_ENABLED" = "true" ]; then
    echo "  mTLS enabled — using HTTPS to Falcosidekick"
    awk -v engine_file="$ENGINE_TMP" '
    /^__ENGINE_CONFIG__$/ {
        while ((getline line < engine_file) > 0) print line
        close(engine_file)
        next
    }
    {
        gsub(/__SIDEKICK_URL__/, "https://sib-sidekick:2801/")
        print
        if (/user_agent:.*falcosidekick/) {
            print "  insecure: false"
            print "  ca_cert: /etc/falco/certs/ca/ca.crt"
            print "  client_cert: /etc/falco/certs/clients/local.crt"
            print "  client_key: /etc/falco/certs/clients/local.key"
            print "  mtls: true"
        }
    }
    ' "$TEMPLATE" > "$OUTPUT"
    echo "  Generated Falco config with mTLS enabled (driver: ${DRIVER})"
else
    awk -v engine_file="$ENGINE_TMP" '
    /^__ENGINE_CONFIG__$/ {
        while ((getline line < engine_file) > 0) print line
        close(engine_file)
        next
    }
    {
        gsub(/__SIDEKICK_URL__/, "http://sib-sidekick:2801/")
        print
    }
    ' "$TEMPLATE" > "$OUTPUT"
    echo "  Generated Falco config (HTTP mode, driver: ${DRIVER})"
fi

rm -f "$ENGINE_TMP"
