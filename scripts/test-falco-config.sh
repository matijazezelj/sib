#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

FALCO_CONFIG_OUTPUT="$TMP/local.yaml" \
FALCO_ENV_FILE="$TMP/nonexistent.env" \
FALCO_DRIVER_TYPE=modern_ebpf \
MTLS_ENABLED=false \
SIDEKICK_URL=http://sidekick.internal:2801/ \
    "$ROOT/scripts/generate-falco-config.sh" >/dev/null

grep -q 'url: "http://sidekick.internal:2801/"' "$TMP/local.yaml"
grep -q 'buffered_outputs: false' "$TMP/local.yaml"
if grep -q 'client_cert:' "$TMP/local.yaml"; then
    echo "HTTP config unexpectedly contains client certificate settings" >&2
    exit 1
fi

FALCO_CONFIG_OUTPUT="$TMP/remote.yaml" \
FALCO_ENV_FILE="$TMP/nonexistent.env" \
FALCO_DRIVER_TYPE=modern_ebpf \
MTLS_ENABLED=true \
SIDEKICK_URL=https://192.0.2.25:2801/ \
FALCO_CLIENT_CERT_NAME=docker-vm \
    "$ROOT/scripts/generate-falco-config.sh" >/dev/null

grep -q 'url: "https://192.0.2.25:2801/"' "$TMP/remote.yaml"
grep -q 'client_cert: /etc/falco/certs/clients/docker-vm.crt' "$TMP/remote.yaml"
grep -q 'client_key: /etc/falco/certs/clients/docker-vm.key' "$TMP/remote.yaml"
grep -q 'ca_cert: /etc/falco/certs/ca/ca.crt' "$TMP/remote.yaml"
grep -q 'mtls: true' "$TMP/remote.yaml"

echo "falco config tests: PASS"