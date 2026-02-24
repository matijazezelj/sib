#!/bin/bash
# Deploy collector to remote host (supports both VM and Grafana stacks)
# Usage: ./deploy.sh user@remote-host sib-server-ip

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <user@remote-host> <sib-server-ip>"
    echo "Example: $0 user@192.168.1.50 192.168.1.100"
    exit 1
fi

REMOTE_HOST="$1"
SIB_SERVER="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTORS_DIR="$(dirname "$SCRIPT_DIR")"

# Load stack config
if [ -f "$COLLECTORS_DIR/../.env" ]; then
    set -a; source "$COLLECTORS_DIR/../.env"; set +a
fi
STACK="${STACK:-vm}"

echo "========================================"
echo "   SIB Collector Deployment ($STACK stack)"
echo "========================================"
echo ""
echo "Remote Host: $REMOTE_HOST"
echo "SIB Server:  $SIB_SERVER"
echo "Stack:       $STACK"
echo ""

if [ "$STACK" = "grafana" ]; then
    # Grafana stack: deploy Alloy
    TEMP_CONFIG=$(mktemp)
    sed "s|SIB_SERVER_IP|$SIB_SERVER|g" "$COLLECTORS_DIR/config/config.alloy" > "$TEMP_CONFIG"

    echo "[1/4] Copying Alloy configuration..."
    ssh "$REMOTE_HOST" "mkdir -p ~/sib-collector/config"
    scp "$TEMP_CONFIG" "$REMOTE_HOST:~/sib-collector/config/config.alloy"
    scp "$COLLECTORS_DIR/compose-grafana.yaml" "$REMOTE_HOST:~/sib-collector/compose.yaml"
    rm "$TEMP_CONFIG"

    echo "[2/4] Starting Alloy container..."
    ssh "$REMOTE_HOST" "cd ~/sib-collector && HOSTNAME=\$(hostname) docker compose up -d"
else
    # VM stack: deploy Vector + vmagent + node-exporter
    TEMP_CONFIG=$(mktemp)
    sed "s|SIB_SERVER_IP|$SIB_SERVER|g" "$COLLECTORS_DIR/config/vector.toml" > "$TEMP_CONFIG"

    TEMP_VMAGENT=$(mktemp)
    sed "s|SIB_SERVER_IP|$SIB_SERVER|g" "$COLLECTORS_DIR/config/vmagent.yml" > "$TEMP_VMAGENT"

    echo "[1/4] Copying collector configuration..."
    ssh "$REMOTE_HOST" "mkdir -p ~/sib-collector/config"
    scp "$TEMP_CONFIG" "$REMOTE_HOST:~/sib-collector/config/vector.toml"
    scp "$TEMP_VMAGENT" "$REMOTE_HOST:~/sib-collector/config/vmagent.yml"
    scp "$COLLECTORS_DIR/compose-vm.yaml" "$REMOTE_HOST:~/sib-collector/compose.yaml"
    rm "$TEMP_CONFIG" "$TEMP_VMAGENT"

    echo "[2/4] Starting collector containers..."
    ssh "$REMOTE_HOST" "cd ~/sib-collector && HOSTNAME=\$(hostname) docker compose up -d"
fi

echo "[3/4] Waiting for collectors to start..."
sleep 5

echo "[4/4] Verifying deployment..."
if [ "$STACK" = "grafana" ]; then
    ssh "$REMOTE_HOST" "docker logs sib-alloy --tail 10 2>&1" || true
else
    ssh "$REMOTE_HOST" "docker logs sib-vector --tail 10 2>&1" || true
fi

echo ""
echo "========================================"
echo "   Deployment Complete!"
echo "========================================"
echo ""
echo "Collectors are now sending data to: $SIB_SERVER"
echo ""
echo "Check the Fleet Overview dashboard in Grafana:"
echo "  http://$SIB_SERVER:3000"
echo ""
