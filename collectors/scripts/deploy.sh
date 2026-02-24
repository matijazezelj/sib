#!/bin/bash
# Deploy Alloy collector to remote host
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

echo "========================================"
echo "   SIB Alloy Collector Deployment"
echo "========================================"
echo ""
echo "Remote Host: $REMOTE_HOST"
echo "SIB Server:  $SIB_SERVER"
echo ""

# Create temp config with correct server IP
TEMP_CONFIG=$(mktemp)
sed "s|SIB_SERVER_IP|$SIB_SERVER|g" "$COLLECTORS_DIR/config/config.alloy" > "$TEMP_CONFIG"

echo "[1/4] Copying Alloy configuration..."
ssh "$REMOTE_HOST" "mkdir -p ~/sib-collector/config"
scp "$TEMP_CONFIG" "$REMOTE_HOST:~/sib-collector/config/config.alloy"
scp "$COLLECTORS_DIR/compose-grafana.yaml" "$REMOTE_HOST:~/sib-collector/compose.yaml"
rm "$TEMP_CONFIG"

echo "[2/4] Starting Alloy container..."
ssh "$REMOTE_HOST" "cd ~/sib-collector && HOSTNAME=\$(hostname) docker compose up -d"

echo "[3/4] Waiting for Alloy to start..."
sleep 5

echo "[4/4] Verifying deployment..."
ssh "$REMOTE_HOST" "docker logs sib-alloy --tail 10 2>&1" || true

echo ""
echo "========================================"
echo "   Deployment Complete!"
echo "========================================"
echo ""
echo "Alloy is now collecting:"
echo "  • System logs (/var/log/syslog, auth.log)"
echo "  • Journal logs (systemd)"
echo "  • Docker container logs"
echo "  • System metrics (CPU, memory, disk, network)"
echo ""
echo "Check the Fleet Overview dashboard in Grafana:"
echo "  http://$SIB_SERVER:3000"
echo ""
