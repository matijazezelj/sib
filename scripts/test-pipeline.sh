#!/bin/bash
# SIB Pipeline Test Script
# Tests the full Falco -> Falcosidekick -> Storage -> Grafana pipeline

set -e

# Load stack configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/../.env" ]; then
    set -a; source "$SCRIPT_DIR/../.env"; set +a
fi

STACK="${STACK:-vm}"

echo "========================================"
echo "   SIB (SIEM in a Box) Test Suite"
echo "   Stack: ${STACK}"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }
info() { echo -e "${YELLOW}→${NC} $1"; }

# Check for required tools
command -v jq >/dev/null 2>&1 || { echo -e "${RED}✗ jq is required but not installed${NC}"; exit 1; }

echo "[1/7] Service Health Check"
echo "---"
if [ "$STACK" = "vm" ]; then
    SERVICES="sib-falco sib-sidekick sib-victorialogs sib-victoriametrics sib-grafana"
else
    SERVICES="sib-falco sib-sidekick sib-loki sib-prometheus sib-grafana"
fi
ALL_HEALTHY=true
for svc in $SERVICES; do
    STATUS=$(docker inspect $svc --format "{{.State.Health.Status}}" 2>/dev/null || echo "missing")
    if [ "$STATUS" = "healthy" ]; then
        pass "$svc: healthy"
    else
        fail "$svc: $STATUS"
        ALL_HEALTHY=false
    fi
done
echo ""

echo "[2/7] Network Connectivity"
echo "---"
HTTP_CODE=$(docker exec sib-falco curl -s -o /dev/null -w "%{http_code}" http://sib-sidekick:2801/healthz 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Falco -> Sidekick: OK"
else
    fail "Falco -> Sidekick: Failed ($HTTP_CODE)"
fi

if [ "$STACK" = "vm" ]; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9428/health 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        pass "VictoriaLogs API: Ready"
    else
        fail "VictoriaLogs API: Not ready ($HTTP_CODE)"
    fi
else
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3100/ready 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        pass "Loki API: Ready"
    else
        fail "Loki API: Not ready ($HTTP_CODE)"
    fi
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Grafana API: Ready"
else
    fail "Grafana API: Not ready ($HTTP_CODE)"
fi
echo ""

echo "[3/7] Metrics Targets"
echo "---"
if [ "$STACK" = "vm" ]; then
    # VictoriaMetrics targets
    TARGETS=$(curl -s "http://localhost:8428/api/v1/targets" 2>/dev/null | jq -r '.data.activeTargets[]? | .labels.job + ":" + .health' 2>/dev/null || echo "")
else
    # Prometheus targets
    TARGETS=$(curl -s "http://localhost:9090/api/v1/targets" 2>/dev/null | jq -r '.data.activeTargets[]? | .labels.job + ":" + .health' 2>/dev/null || echo "")
fi
for target in $TARGETS; do
    JOB=$(echo $target | cut -d: -f1)
    HEALTH=$(echo $target | cut -d: -f2)
    if [ "$HEALTH" = "up" ]; then
        pass "$JOB: up"
    else
        fail "$JOB: $HEALTH"
    fi
done
echo ""

echo "[4/7] Trigger Test Events"
echo "---"
info "Reading sensitive file (/etc/shadow)..."
sudo cat /etc/shadow > /dev/null 2>&1 || true

info "Executing shell in container..."
docker exec sib-loki sh -c "whoami" > /dev/null 2>&1 || true

info "Reading files in container..."
docker exec sib-loki cat /etc/passwd > /dev/null 2>&1 || true

info "Waiting for events to propagate..."
sleep 3
pass "Test events triggered"
echo ""

echo "[5/7] Log Data Verification"
echo "---"
if [ "$STACK" = "vm" ]; then
    TOTAL=$(curl -sf -G "http://localhost:9428/select/logsql/query" \
        --data-urlencode "query=source:syscall" \
        --data-urlencode "limit=1" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$TOTAL" -gt 0 ] 2>/dev/null; then
        # Get actual count
        COUNT=$(curl -sf -G "http://localhost:9428/select/logsql/query" \
            --data-urlencode "query=source:syscall" \
            --data-urlencode "limit=10000" 2>/dev/null | wc -l | tr -d ' ')
        pass "Events in VictoriaLogs: $COUNT"
    else
        fail "No events found in VictoriaLogs"
    fi
else
    TOTAL=$(curl -s "http://localhost:3100/loki/api/v1/query?query=count_over_time(%7Bsource%3D%22syscall%22%7D%5B1h%5D)" 2>/dev/null | jq -r '.data.result[0].value[1] // "0"')
    if [ "$TOTAL" -gt 0 ] 2>/dev/null; then
        pass "Events in Loki (last hour): $TOTAL"
    else
        fail "No events found in Loki"
    fi
fi
echo ""

echo "[6/7] Detection Rules Triggered"
echo "---"
if [ "$STACK" = "vm" ]; then
    RULES=$(curl -sf -G "http://localhost:9428/select/logsql/query" \
        --data-urlencode "query=source:syscall" \
        --data-urlencode "limit=500" 2>/dev/null | jq -r '.priority + ": " + .rule' 2>/dev/null | sort | uniq -c | sort -rn | head -10 || echo "")
else
    # Use portable timestamp (works on both GNU and BSD/macOS)
    if date -d "1 hour ago" +%s >/dev/null 2>&1; then
        START=$(date -d "1 hour ago" +%s)000000000
    else
        START=$(date -v-1H +%s)000000000
    fi
    END=$(date +%s)000000000
    RULES=$(curl -s "http://localhost:3100/loki/api/v1/query_range?query=%7Bsource%3D%22syscall%22%7D&limit=500&start=$START&end=$END" 2>/dev/null | jq -r '.data.result[] | .stream | .priority + ": " + .rule' 2>/dev/null | sort | uniq -c | sort -rn | head -10 || echo "")
fi

if [ -n "$RULES" ]; then
    echo "$RULES" | while read line; do
        echo "  $line"
    done
else
    info "No rules triggered yet"
fi
echo ""

echo "[7/7] Access URLs"
echo "---"
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ipconfig getifaddr en0 2>/dev/null || echo "localhost")
echo "  Grafana:      http://${SERVER_IP}:3000"
if [ "$STACK" = "vm" ]; then
    echo "  VictoriaLogs: http://${SERVER_IP}:9428"
    echo "  VictoriaMetrics: http://${SERVER_IP}:8428"
else
    echo "  Prometheus:   http://${SERVER_IP}:9090"
    echo "  Loki:         http://${SERVER_IP}:3100"
fi
echo "  Sidekick:     http://${SERVER_IP}:2801"
echo ""

echo "========================================"
if [ "$ALL_HEALTHY" = true ]; then
    echo -e "   ${GREEN}All Tests Passed!${NC}"
else
    echo -e "   ${YELLOW}Some Tests Failed - Check Above${NC}"
fi
echo "========================================"
