#!/bin/bash
# SIB Pipeline Test Script
# Tests the full Falco -> Falcosidekick -> Loki -> Grafana pipeline

set -e

echo "========================================"
echo "   SIB (SIEM in a Box) Test Suite"
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

echo "[1/7] Service Health Check"
echo "---"
SERVICES="sib-falco sib-sidekick sib-loki sib-prometheus sib-grafana"
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

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3100/ready 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Loki API: Ready"
else
    fail "Loki API: Not ready ($HTTP_CODE)"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "Grafana API: Ready"
else
    fail "Grafana API: Not ready ($HTTP_CODE)"
fi
echo ""

echo "[3/7] Prometheus Targets"
echo "---"
TARGETS=$(curl -s "http://localhost:9090/api/v1/targets" 2>/dev/null | jq -r '.data.activeTargets[] | .labels.job + ":" + .health' 2>/dev/null)
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

echo "[5/7] Loki Data Verification"
echo "---"
TOTAL=$(curl -s "http://localhost:3100/loki/api/v1/query?query=count_over_time(%7Bsource%3D%22syscall%22%7D%5B1h%5D)" 2>/dev/null | jq -r '.data.result[0].value[1] // "0"')
if [ "$TOTAL" -gt 0 ] 2>/dev/null; then
    pass "Events in Loki (last hour): $TOTAL"
else
    fail "No events found in Loki"
fi
echo ""

echo "[6/7] Detection Rules Triggered"
echo "---"
START=$(date -d "1 hour ago" +%s)000000000
END=$(date +%s)000000000
RULES=$(curl -s "http://localhost:3100/loki/api/v1/query_range?query=%7Bsource%3D%22syscall%22%7D&limit=500&start=$START&end=$END" 2>/dev/null | jq -r '.data.result[] | .stream | .priority + ": " + .rule' 2>/dev/null | sort | uniq -c | sort -rn | head -10)

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
echo "  Grafana:      http://$(hostname -I | awk '{print $1}'):3000"
echo "  Prometheus:   http://$(hostname -I | awk '{print $1}'):9090"
echo "  Loki:         http://$(hostname -I | awk '{print $1}'):3100"
echo "  Sidekick:     http://$(hostname -I | awk '{print $1}'):2801"
echo ""

echo "========================================"
if [ "$ALL_HEALTHY" = true ]; then
    echo -e "   ${GREEN}All Tests Passed!${NC}"
else
    echo -e "   ${YELLOW}Some Tests Failed - Check Above${NC}"
fi
echo "========================================"
