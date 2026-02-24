#!/bin/bash
# =============================================================================
# Threat Intel Feed Updater for SIB
# =============================================================================
# Downloads IP blocklists from various threat intel sources and makes them
# available for enrichment in Falco rules and Grafana dashboards.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEL_DIR="$SCRIPT_DIR/feeds"
COMBINED_FILE="$INTEL_DIR/combined_blocklist.txt"
FALCO_RULE_FILE="$SCRIPT_DIR/falco_threatintel_rules.yaml"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$INTEL_DIR"

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}            🔍 SIB Threat Intel Feed Updater                  ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Download feeds
download_feed() {
    local name=$1
    local url=$2
    local output="$INTEL_DIR/${name}.txt"
    
    echo -ne "  Downloading ${YELLOW}$name${NC}... "
    if curl -sf "$url" -o "$output" 2>/dev/null; then
        count=$(wc -l < "$output" | tr -d ' ')
        echo -e "${GREEN}✓${NC} ($count IPs)"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} Failed"
        return 1
    fi
}

echo -e "${CYAN}Downloading threat intel feeds...${NC}"
echo ""

# Abuse.ch - Feodo Tracker (Banking trojans, C2)
download_feed "feodotracker" "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# Abuse.ch - SSL Blacklist (Malware C2 SSL certs)
download_feed "sslbl" "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"

# Emerging Threats - Compromised IPs
download_feed "et_compromised" "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"

# Spamhaus DROP (Don't Route Or Peer)
download_feed "spamhaus_drop" "https://www.spamhaus.org/drop/drop.txt"

# Blocklist.de - SSH bruteforce
download_feed "blocklist_ssh" "https://lists.blocklist.de/lists/ssh.txt"

# Blocklist.de - All attacks
download_feed "blocklist_all" "https://lists.blocklist.de/lists/all.txt"

# CINSscore - CI Army (threat intel)
download_feed "ci_army" "https://cinsscore.com/list/ci-badguys.txt"

echo ""
echo -e "${CYAN}Combining feeds...${NC}"

# Combine all feeds, extract IPs, remove comments and duplicates
cat "$INTEL_DIR"/*.txt 2>/dev/null | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
    grep -v '^#' | \
    cut -d' ' -f1 | \
    cut -d'/' -f1 | \
    sort -u > "$COMBINED_FILE"

total_ips=$(wc -l < "$COMBINED_FILE" | tr -d ' ')
echo -e "  ${GREEN}✓${NC} Combined blocklist: ${YELLOW}$total_ips${NC} unique IPs"

echo ""
echo -e "${CYAN}Generating Falco rules...${NC}"

# Populate IP list from combined blocklist (capped for Falco memory)
MAX_IPS=${MAX_THREATINTEL_IPS:-10000}
actual_count=$(wc -l < "$COMBINED_FILE" | tr -d ' ')
if [ "$actual_count" -gt "$MAX_IPS" ]; then
    echo -e "  ${YELLOW}!${NC} Capping IP list to ${YELLOW}$MAX_IPS${NC} of $actual_count IPs (set MAX_THREATINTEL_IPS to change)"
fi

# Build the Falco rule file in parts so the IP list is populated
cat > "$FALCO_RULE_FILE" << 'HEADER'
# =============================================================================
# Threat Intel Rules for Falco - Auto-generated
# =============================================================================
# These rules detect connections to known malicious IPs from threat intel feeds.
# Run ./threatintel/update-feeds.sh to update the blocklists.
# =============================================================================

HEADER

# Generate IP list from combined blocklist
echo "# IPs loaded from combined_blocklist.txt" >> "$FALCO_RULE_FILE"
echo "- list: threatintel_ips" >> "$FALCO_RULE_FILE"
echo "  items:" >> "$FALCO_RULE_FILE"
head -n "$MAX_IPS" "$COMBINED_FILE" | awk '{printf "    - \"%s\"\n", $1}' >> "$FALCO_RULE_FILE"

# Append the rest of the rules
cat >> "$FALCO_RULE_FILE" << 'RULES'

# Macro to check if an IP is in the threat intel list
- macro: known_malicious_ip
  condition: >
    (fd.sip in (threatintel_ips) or fd.dip in (threatintel_ips))

# =============================================================================
# Detection Rules
# =============================================================================

- rule: Connection to Threat Intel IP (Outbound)
  desc: Detects outbound network connections to IPs from threat intelligence feeds
  condition: >
    outbound and
    fd.typechar = 4 and
    known_malicious_ip and
    fd.dip != "127.0.0.1" and
    fd.dip != "0.0.0.0"
  output: >
    Threat Intel Alert: Outbound connection to suspicious IP
    (connection=%fd.name command=%proc.cmdline container=%container.name image=%container.image.repository ip=%fd.dip port=%fd.dport)
  priority: WARNING
  tags: [network, threatintel, mitre_command_and_control]

- rule: Connection from Threat Intel IP (Inbound)
  desc: Detects inbound connections from IPs in threat intelligence feeds  
  condition: >
    inbound and
    fd.typechar = 4 and
    known_malicious_ip and
    fd.sip != "127.0.0.1"
  output: >
    Threat Intel Alert: Inbound connection from suspicious IP
    (connection=%fd.name command=%proc.cmdline source_ip=%fd.sip port=%fd.sport)
  priority: WARNING
  tags: [network, threatintel, mitre_initial_access]

# =============================================================================
# Specific Threat Categories
# =============================================================================

- rule: Connection to Known C2 Server
  desc: Detects connections to known Command & Control servers from threat intel feeds
  condition: >
    outbound and
    fd.typechar = 4 and
    fd.sip in (threatintel_ips)
  output: >
    Possible C2 Connection Detected
    (command=%proc.cmdline dest=%fd.dip:%fd.dport container=%container.name)
  priority: ERROR
  tags: [network, c2, mitre_command_and_control]

- rule: Connection to Crypto Mining Pool
  desc: Detects connections to known cryptocurrency mining pools
  condition: >
    outbound and
    fd.typechar = 4 and
    (fd.dport = 3333 or fd.dport = 5555 or fd.dport = 7777 or fd.dport = 14444 or fd.dport = 45700)
  output: >
    Crypto Mining Pool Connection Detected
    (command=%proc.cmdline dest=%fd.dip:%fd.dport container=%container.name)
  priority: CRITICAL
  tags: [network, cryptomining, mitre_impact]

# =============================================================================
# DNS-based Detection
# =============================================================================

- rule: Connection to Known Malicious IP
  desc: Detects any connection to IPs in the threat intel blocklist
  condition: >
    outbound and
    fd.typechar = 4 and
    fd.sip in (threatintel_ips)
  output: >
    Connection to Known Malicious IP
    (command=%proc.cmdline dest=%fd.dip:%fd.dport process=%proc.name container=%container.name)
  priority: WARNING
  tags: [network, threatintel, mitre_command_and_control]
RULES

echo -e "  ${GREEN}✓${NC} Generated: $FALCO_RULE_FILE"
loaded_count=$((actual_count < MAX_IPS ? actual_count : MAX_IPS))
echo -e "  ${GREEN}✓${NC} Loaded ${YELLOW}$loaded_count${NC} IPs into threatintel_ips list"

# Create a simple IP lookup script
cat > "$SCRIPT_DIR/lookup-ip.sh" << 'LOOKUP_EOF'
#!/bin/bash
# Quick IP lookup against threat intel feeds
IP="$1"
if [ -z "$IP" ]; then
    echo "Usage: $0 <ip-address>"
    exit 1
fi

INTEL_DIR="$(dirname "$0")/feeds"

echo "Checking $IP against threat intel feeds..."
echo ""

for feed in "$INTEL_DIR"/*.txt; do
    name=$(basename "$feed" .txt)
    if grep -q "^${IP}$" "$feed" 2>/dev/null; then
        echo "  ⚠️  FOUND in $name"
    fi
done

if grep -q "^${IP}$" "$INTEL_DIR/combined_blocklist.txt" 2>/dev/null; then
    echo ""
    echo "  🚨 IP is in combined blocklist!"
else
    echo ""
    echo "  ✓ IP not found in any blocklist"
fi
LOOKUP_EOF

chmod +x "$SCRIPT_DIR/lookup-ip.sh"
echo -e "  ${GREEN}✓${NC} Generated: $SCRIPT_DIR/lookup-ip.sh"

echo ""
echo -e "${CYAN}Summary:${NC}"
echo -e "  • Downloaded ${YELLOW}$(ls "$FEED_DIR"/*.txt 2>/dev/null | wc -l | tr -d ' ')${NC} threat intel feeds"
echo -e "  • Combined ${YELLOW}$total_ips${NC} unique malicious IPs"
echo -e "  • Generated Falco rules"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo -e "  Copy rules to Falco:"
echo -e "    ${YELLOW}cp $FALCO_RULE_FILE detection/config/rules/${NC}"
echo ""
echo -e "  Lookup an IP:"
echo -e "    ${YELLOW}./threatintel/lookup-ip.sh 1.2.3.4${NC}"
echo ""
echo -e "  Schedule updates (crontab):"
echo -e "    ${YELLOW}0 */6 * * * /path/to/sib/threatintel/update-feeds.sh${NC}"
echo ""
