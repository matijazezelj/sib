#!/bin/bash
# =============================================================================
# Threat Intel Feed Updater for SIB
# =============================================================================
# Downloads IP blocklists from threat intel sources, combines them and
# generates Falco rules (falco_threatintel_rules.yaml) and lookup-ip.sh.
#
#   MAX_THREATINTEL_IPS    addresses loaded into Falco (default 10000)
#   MAX_THREATINTEL_NETS   network ranges loaded into Falco (default 2000)
#   THREATINTEL_OFFLINE=1  don't download: use the feed files already there
#   THREATINTEL_DIR        where feeds and outputs live (default: this folder)
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="${THREATINTEL_DIR:-$SCRIPT_DIR}"
INTEL_DIR="$BASE_DIR/feeds"
COMBINED_FILE="$INTEL_DIR/combined_blocklist.txt"
FALCO_RULE_FILE="$BASE_DIR/falco_threatintel_rules.yaml"
MAX_IPS=${MAX_THREATINTEL_IPS:-10000}
MAX_NETS=${MAX_THREATINTEL_NETS:-2000}

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Feeds, most valuable first: when the address cap cuts the list, it keeps the
# top of this order. name | url | kind (c2: command-and-control servers, also
# loaded into their own list and rule; ip: other attack sources).
FEEDS=(
    "feodotracker|https://feodotracker.abuse.ch/downloads/ipblocklist.txt|c2"
    "sslbl|https://sslbl.abuse.ch/blacklist/sslipblacklist.txt|c2"
    "et_compromised|https://rules.emergingthreats.net/blockrules/compromised-ips.txt|ip"
    "ci_army|https://cinsscore.com/list/ci-badguys.txt|ip"
    "spamhaus_drop|https://www.spamhaus.org/drop/drop.txt|ip"
    "netapi_honeypot|https://netapi.com/api2/?method=compromised&dataset_type=ip&header=0|ip"
    "blocklist_ssh|https://lists.blocklist.de/lists/ssh.txt|ip"
    "blocklist_all|https://lists.blocklist.de/lists/all.txt|ip"
)

mkdir -p "$INTEL_DIR"

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}            🔍 SIB Threat Intel Feed Updater                  ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# A failed download keeps the previous copy of that feed (if any).
download_feed() {
    local name=$1 url=$2
    local output="$INTEL_DIR/${name}.txt"
    echo -ne "  Downloading ${YELLOW}$name${NC}... "
    if curl -sfL --max-time 60 "$url" -o "$output.tmp" 2>/dev/null; then
        mv "$output.tmp" "$output"
        echo -e "${GREEN}✓${NC} ($(wc -l < "$output" | tr -d ' ') lines)"
    else
        rm -f "$output.tmp"
        echo -e "${YELLOW}⚠${NC} Failed$([ -f "$output" ] && echo ", keeping the previous copy")"
    fi
}

if [ "${THREATINTEL_OFFLINE:-0}" != 1 ]; then
    echo -e "${CYAN}Downloading threat intel feeds...${NC}"
    echo ""
    for f in "${FEEDS[@]}"; do
        IFS='|' read -r name url _ <<< "$f"
        download_feed "$name" "$url"
    done
    echo ""
fi

# Public IPv4 addresses (kind=ip) or ranges (kind=net) from feed files, in
# order, one per line. Each line's first word counts, after comments (# or ;)
# are cut; anything that isn't exactly an address or a range is dropped, as are
# private, loopback, link-local, CGNAT, multicast and reserved addresses, so a
# bad feed line can neither break the rules file nor flag internal traffic.
# awk reads every file to its end, newline or not; CRLF line ends (Feodo) are
# handled.
extract() {
    local kind=$1; shift
    [ $# -gt 0 ] || return 0
    awk -v kind="$kind" '
        { sub(/\r$/, ""); sub(/[#;].*/, ""); if (split($0, w, /[ \t,]+/) == 0) next; v = w[1]; if (v == "") v = w[2] }
        kind == "ip"  && v !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { next }
        kind == "net" && v !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ { next }
        {
            split(v, p, /[.\/]/)
            for (i = 1; i <= 4; i++) if (p[i] > 255 || length(p[i]) > 3) next
            if (kind == "net" && (p[5] < 8 || p[5] > 32)) next
            a = p[1] + 0; b = p[2] + 0
            if (a == 0 || a == 10 || a == 127 || a >= 224) next
            if (a == 169 && b == 254) next
            if (a == 172 && b >= 16 && b <= 31) next
            if (a == 192 && b == 168) next
            if (a == 100 && b >= 64 && b <= 127) next
            if (a == 192 && b == 0 && (p[3] + 0 == 0 || p[3] + 0 == 2)) next
            if (a == 198 && (b == 18 || b == 19)) next
            if (a == 198 && b == 51 && p[3] + 0 == 100) next
            if (a == 203 && b == 0 && p[3] + 0 == 113) next
            print v
        }' "$@"
}

feed_files() { # feed files of the given kind ("all" or c2), in FEEDS order
    local want=$1 f name kind
    for f in "${FEEDS[@]}"; do
        IFS='|' read -r name _ kind <<< "$f"
        [ "$want" = all ] || [ "$kind" = "$want" ] || continue
        [ -f "$INTEL_DIR/$name.txt" ] && echo "$INTEL_DIR/$name.txt"
    done
    return 0
}

echo -e "${CYAN}Combining feeds...${NC}"
mapfile -t ALL < <(feed_files all)
mapfile -t C2 < <(feed_files c2)

# Only the named feed files are read, never combined_blocklist.txt itself, so an
# address dropped by every feed drops out here too. Duplicates keep their first
# (highest priority) place.
extract ip "${ALL[@]}" | awk '!seen[$0]++' > "$INTEL_DIR/.ips.tmp"
extract net "${ALL[@]}" | awk '!seen[$0]++' > "$INTEL_DIR/.nets.tmp"
extract ip "${C2[@]}" | awk '!seen[$0]++' > "$INTEL_DIR/.c2.tmp"
sort -u "$INTEL_DIR/.ips.tmp" "$INTEL_DIR/.nets.tmp" > "$COMBINED_FILE.tmp"
mv "$COMBINED_FILE.tmp" "$COMBINED_FILE"

total_ips=$(wc -l < "$INTEL_DIR/.ips.tmp" | tr -d ' ')
total_nets=$(wc -l < "$INTEL_DIR/.nets.tmp" | tr -d ' ')
total_c2=$(wc -l < "$INTEL_DIR/.c2.tmp" | tr -d ' ')
echo -e "  ${GREEN}✓${NC} Combined blocklist: ${YELLOW}$total_ips${NC} addresses, ${YELLOW}$total_nets${NC} ranges ($total_c2 C2 servers)"

echo ""
echo -e "${CYAN}Generating Falco rules...${NC}"
if [ "$total_ips" -gt "$MAX_IPS" ]; then
    echo -e "  ${YELLOW}!${NC} Loading the first ${YELLOW}$MAX_IPS${NC} of $total_ips addresses in feed priority order (set MAX_THREATINTEL_IPS to change)"
fi
if [ "$total_nets" -gt "$MAX_NETS" ]; then
    echo -e "  ${YELLOW}!${NC} Loading the first ${YELLOW}$MAX_NETS${NC} of $total_nets ranges (set MAX_THREATINTEL_NETS to change)"
fi

# A Falco list. An empty one gets a TEST-NET address (never routed) so the
# rules still compile.
falco_list() {
    local name=$1 file=$2 max=$3 placeholder=$4
    echo "- list: $name"
    echo "  items:"
    if [ -s "$file" ]; then
        head -n "$max" "$file" | awk '{printf "    - \"%s\"\n", $1}'
    else
        echo "    - \"$placeholder\"   # placeholder: the feeds had no entries"
    fi
    echo ""
}

{
    cat << 'HEADER'
# =============================================================================
# Threat Intel Rules for Falco - Auto-generated by threatintel/update-feeds.sh
# =============================================================================
# Detects connections to and from addresses on threat intel blocklists. Load
# after falco_rules.yaml (it uses the outbound macro). Regenerate with
# make update-threatintel.
# =============================================================================

HEADER
    falco_list threatintel_ips "$INTEL_DIR/.ips.tmp" "$MAX_IPS" "192.0.2.1"
    falco_list threatintel_nets "$INTEL_DIR/.nets.tmp" "$MAX_NETS" "192.0.2.0/32"
    falco_list threatintel_c2_ips "$INTEL_DIR/.c2.tmp" "$MAX_IPS" "192.0.2.2"
    cat << 'RULES'
# Fields by connection direction, not fd.rip: Falco tells local from remote by
# the host's interfaces, which a Falco container without the host network
# can't see (fd.rip is then the local address).
- macro: threatintel_server
  condition: (fd.sip in (threatintel_ips) or fd.snet in (threatintel_nets))

- macro: threatintel_client
  condition: (fd.cip in (threatintel_ips) or fd.cnet in (threatintel_nets))

# An accepted IPv4 connection (falco_rules.yaml has no inbound macro).
- macro: threatintel_inbound
  condition: (evt.type in (accept, accept4) and fd.typechar = 4 and evt.rawres >= 0)

# =============================================================================
# Detection Rules
# =============================================================================

- rule: Connection to Known C2 Server
  desc: >
    Outbound connection to a command-and-control server listed by a C2 feed
    (Feodo Tracker, SSL Blacklist).
  condition: outbound and fd.typechar = 4 and fd.sip in (threatintel_c2_ips)
  output: >
    Possible C2 connection
    (ip=%fd.sip port=%fd.sport connection=%fd.name command=%proc.cmdline process=%proc.name
    container=%container.name)
  priority: ERROR
  tags: [network, threatintel, c2, mitre_command_and_control]

- rule: Connection to Threat Intel IP (Outbound)
  desc: >
    Outbound connection to an address on a threat intel blocklist (attack
    sources, compromised hosts, hijacked ranges); C2 servers have their own rule.
  condition: >
    outbound and fd.typechar = 4 and threatintel_server
    and not fd.sip in (threatintel_c2_ips)
  output: >
    Outbound connection to a blocklisted address
    (ip=%fd.sip port=%fd.sport connection=%fd.name command=%proc.cmdline process=%proc.name
    container=%container.name)
  priority: WARNING
  tags: [network, threatintel, mitre_command_and_control]

- rule: Connection from Threat Intel IP (Inbound)
  desc: >
    A connection from an address on a threat intel blocklist was accepted. Most
    are scanners and brute-force sources, so on an internet-facing host this is
    background noise; it shows who got through to a listening service.
  condition: threatintel_inbound and threatintel_client
  output: >
    Accepted connection from a blocklisted address
    (ip=%fd.cip local_port=%fd.sport connection=%fd.name command=%proc.cmdline process=%proc.name
    container=%container.name)
  priority: NOTICE
  tags: [network, threatintel, mitre_initial_access]

- rule: Connection to Crypto Mining Pool
  desc: Detects outbound connections to ports commonly used by cryptocurrency mining pools
  condition: >
    outbound and fd.typechar = 4 and fd.sport in (3333, 5555, 7777, 14444, 45700)
  output: >
    Crypto mining pool connection
    (ip=%fd.sip port=%fd.sport command=%proc.cmdline process=%proc.name container=%container.name)
  priority: CRITICAL
  tags: [network, cryptomining, mitre_impact]
RULES
} > "$FALCO_RULE_FILE.tmp"
mv "$FALCO_RULE_FILE.tmp" "$FALCO_RULE_FILE"
rm -f "$INTEL_DIR/.ips.tmp" "$INTEL_DIR/.nets.tmp" "$INTEL_DIR/.c2.tmp"

echo -e "  ${GREEN}✓${NC} Generated: $FALCO_RULE_FILE"
echo -e "  ${GREEN}✓${NC} Loaded ${YELLOW}$((total_ips < MAX_IPS ? total_ips : MAX_IPS))${NC} addresses and ${YELLOW}$((total_nets < MAX_NETS ? total_nets : MAX_NETS))${NC} ranges"

# A simple IP lookup script
cat > "$BASE_DIR/lookup-ip.sh" << 'LOOKUP_EOF'
#!/bin/bash
# Quick IP lookup against threat intel feeds (exact address matches)
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
    [ "$name" = combined_blocklist ] && continue
    if awk '{sub(/\r$/, ""); sub(/[#;].*/, ""); print $1}' "$feed" 2>/dev/null | grep -qxF "$IP"; then
        echo "  ⚠️  FOUND in $name"
    fi
done

if grep -qxF "$IP" "$INTEL_DIR/combined_blocklist.txt" 2>/dev/null; then
    echo ""
    echo "  🚨 IP is in combined blocklist!"
else
    echo ""
    echo "  ✓ IP not found in any blocklist (ranges aren't checked)"
fi
LOOKUP_EOF

chmod +x "$BASE_DIR/lookup-ip.sh"
echo -e "  ${GREEN}✓${NC} Generated: $BASE_DIR/lookup-ip.sh"

echo ""
echo -e "${CYAN}Summary:${NC}"
echo -e "  • ${YELLOW}${#ALL[@]}${NC} threat intel feeds"
echo -e "  • ${YELLOW}$total_ips${NC} addresses and ${YELLOW}$total_nets${NC} ranges"
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
