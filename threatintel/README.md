# Threat Intelligence Integration

SIB includes threat intelligence feed integration to enrich security events with known malicious IP data.

## Features

- **IP Blocklists**: Download and aggregate IP blocklists from multiple sources
- **Falco Rules**: Auto-generated rules to detect connections to malicious IPs
- **IP Lookup**: Quick command-line tool to check IPs against all feeds

## Supported Threat Intel Sources

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Banking trojans, C2 servers | 5 min |
| [SSL Blacklist](https://sslbl.abuse.ch/) | Malware C2 SSL certificates | 5 min |
| [Emerging Threats](https://rules.emergingthreats.net/) | Compromised IPs | Daily |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Don't Route Or Peer list | Daily |
| [Blocklist.de](https://www.blocklist.de/) | SSH bruteforce, attacks | Hourly |
| [CINSscore](https://cinsscore.com/) | CI Army threat intel | Daily |
| [NetAPI](https://netapi.com/compromised-ips/) | IPs that attacked NetAPI honeypot sensors in the last 48 hours | Hourly |

## Usage

### Update Threat Intel Feeds

```bash
# Download/update all feeds
./threatintel/update-feeds.sh

# Or via Makefile
make update-threatintel
```

This will:
1. Download IP blocklists from all sources
2. Combine them into a single deduplicated list
3. Generate Falco rules for threat intel detection

### Lookup an IP

```bash
# Check if an IP is in any blocklist
./threatintel/lookup-ip.sh 1.2.3.4

# Output (exact addresses only; ranges aren't checked):
# Checking 1.2.3.4 against threat intel feeds...
#   ⚠️  FOUND in feodotracker
#   ⚠️  FOUND in sslbl
#   🚨 IP is in combined blocklist!
```

### Enable Threat Intel Rules in Falco

Falco only loads the files listed under `rules_files` in
`detection/config/falco.yaml.template`, so copying the file is not enough.
Because the rules are regenerated on every feed update, load them as their own
file rather than appending them to `custom_rules.yaml` (which would duplicate
them on each update).

First copy the generated file in (Falco won't start if a listed rules file is
missing):

```bash
cp threatintel/falco_threatintel_rules.yaml detection/config/rules/
```

Then, once, add this line to `rules_files` in
`detection/config/falco.yaml.template` and re-run `make install-detection`:

```yaml
  - /etc/falco/rules/falco_threatintel_rules.yaml
```

After later feed updates, copy the file again. Falco reloads a changed rules
file by itself.

## Automated Updates

Schedule regular feed updates via cron:

```bash
# Update every 6 hours and copy the rules to Falco
0 */6 * * * cd /path/to/sib && make update-threatintel && cp threatintel/falco_threatintel_rules.yaml detection/config/rules/
```

## Feed Files

After running `update-feeds.sh`:

```
threatintel/
├── feeds/
│   ├── feodotracker.txt       # Feodo Tracker IPs (C2)
│   ├── sslbl.txt              # SSL Blacklist IPs (C2)
│   ├── et_compromised.txt     # Emerging Threats IPs
│   ├── ci_army.txt            # CINSscore CI Army
│   ├── spamhaus_drop.txt      # Spamhaus DROP (ranges)
│   ├── netapi_honeypot.txt    # NetAPI honeypot attackers (CC BY 4.0)
│   ├── blocklist_ssh.txt      # Blocklist.de SSH
│   ├── blocklist_all.txt      # Blocklist.de All
│   └── combined_blocklist.txt # All feeds combined (addresses and ranges)
├── falco_threatintel_rules.yaml  # Generated Falco rules
├── lookup-ip.sh               # IP lookup script
└── update-feeds.sh            # Feed updater
```

## Falco Rules Generated

The feed updater generates Falco rules for:

| Rule | Priority | Description |
|------|----------|-------------|
| Connection to Known C2 Server | ERROR | Outbound connection to an address from a C2 feed (Feodo Tracker, SSL Blacklist) |
| Connection to Threat Intel IP (Outbound) | WARNING | Outbound connection to any other blocklisted address or range |
| Connection from Threat Intel IP (Inbound) | NOTICE | Accepted connection from a blocklisted address or range (mostly scanners: noisy on internet-facing hosts) |
| Connection to Crypto Mining Pool | CRITICAL | Outbound connection to a common mining pool port |

The lists are `threatintel_ips` (addresses, at most `MAX_THREATINTEL_IPS`,
default 10000), `threatintel_nets` (ranges such as Spamhaus DROP, at most
`MAX_THREATINTEL_NETS`, default 2000) and `threatintel_c2_ips`. When the cap
cuts a list, it keeps the feeds in priority order: the C2 feeds first, then
Emerging Threats, CINSscore, Spamhaus, NetAPI, blocklist.de. Only public IPv4
addresses and ranges are kept. The rules are generated, not loaded: see
[Enable Threat Intel Rules in Falco](#enable-threat-intel-rules-in-falco).

## Settings

Environment variables for `update-feeds.sh` / `make update-threatintel` (not
read from `.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_THREATINTEL_IPS` | `10000` | Addresses loaded into Falco |
| `MAX_THREATINTEL_NETS` | `2000` | Ranges loaded into Falco |
| `THREATINTEL_OFFLINE` | `0` | `1`: don't download, use the feed files already there |
| `THREATINTEL_DIR` | `threatintel/` | Where feeds and generated files live |

## Adding Custom Feeds

Add an entry to the `FEEDS` array in `update-feeds.sh`, as `name|url|kind`:

```bash
"custom_feed|https://example.com/blocklist.txt|ip"
```

`kind` is `ip`, or `c2` for command-and-control servers. Entries higher in the
array win when a cap applies.

The feed should be a text file with one public IPv4 address or range (`/8` to
`/32`) per line; `#` and `;` start comments.
