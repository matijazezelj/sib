---
layout: default
title: Threat Intelligence - SIEM in a Box
---

# Threat Intelligence

Enrich detections with IOC feeds from public blocklists.

[← Back to Home](index.md)

---

## Overview

SIB can automatically download and integrate threat intelligence feeds, enriching your detections with known malicious IPs, domains, and indicators of compromise (IOCs).

---

## Quick Start

```bash
# Download/update threat intel feeds
make update-threatintel
```

This downloads feeds, combines them, and generates Falco rules.

---

## Included Feeds

| Source | Feed Type | Description |
|--------|-----------|-------------|
| **Feodo Tracker** | C&C IPs | Banking trojan command & control servers |
| **SSL Blacklist** | SSL abuse IPs | Malicious SSL certificate IPs |
| **Emerging Threats** | Compromised IPs | Known compromised hosts |
| **Spamhaus DROP** | Hijacked IPs | Don't Route Or Peer list |
| **Blocklist.de** | Attack IPs | Brute force and attack sources |
| **CINSscore** | Threat scoring | Collective Intelligence Network Security |
| **NetAPI** | Attack IPs | Addresses that attacked NetAPI honeypot sensors in the last 48 hours |

---

## Generated Files

After running `make update-threatintel`:

```
threatintel/
├── feeds/                      # Individual feed downloads
│   ├── feodotracker.txt
│   ├── sslbl.txt
│   ├── et_compromised.txt
│   ├── ci_army.txt
│   ├── spamhaus_drop.txt
│   ├── netapi_honeypot.txt
│   ├── blocklist_ssh.txt
│   ├── blocklist_all.txt
│   └── combined_blocklist.txt  # Unified blocklist (deduplicated)
├── falco_threatintel_rules.yaml # Generated Falco rules
└── lookup-ip.sh                # IP lookup utility
```

---

## Using Threat Intel

### Add to Falco Detection

`make update-threatintel` writes `threatintel/falco_threatintel_rules.yaml`
with the address lists filled in. Falco doesn't load it until you add it:

1. Copy it next to SIB's other rule packs:
   `cp threatintel/falco_threatintel_rules.yaml detection/config/rules/`
2. Uncomment `/etc/falco/rules/falco_threatintel_rules.yaml` under
   `rules_files` in `detection/config/falco.yaml.template` (it must come after
   `falco_rules.yaml`, whose `outbound` macro it uses).
3. `make install-detection`. `make test-rules` checks that it loads.

For fleet hosts, add `falco_threatintel_rules.yaml` to the host's
`falco_custom_rules` and run `make update-rules`.

Each update needs the copy again (step 1); Falco reloads a changed rules
file by itself.

When a list is longer than its cap (`MAX_THREATINTEL_IPS`, default 10000;
`MAX_THREATINTEL_NETS`, default 2000), the feeds are kept in priority order:
the C2 feeds first, then Emerging Threats, CINSscore, Spamhaus, NetAPI,
blocklist.de.
Only public IPv4 addresses and ranges are kept; private, loopback, link-local
and reserved ones in a feed are dropped.

### Look Up an IP

Check if an IP is in any blocklist:

```bash
./threatintel/lookup-ip.sh 1.2.3.4
```

Output:
```
Checking 1.2.3.4 against threat intel feeds...

  ⚠️  FOUND in feodotracker
  ⚠️  FOUND in et_compromised

  🚨 IP is in combined blocklist!
```

It matches exact addresses; an address inside a listed range (Spamhaus DROP)
isn't reported.

---

## Generated Falco Rules

The threat intel script generates three lists and four rules:

| Rule | Priority | Fires on |
|------|----------|----------|
| Connection to Known C2 Server | ERROR | outbound connection to an address from a C2 feed (Feodo Tracker, SSL Blacklist) |
| Connection to Threat Intel IP (Outbound) | WARNING | outbound connection to any other listed address or range |
| Connection from Threat Intel IP (Inbound) | NOTICE | an accepted connection from a listed address or range. Most are scanners, so on an internet-facing host this is background noise |
| Connection to Crypto Mining Pool | CRITICAL | outbound connection to a common mining pool port |

```yaml
- list: threatintel_ips
  items:
    - "1.2.3.4"
- list: threatintel_nets
  items:
    - "1.10.16.0/20"

- macro: threatintel_server
  condition: (fd.sip in (threatintel_ips) or fd.snet in (threatintel_nets))

- rule: Connection to Threat Intel IP (Outbound)
  condition: >
    outbound and fd.typechar = 4 and threatintel_server
    and not fd.sip in (threatintel_c2_ips)
  output: >
    Outbound connection to a blocklisted address
    (ip=%fd.sip port=%fd.sport connection=%fd.name command=%proc.cmdline ...)
  priority: WARNING
```

The rules match by connection direction (`fd.sip` is the server, `fd.cip` the
client), not `fd.rip`: Falco tells local from remote by the host's network
interfaces, which a Falco container without the host network can't see.

---

## Automating Updates

### Cron Job

Add to crontab to update feeds daily:

```bash
# Edit crontab
crontab -e

# Add this line (updates at 2 AM daily)
0 2 * * * cd /path/to/sib && make update-threatintel && cp threatintel/falco_threatintel_rules.yaml detection/config/rules/
```

### Systemd Timer

Create `/etc/systemd/system/sib-threatintel.timer`:

```ini
[Unit]
Description=Update SIB Threat Intelligence Daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Create `/etc/systemd/system/sib-threatintel.service`:

```ini
[Unit]
Description=SIB Threat Intel Update

[Service]
Type=oneshot
WorkingDirectory=/path/to/sib
ExecStart=/usr/bin/make update-threatintel
ExecStartPost=/usr/bin/cp threatintel/falco_threatintel_rules.yaml detection/config/rules/
```

Enable the timer:
```bash
sudo systemctl enable --now sib-threatintel.timer
```

---

## Adding Custom Feeds

Edit `threatintel/update-feeds.sh` to add your own feeds:

```bash
# Add a custom feed
CUSTOM_FEED="https://example.com/blocklist.txt"
curl -s "$CUSTOM_FEED" > feeds/custom_feed.txt
```

### Feed Format

Feeds should be plain text with one IP per line:
```
1.2.3.4
5.6.7.8
# Comments are ignored
10.0.0.1
```

CIDR notation is also supported:
```
192.168.0.0/16
10.0.0.0/8
```

---

## Feed Sources

### Abuse.ch

- [Feodo Tracker](https://feodotracker.abuse.ch/) - Banking trojan C2
- [SSL Blacklist](https://sslbl.abuse.ch/) - Malicious SSL certificates
- [URLhaus](https://urlhaus.abuse.ch/) - Malware URLs (not included by default)

### Spamhaus

- [DROP List](https://www.spamhaus.org/drop/) - Don't Route Or Peer
- [EDROP List](https://www.spamhaus.org/drop/) - Extended DROP

### Emerging Threats

- [Compromised IPs](https://rules.emergingthreats.net/) - ET Open rules

### Blocklist.de

- [SSH Attacks](https://www.blocklist.de/en/export.html) - SSH brute force
- [All Attacks](https://www.blocklist.de/en/export.html) - All attack types

### CINSscore

- [CI Army List](https://cinsscore.com/) - Collective intelligence

### NetAPI

- [Compromised IPs](https://netapi.com/compromised-ips/) - Honeypot attack sources, CC BY 4.0

---

## Performance Considerations

### Large Blocklists

If you have very large blocklists (>100k IPs):

1. **Split into multiple lists**: Falco handles multiple smaller lists better
2. **Use CIDR where possible**: `10.0.0.0/8` is more efficient than 16M individual IPs
3. **Consider sampling**: For very large feeds, sample or prioritize high-confidence IOCs

### Memory Usage

Each IP in a Falco list uses memory. Monitor with:
```bash
docker stats sib-falco
```

---

## Troubleshooting

### Feed Download Fails

Check network connectivity:
```bash
curl -I https://feodotracker.abuse.ch/downloads/ipblocklist.txt
```

Some feeds may require specific user agents or have rate limits.

### Rules Not Triggering

1. Verify rules are loaded:
   ```bash
   docker exec sib-falco cat /etc/falco/rules.d/custom_rules.yaml | grep threat_intel
   ```

2. Check the IP is in the list:
   ```bash
   ./threatintel/lookup-ip.sh <suspicious-ip>
   ```

3. Generate a test connection (carefully, in a lab):
   ```bash
   # This is just for testing - don't connect to actual malicious IPs
   curl --connect-timeout 1 http://<known-bad-ip>:80 || true
   ```

### Too Many False Positives

Some feeds are aggressive. Consider:
- Using only high-confidence feeds (Feodo, Spamhaus DROP)
- Adding exclusions for known-good IPs
- Reducing priority from CRITICAL to WARNING

---

## Security Notes

- **Do not expose your blocklist**: Attackers could use it to evade detection
- **Verify feed sources**: Only use trusted, reputable feeds
- **Monitor for false positives**: Legitimate services occasionally appear in blocklists
- **Keep feeds updated**: Stale IOCs are less useful and may cause FPs

---

[← Back to Home](index.md)
