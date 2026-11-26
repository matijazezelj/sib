---
layout: default
title: Threat Intelligence - SIEM in a Box
---

# Threat Intelligence

Enrich detections with IOC feeds from public blocklists.

[← Back to Home](index.md)

---

## Overview

SIB downloads public IP blocklists and turns them into Falco rules for connections to and from the listed addresses and ranges. Only IPv4 is used; domains, URLs and file hashes are not.

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
The NetAPI feed alone has tens of thousands of addresses, so at the default
cap it doesn't make it in; raise `MAX_THREATINTEL_IPS` to load it.
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
sudo systemctl daemon-reload
sudo systemctl enable --now sib-threatintel.timer
```

---

## Adding Custom Feeds

Add an entry to the `FEEDS` array in `threatintel/update-feeds.sh`, as
`name|url|kind`:

```bash
FEEDS=(
    "feodotracker|https://feodotracker.abuse.ch/downloads/ipblocklist.txt|c2"
    # ...
    "custom_feed|https://example.com/blocklist.txt|ip"
)
```

- `name`: the file name under `threatintel/feeds/` (`<name>.txt`).
- `kind`: `ip` for attack sources. `c2` for command-and-control servers, which
  also go into `threatintel_c2_ips` and its rule.
- Position matters: when a cap cuts a list, entries higher in the array win.

Then run `make update-threatintel`. A file you only drop into `feeds/` is not
combined or loaded.

### Feed Format

Plain text, one address or range per line. The first word of each line counts,
and anything after `#` or `;` is ignored:
```
# comment
1.2.3.4
5.6.7.8
1.10.16.0/20
```

Ranges must be between `/8` and `/32`. Private, loopback, link-local, CGNAT,
multicast, reserved and documentation addresses are dropped.

---

## Feed Sources

### Abuse.ch

- [Feodo Tracker](https://feodotracker.abuse.ch/) - Banking trojan C2
- [SSL Blacklist](https://sslbl.abuse.ch/) - Malicious SSL certificates
- [URLhaus](https://urlhaus.abuse.ch/) - Malware URLs (not included by default)

### Spamhaus

- [DROP List](https://www.spamhaus.org/drop/) - Don't Route Or Peer

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

The generated lists are capped. Raise or lower the caps with environment
variables; they are not read from `.env`, so set them in the cron line or
systemd unit too:

```bash
MAX_THREATINTEL_IPS=60000 MAX_THREATINTEL_NETS=2000 make update-threatintel
```

`THREATINTEL_OFFLINE=1` rebuilds the rules from the feed files already
downloaded. `THREATINTEL_DIR` changes where feeds and generated files go
(default `threatintel/`).

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

1. Verify the rules file is listed in Falco's config and was loaded:
   ```bash
   grep threatintel detection/config/falco.yaml   # line must not be commented out
   docker exec sib-falco ls /etc/falco/rules/falco_threatintel_rules.yaml
   make logs-falco   # look for rule loading errors
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

Some feeds are aggressive. `falco_threatintel_rules.yaml` is overwritten on
every update, so make changes in `threatintel/update-feeds.sh`:
- Remove noisy feeds from `FEEDS` (Feodo Tracker and Spamhaus DROP are the
  high-confidence ones)
- Add exclusions for known-good IPs, or change a rule's priority, in the rules
  block of the script

---

## Security Notes

- **Do not expose your blocklist**: Attackers could use it to evade detection
- **Verify feed sources**: Only use trusted, reputable feeds
- **Monitor for false positives**: Legitimate services occasionally appear in blocklists
- **Keep feeds updated**: Stale IOCs are less useful and may cause FPs

---

[← Back to Home](index.md)
