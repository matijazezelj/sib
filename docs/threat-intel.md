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

---

## Generated Files

After running `make update-threatintel`:

```
threatintel/
├── feeds/                      # Individual feed downloads
│   ├── feodo_ipblocklist.txt
│   ├── sslbl_aggressive.txt
│   ├── emerging_threats.txt
│   ├── spamhaus_drop.txt
│   ├── blocklist_de_ssh.txt
│   ├── blocklist_de_all.txt
│   └── cinsscore.txt
├── combined_blocklist.txt      # Unified blocklist (deduplicated)
├── falco_threatintel_rules.yaml # Generated Falco rules
└── lookup-ip.sh                # IP lookup utility
```

---

## Using Threat Intel

### Add to Falco Detection

```bash
# Append generated rules to custom rules
cat threatintel/falco_threatintel_rules.yaml >> detection/config/rules/custom_rules.yaml

# Restart to apply
make restart
```

### Look Up an IP

Check if an IP is in any blocklist:

```bash
./threatintel/lookup-ip.sh 1.2.3.4
```

Output:
```
Checking 1.2.3.4 against threat intel feeds...

[✓] Found in: feodo_ipblocklist.txt
[✓] Found in: emerging_threats.txt
[ ] Not in: spamhaus_drop.txt
[ ] Not in: blocklist_de_all.txt

Result: IP 1.2.3.4 is MALICIOUS (found in 2 feeds)
```

---

## Generated Falco Rules

The threat intel script generates rules like:

```yaml
- list: threat_intel_ips
  items: [1.2.3.4, 5.6.7.8, ...]

- rule: Connection to Threat Intel IP
  desc: Outbound connection to known malicious IP
  condition: >
    outbound and 
    fd.rip in (threat_intel_ips)
  output: >
    Connection to threat intel IP 
    (proc=%proc.name ip=%fd.rip user=%user.name)
  priority: CRITICAL
  tags: [network, mitre_command_and_control, threat_intel]
```

---

## Automating Updates

### Cron Job

Add to crontab to update feeds daily:

```bash
# Edit crontab
crontab -e

# Add this line (updates at 2 AM daily)
0 2 * * * cd /path/to/sib && make update-threatintel && make restart
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
ExecStartPost=/usr/bin/make restart
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
