---
layout: default
title: Sigma Rules - SIEM in a Box
---

# Sigma Rules Integration

Convert community detection rules to Falco and LogQL formats.

[← Back to Home](index.md)

---

## Overview

[Sigma](https://sigmahq.io/) is the universal language for security detection rules. SIB includes a converter that transforms Sigma rules into:

1. **Falco rules** — For runtime detection
2. **LogQL alerts** — For log-based detection in Loki

This means you're not locked into any single detection format. The entire Sigma rule ecosystem is available to you.

---

## Quick Start

```bash
# Convert all Sigma rules in sigma/rules/
make convert-sigma

# Convert a specific rule
./sigma/sigma2sib.py sigma/rules/crypto_mining.yml
```

---

## Included Sample Rules

SIB includes several example Sigma rules:

| Rule | Description | MITRE Tactic |
|------|-------------|--------------|
| `crypto_mining.yml` | Detects cryptocurrency miners | Impact (T1496) |
| `shadow_access.yml` | Password file access | Credential Access (T1003) |
| `ssh_keys.yml` | SSH private key access | Credential Access (T1552) |
| `reverse_shell.yml` | Reverse shell patterns | Execution (T1059) |
| `container_escape.yml` | Container breakout attempts | Privilege Escalation (T1611) |

---

## Adding Sigma Rules

### From SigmaHQ Repository

The [SigmaHQ rules repository](https://github.com/SigmaHQ/sigma) contains thousands of community rules.

```bash
# Clone the Sigma rules repo
git clone https://github.com/SigmaHQ/sigma.git /tmp/sigma

# Copy rules you want
cp /tmp/sigma/rules/linux/process_creation/*.yml sigma/rules/

# Convert to SIB format
make convert-sigma
```

### Custom Rules

Create your own Sigma rules in `sigma/rules/`:

```yaml
title: Detect Base64 Encoded Payload Execution
id: 12345678-1234-1234-1234-123456789abc
status: experimental
description: Detects execution of base64 encoded commands
author: Your Name
date: 2024/01/15
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'base64 -d'
            - 'base64 --decode'
    condition: selection
falsepositives:
    - Legitimate admin scripts
level: medium
tags:
    - attack.execution
    - attack.t1059
```

---

## Converter Output

Running `make convert-sigma` generates:

### Falco Rules

```yaml
# Generated from sigma/rules/crypto_mining.yml
- rule: Sigma - Cryptocurrency Mining Activity
  desc: Detects cryptocurrency mining processes
  condition: >
    spawned_process and 
    (proc.name in (xmrig, minerd, cpuminer) or
     proc.cmdline contains "stratum+tcp")
  output: >
    Cryptocurrency mining activity detected 
    (user=%user.name command=%proc.cmdline container_id=%container.id)
  priority: WARNING
  tags: [sigma, mitre_impact, T1496]
```

### LogQL Alerts

```yaml
# For Loki alerting
groups:
  - name: sigma_rules
    rules:
      - alert: CryptocurrencyMiningActivity
        expr: |
          count_over_time({job="falco"} 
            |~ "xmrig|minerd|cpuminer|stratum" [5m]) > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: Cryptocurrency mining detected
```

---

## Using Converted Rules

### Add to Falco

```bash
# Append to custom rules
cat sigma/output/falco_rules.yaml >> detection/config/rules/custom_rules.yaml

# Restart to apply
make restart
```

### Add to Loki Alerting

```bash
# Copy to Loki config
cp sigma/output/logql_alerts.yaml storage/config/rules/

# Restart Loki
docker compose -f storage/compose.yaml restart loki
```

---

## Sigma Rule Syntax

### Basic Structure

```yaml
title: Rule Name
id: unique-uuid
status: experimental|test|stable
description: What this rule detects
author: Author Name
date: YYYY/MM/DD
logsource:
    category: process_creation|file_event|network_connection
    product: linux|windows|macos
detection:
    selection:
        FieldName: value
        FieldName|modifier: value
    condition: selection
level: informational|low|medium|high|critical
tags:
    - attack.tactic
    - attack.technique_id
```

### Detection Modifiers

| Modifier | Description | Example |
|----------|-------------|---------|
| `contains` | Substring match | `CommandLine|contains: wget` |
| `startswith` | Prefix match | `FilePath|startswith: /tmp` |
| `endswith` | Suffix match | `FileName|endswith: .sh` |
| `re` | Regex match | `CommandLine|re: .*base64.*` |
| `all` | All values must match | `selection|all: true` |

### Conditions

```yaml
# Simple
condition: selection

# Multiple selections with AND
condition: selection1 and selection2

# Multiple selections with OR
condition: selection1 or selection2

# Negation
condition: selection and not filter

# Aggregation
condition: selection | count() > 10
```

---

## Supported Sigma Categories

The converter supports these Sigma log sources:

| Category | Maps to |
|----------|---------|
| `process_creation` | Falco spawned_process events |
| `file_event` | Falco file activity events |
| `network_connection` | Falco network events |
| `syslog` | Loki syslog stream |
| `auditd` | Loki audit logs |

---

## Troubleshooting

### Conversion Fails

Check rule syntax:
```bash
# Validate YAML
python3 -c "import yaml; yaml.safe_load(open('sigma/rules/myrule.yml'))"
```

### Rule Doesn't Trigger

1. Verify the rule is in Falco:
   ```bash
   docker exec sib-falco cat /etc/falco/rules.d/custom_rules.yaml | grep "rule name"
   ```

2. Check Falco logs:
   ```bash
   make logs-falco
   ```

3. Generate a matching event manually and watch logs

### False Positives

Add filters to the Sigma rule:
```yaml
detection:
    selection:
        CommandLine|contains: wget
    filter:
        User: backup_user
    condition: selection and not filter
```

---

## Resources

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [SigmaHQ Rules Repository](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Falco Rules Documentation](https://falco.org/docs/rules/)

---

[← Back to Home](index.md)
