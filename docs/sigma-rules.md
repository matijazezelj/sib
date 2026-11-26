---
layout: default
title: Sigma Rules - SIEM in a Box
---

# Sigma Rules Integration

Convert simple Sigma rules to Falco rules, LogQL or LogsQL.

[← Back to Home](index.md)

---

## Overview

[Sigma](https://sigmahq.io/) is a generic format for detection rules. SIB's converter, `sigma/sigma2sib.py`, produces:

1. **Falco rules** for runtime detection
2. **LogQL alerts** (Loki)
3. **LogsQL alerts** (VictoriaLogs)

It handles only a small part of the Sigma format, and its output can be wrong without any error. Read [What the converter handles](#what-the-converter-handles) and check every converted rule before you load it.

---

## Quick Start

The converter runs on the host and needs Python 3 with PyYAML (`pip install pyyaml`, or your distribution's package).

```bash
# Convert all Sigma rules in sigma/rules/ to Falco
make convert-sigma

# Convert a specific rule (prints to the terminal, writes no file)
./sigma/sigma2sib.py sigma/rules/crypto_mining.yml
```

---

## Included Sample Rules

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `crypto_mining.yml` | Cryptocurrency miners | Impact (T1496) |
| `shadow_access.yml` | `/etc/shadow` and `/etc/gshadow` access | Credential Access (T1003) |
| `ssh_keys.yml` | `authorized_keys` changes | Persistence (T1098) |
| `reverse_shell.yml` | Reverse shell patterns | Execution (T1059) |
| `container_escape.yml` | Docker and containerd socket access | Privilege Escalation (T1611) |

The converted Falco versions need editing before they detect anything useful:

- `shadow_access`, `ssh_keys` and `container_escape` match on file names, but the output only looks at process starts. Replace `spawned_process` with a file-open condition.
- `reverse_shell` comes out with its four groups joined by `and`, so it never matches. Change those joins to `or`.
- `crypto_mining` matches the program name as typed, so `/usr/bin/xmrig` matches and a bare `xmrig` does not.

---

## Adding Sigma Rules

### From SigmaHQ Repository

The [SigmaHQ rules repository](https://github.com/SigmaHQ/sigma) contains thousands of community rules. Many use features the converter doesn't handle.

```bash
# Clone the Sigma rules repo
git clone https://github.com/SigmaHQ/sigma.git /tmp/sigma

# Copy rules you want
cp /tmp/sigma/rules/linux/process_creation/<rule>.yml sigma/rules/

# Convert to Falco
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

`make convert-sigma` writes Falco rules only, to `sigma/rules/converted_falco_rules.yaml`. Run the converter directly for the other formats. Its default is `-o all`:

| `-o` | Output (directory input) |
|------|--------------------------|
| `falco` | `converted_falco_rules.yaml` |
| `logql` | `converted_logql_alerts.yaml` |
| `logsql` | `converted_logsql_alerts.yaml` |
| `both` | Falco and LogQL |
| `all` | all three |

The files are written into the input directory.

> **Delete old `converted_*.yaml` files before converting a directory again.** The converter reads them as Sigma rules. A leftover LogQL or LogsQL file becomes a Falco rule named `Unknown Rule` that matches every process start.

A converted Falco rule looks like this (list shortened):

```yaml
- rule: Crypto Mining Process Detection
  desc: "Detects known cryptocurrency mining processes"
  condition: >
    spawned_process and
    (proc.exe endswith "/xmrig" or proc.exe endswith "/minerd")
  output: >
    Sigma Alert: Crypto Mining Process Detection
    (user=%user.name cmd=%proc.cmdline file=%fd.name)
  priority: CRITICAL
  tags: [mitre_impact, mitre_technique_T1496, sigma]
```

MITRE tags are carried over (`attack.impact` becomes `mitre_impact`, `attack.t1496` becomes `mitre_technique_T1496`). The MITRE ATT&CK dashboard counts events by the tactic tags.

---

## Using Converted Rules

### Add to Falco

```bash
# Append to custom rules
cat sigma/rules/converted_falco_rules.yaml >> detection/config/rules/custom_rules.yaml

# Check that all rule files load, then restart Falco
make test-rules
make restart-detection
```

Alternatively, copy the file into `detection/config/rules/`, add `/etc/falco/rules/converted_falco_rules.yaml` to `rules_files` in `detection/config/falco.yaml.template`, and re-run `make install-detection`. Copying alone doesn't load it.

### LogQL and LogsQL Alerts

SIB doesn't copy these files anywhere and sets up no alert delivery for them (no Alertmanager, no vmalert). Use the queries as a starting point for your own alert rules, and test each one. Values containing spaces, quotes or `-` can produce invalid LogQL. The queries match the listed strings only, not the field they came from.

---

## What the converter handles

| Sigma feature | Result |
|---------------|--------|
| Fields in a selection | Joined with `and`; a list of values is joined with `or` |
| `contains`, `startswith`, `endswith` | Supported |
| `contains\|all` | Values are joined with `or`, not `and` |
| `re` and other modifiers | Not converted correctly: `re` is never treated as a regular expression, others become `contains` |
| `*` wildcards | Handled for single values, not inside lists |
| Numbers as single values, keyword lists | Dropped. A rule left with no conditions matches every process start |
| `condition` | Not parsed. If it contains `1 of` or `any of`, every clause is joined with `or`, otherwise with `and`. `or` and `not` are ignored |
| Aggregations, correlation | Not supported |
| `logsource` category | Ignored for Falco: every rule starts with `spawned_process`, so only process rules work as written |

Falco field mapping: `CommandLine` → `proc.cmdline`, `Image` → `proc.exe`, `ParentImage` → `proc.pname`, `User` → `user.name`, `TargetFilename` → `fd.name`, `SourceIp` → `fd.cip`, `DestinationIp` → `fd.sip`, `DestinationPort` → `fd.sport`, `ProcessName` → `proc.name`, `CurrentDirectory` → `proc.cwd`. Other field names are only lowercased, which usually gives a field Falco doesn't have.

---

## Troubleshooting

### Conversion Fails

Check rule syntax:
```bash
# Validate YAML
python3 -c "import yaml; yaml.safe_load(open('sigma/rules/myrule.yml'))"
```

### Rule Doesn't Trigger

1. Compare the converted condition with the Sigma rule (see the table above)

2. Verify the rule is in a file Falco loads:
   ```bash
   docker exec sib-falco grep "rule name" /etc/falco/rules/custom_rules.yaml
   ```

3. Check Falco logs:
   ```bash
   make logs-falco
   ```

4. Generate a matching event manually and watch logs

### False Positives

The converter turns `not filter` into a positive match, so don't add filters in the Sigma rule. Add the exclusion to the converted Falco condition:

```yaml
  condition: >
    spawned_process and
    proc.cmdline contains "wget"
    and not user.name = "backup_user"
```

---

## Resources

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [SigmaHQ Rules Repository](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Falco Rules Documentation](https://falco.org/docs/rules/)

---

[← Back to Home](index.md)
