# Sigma Rules Integration

SIB includes tooling to convert [Sigma](https://github.com/SigmaHQ/sigma) rules to Falco rules and LogQL alerts.

## What is Sigma?

Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner. It's the "YARA for logs" - a universal detection rule format that can be converted to various SIEM systems.

## Usage

### Convert Sigma Rules

```bash
# Install dependencies
pip install pyyaml

# Convert a single rule
./sigma/sigma2sib.py sigma/rules/crypto_mining.yml

# Convert all rules in a directory
./sigma/sigma2sib.py sigma/rules/

# Output only Falco format
./sigma/sigma2sib.py sigma/rules/ -o falco

# Output only LogQL alerts
./sigma/sigma2sib.py sigma/rules/ -o logql
```

### Output Formats

#### Falco Rules
Converted rules are saved to `converted_falco_rules.yaml` and can be copied to `detection/config/rules/`.

```yaml
- rule: Crypto Mining Process Detection
  desc: "Detects known cryptocurrency mining processes"
  condition: >
    spawned_process and
    (proc.exe endswith "/xmrig" or proc.exe endswith "/minerd")
  output: >
    Sigma Alert: Crypto Mining Process Detection
    (user=%user.name cmd=%proc.cmdline)
  priority: CRITICAL
  tags: [mitre_impact, mitre_technique_T1496, sigma]
```

#### LogQL Alerts
Converted rules are saved to `converted_logql_alerts.yaml` for use with Loki Ruler.

```yaml
groups:
  - name: sigma_crypto_mining_process_detection
    rules:
      - alert: Crypto_Mining_Process_Detection
        expr: count_over_time({source="syscall"} |~ "(?i)(xmrig|minerd)" [5m]) > 0
        labels:
          severity: critical
          source: sigma
```

## Included Sample Rules

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `crypto_mining.yml` | Detects cryptocurrency miners | T1496 |
| `shadow_access.yml` | Detects /etc/shadow access | T1003 |
| `ssh_keys.yml` | Detects authorized_keys changes | T1098.004 |
| `reverse_shell.yml` | Detects reverse shell patterns | T1059 |
| `container_escape.yml` | Detects Docker socket access | T1611 |

## Using Sigma Rules from SigmaHQ

Download rules from the official Sigma repository:

```bash
# Clone the Sigma repository
git clone https://github.com/SigmaHQ/sigma.git /tmp/sigma

# Convert Linux rules
./sigma/sigma2sib.py /tmp/sigma/rules/linux/ -o falco

# Convert specific categories
./sigma/sigma2sib.py /tmp/sigma/rules/linux/process_creation/ -o falco
```

## Limitations

The converter handles basic Sigma rule patterns. Complex rules may require manual adjustment:

- **Modifiers**: Only `contains`, `endswith`, `startswith` are fully supported. Others (e.g., `re`, `cidr`, `base64`) are silently passed through as-is and will produce invalid Falco conditions.
- **Wildcard group selectors**: `1 of selection*`, `all of them`, `X of filter*` patterns silently degrade — all matched selections are joined with `and` regardless of the numeric threshold. Review converted output when the original rule uses these constructs.
- **Nested condition logic**: Complex boolean trees with mixed `and`/`or`/`not` groupings may not faithfully preserve operator precedence. Always validate converted rules with `make test-rules`.
- **Aggregations**: `count()`, `sum()` conditions need manual conversion
- **Correlation**: Multi-event correlation rules are not supported
- **Field Mapping**: Some fields may not have direct Falco equivalents

## Adding to Falco

Copy converted rules to the Falco rules directory:

```bash
# Convert rules
./sigma/sigma2sib.py sigma/rules/ -o falco

# Copy to Falco
cp sigma/rules/converted_falco_rules.yaml detection/config/rules/

# Restart Falco to load new rules
make restart-detection
```

## MITRE ATT&CK Tags

Sigma rules include MITRE ATT&CK tags that are preserved during conversion:

- `attack.impact` → `mitre_impact`
- `attack.t1496` → `mitre_technique_T1496`
- `attack.persistence` → `mitre_persistence`

These tags are used by the MITRE ATT&CK dashboard to show coverage.
