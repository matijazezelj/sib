# Sigma Rules Integration

SIB includes tooling to convert [Sigma](https://github.com/SigmaHQ/sigma) rules to Falco rules, LogQL (Loki) and LogsQL (VictoriaLogs) alerts. It handles only simple rules, so check its output before you use it. Full guide: [docs/sigma-rules.md](../docs/sigma-rules.md).

## What is Sigma?

Sigma is a generic and open signature format that allows you to describe relevant log events in a straightforward manner. It's the "YARA for logs" - a universal detection rule format that can be converted to various SIEM systems.

## Usage

### Convert Sigma Rules

```bash
# Install dependencies
pip install pyyaml

# Convert a single rule (prints to the terminal, writes no file)
./sigma/sigma2sib.py sigma/rules/crypto_mining.yml

# Convert all rules in a directory, all formats
./sigma/sigma2sib.py sigma/rules/

# Output only Falco format (same as make convert-sigma)
./sigma/sigma2sib.py sigma/rules/ -o falco

# Output only LogQL or LogsQL alerts
./sigma/sigma2sib.py sigma/rules/ -o logql
./sigma/sigma2sib.py sigma/rules/ -o logsql
```

### Output Formats

For directory input the converter writes `converted_falco_rules.yaml`, `converted_logql_alerts.yaml` and `converted_logsql_alerts.yaml` into that directory, depending on `-o` (`falco`, `logql`, `logsql`, `both` = Falco and LogQL, `all` = default).

Delete old `converted_*.yaml` files before converting the directory again: they are read as Sigma rules, and a leftover LogQL or LogsQL file becomes a Falco rule that matches every process start.

SIB doesn't copy the LogQL or LogsQL files anywhere and sets up no alert delivery for them (no Alertmanager, no vmalert).

## Included Sample Rules

| Rule | Description | MITRE ATT&CK |
|------|-------------|--------------|
| `crypto_mining.yml` | Detects cryptocurrency miners | T1496 |
| `shadow_access.yml` | Detects /etc/shadow access | T1003 |
| `ssh_keys.yml` | Detects authorized_keys changes | T1098 |
| `reverse_shell.yml` | Detects reverse shell patterns | T1059 |
| `container_escape.yml` | Detects Docker and containerd socket access | T1611 |

Several of these need editing after conversion; see [the full guide](../docs/sigma-rules.md#included-sample-rules).

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

- **Conditions**: `condition` is not parsed. If it contains `1 of` or `any of`, every clause is joined with `or`, otherwise with `and`. `or` is ignored and `not filter` becomes a positive match.
- **Modifiers**: only `contains`, `endswith` and `startswith` work. `all` is ignored (values are joined with `or`); `re` is never treated as a regular expression and others become `contains`.
- **Dropped input**: single numeric values and keyword lists are dropped. A rule left with no conditions matches every process start.
- **Log source**: every Falco rule starts with `spawned_process`, so file and network rules need editing.
- **Field mapping**: unknown field names are only lowercased and usually don't exist in Falco.
- **Aggregations and correlation**: not supported.

## Adding to Falco

Append converted rules to the custom rules file Falco loads:

```bash
# Convert rules
make convert-sigma

# Review the output, then append to custom rules
cat sigma/rules/converted_falco_rules.yaml >> detection/config/rules/custom_rules.yaml

# Check that all rule files load, then restart Falco
make test-rules
make restart-detection
```

Copying the file into `detection/config/rules/` is not enough: Falco only loads the files listed under `rules_files` in `detection/config/falco.yaml.template`. Alternatively, add the file's path there and re-run `make install-detection`.

## MITRE ATT&CK Tags

Sigma rules include MITRE ATT&CK tags that are preserved during conversion:

- `attack.impact` → `mitre_impact`
- `attack.t1496` → `mitre_technique_T1496`
- `attack.persistence` → `mitre_persistence`

The MITRE ATT&CK dashboard counts events by the tactic tags.
