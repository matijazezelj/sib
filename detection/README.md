# Detection Stack

This directory contains the Falco runtime security engine configuration.

## Components

| Service | Port | Description |
|---------|------|-------------|
| **Falco** | - | Runtime security detection engine |

## What Falco Detects

Falco monitors system calls and Kubernetes audit events to detect:

- **Container Escapes**: Privileged container access, namespace changes
- **File Integrity**: Writes to sensitive directories (/etc, /usr/bin)
- **Process Anomalies**: Shells in containers, unexpected binaries
- **Network Activity**: Unexpected connections, port scanning
- **Credential Access**: Shadow file access, SSH key theft
- **Persistence**: Cron/systemd modifications

## Configuration

### Falco Configuration

`config/falco.yaml` is **generated** by `make install-detection` (via `scripts/generate-falco-config.sh`). Do not edit directly — changes will be overwritten on next install. To customize:

- Edit `config/falco.yaml.template` for structural changes
- Use `.env` settings (`MTLS_ENABLED`, etc.) for runtime options

Key settings in the generated config:
- `json_output`: Enable JSON output for Falcosidekick
- `priority`: Minimum alert priority
- `engine.kind`: `modern_ebpf` (default driver)

### Rules
- `config/rules/falco_rules.yaml`: Default rules (from Falco)
- `config/rules/custom_rules.yaml`: Your custom rules

Only files listed under `rules_files` in `config/falco.yaml.template` are loaded; `cloud_rules.yaml`, `webserver_rules.yaml` and `coding_agent_rules.yaml` (for hosts running Claude Code, Codex or [HIB](../docs/hib-integration.md)) are commented out by default. To use another rules file, add its path to `rules_files` and re-run `make install-detection`.

## Custom Rules Example

```yaml
- rule: Detect Cryptocurrency Mining
  desc: Detect crypto mining processes
  condition: >
    spawned_process and 
    proc.name in (xmrig, minerd, cpuminer)
  output: "Crypto miner detected (user=%user.name cmd=%proc.cmdline)"
  priority: CRITICAL
  tags: [cryptomining]
```

## Troubleshooting

### Falco Won't Start

Falco requires privileged access:
```bash
docker run --rm --privileged alpine echo "test"
```

### High CPU Usage

Adjust buffer sizes in `falco.yaml`:
```yaml
syscall_buf_size_preset: 4
```

### Check Dropped Events

```bash
docker exec sib-falco falco --stats-interval=1
```
