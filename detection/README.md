# Detection Stack

This directory contains the Falco runtime security engine configuration.

## Components

| Service | Port | Description |
|---------|------|-------------|
| **Falco** | 8765 (internal, not published) | Runtime security detection engine; `/healthz` and `/metrics` |

## What Falco Detects

Falco monitors system calls to detect:

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
- Use `.env` settings for runtime options, then re-run `make install-detection`

| `.env` variable | Default | Purpose |
|---|---|---|
| `FALCO_VERSION` | `0.45.2` | Image tag |
| `FALCO_PRIORITY` | `notice` | Minimum alert priority |
| `FALCO_BUFFERED_OUTPUTS` | `false` | Output buffering |
| `FALCO_TIME_FORMAT` | `iso8601` | `iso8601` or `rfc2822` |
| `FALCO_HOSTNAME` | `sib-host` | Container hostname |
| `FALCO_DRIVER_TYPE` | auto-detected | `modern_ebpf`, `ebpf` or `kmod`; written to `.env` on install |
| `MTLS_ENABLED` | `false` | Send to Sidekick with a client certificate |
| `SIDEKICK_URL` | `http://sib-sidekick:2801/` | Sidekick address; use `https://` with mTLS |
| `FALCO_CLIENT_CERT_NAME` | `local` | Client certificate in `certs/clients/` |

Key settings in the generated config:
- `json_output`: Enable JSON output for Falcosidekick
- `priority`: Minimum alert priority
- `engine.kind`: `modern_ebpf` on kernel 5.8+

### Rules
- `config/rules/falco_rules.yaml`: Base macros and a subset of the Falco project's rules
- `config/rules/falco-incubating_rules.yaml`, `falco-sandbox_rules.yaml`: Empty placeholders
- `config/rules/custom_rules.yaml`: SIB's rules; add your own here

Only files listed under `rules_files` in `config/falco.yaml.template` are loaded; `cloud_rules.yaml`, `webserver_rules.yaml` and `coding_agent_rules.yaml` (for hosts running Claude Code, Codex or [HIB](../docs/hib-integration.md)) are commented out by default, as are the [threat intel](../docs/threat-intel.md) rules. To use another rules file, add its path to `rules_files` and re-run `make install-detection`.

Check that all rule files load with `make test-rules`.

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

### Dropped Events

Check Falco's logs and metrics:
```bash
docker logs sib-falco 2>&1 | grep -i drop
docker exec sib-falco curl -s http://127.0.0.1:8765/metrics | grep -i drop
```

To enlarge the syscall buffer, raise `buf_size_preset` in `scripts/generate-falco-config.sh` and re-run `make install-detection`.
