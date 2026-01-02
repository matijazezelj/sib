# 🛡️ SIEM in a Box Documentation

Welcome to the SIB documentation. This guide covers installation, configuration, and usage.

## Quick Start

```bash
# Clone and enter directory
cd sib

# Configure
cp .env.example .env
# Edit .env and set GRAFANA_ADMIN_PASSWORD

# Install
make install

# Open Grafana
make open
```

## Architecture

SIB consists of four main stacks:

### 1. Detection Stack (Falco)
- Runtime security monitoring
- Syscall-based detection
- Configurable rules
- Plugin support

### 2. Alerting Stack (Falcosidekick)
- Alert routing and fan-out
- 50+ output destinations
- Web UI for event viewing
- Prometheus metrics

### 3. Storage Stack (Loki + Prometheus)
- Log aggregation (Loki)
- Metrics storage (Prometheus)
- Long-term retention
- Query capabilities

### 4. Visualization (Grafana)
- Pre-built dashboards
- LogQL/PromQL queries
- Alerting rules
- Annotations

## Configuration Guide

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin password | `CHANGE_ME` |
| `FALCO_PRIORITY` | Minimum alert priority | `notice` |
| `SIDEKICK_DEBUG` | Enable debug logging | `false` |
| `LOKI_RETENTION_PERIOD` | Log retention | `168h` |

### Falco Rules

Rules are in YAML format and support:
- **Macros**: Reusable conditions
- **Lists**: Named arrays
- **Rules**: Detection logic

Example rule:
```yaml
- rule: Shell in Container
  desc: Detect shell spawn in container
  condition: spawned_process and container and proc.name in (shell_binaries)
  output: "Shell in container (user=%user.name cmd=%proc.cmdline)"
  priority: WARNING
  tags: [container, shell]
```

### Falcosidekick Outputs

Configure outputs in `alerting/config/config.yaml`:

#### Slack
```yaml
slack:
  webhookurl: "https://hooks.slack.com/services/XXX"
  channel: "#security"
  minimumpriority: "warning"
```

#### PagerDuty
```yaml
pagerduty:
  routingkey: "your-key"
  minimumpriority: "error"
```

## Commands Reference

### Installation
| Command | Description |
|---------|-------------|
| `make install` | Install all stacks |
| `make install-detection` | Install Falco only |
| `make install-alerting` | Install Falcosidekick only |
| `make install-storage` | Install Loki + Prometheus |
| `make install-grafana` | Install Grafana only |

### Management
| Command | Description |
|---------|-------------|
| `make start` | Start all services |
| `make stop` | Stop all services |
| `make restart` | Restart all services |
| `make status` | Show service status |

### Health & Logs
| Command | Description |
|---------|-------------|
| `make health` | Health check |
| `make doctor` | Diagnose issues |
| `make logs` | Tail all logs |
| `make logs-falco` | Tail Falco logs |

### Testing
| Command | Description |
|---------|-------------|
| `make test-alert` | Generate test alert |
| `make demo` | Run demo scenarios |
| `make test-rules` | Validate rules |

## LogQL Examples

```logql
# All events
{job="falco"}

# By priority
{job="falco"} | json | priority = "Critical"

# By container
{job="falco"} | json | container_name = "nginx"

# By rule pattern
{job="falco"} | json | rule =~ ".*shell.*"

# Count over time
sum by (priority) (count_over_time({job="falco"} [1h]))

# Rate of events
rate({job="falco"} [5m])
```

## Troubleshooting

### Falco Not Starting
1. Check Docker privileged mode
2. Verify kernel headers
3. Check logs: `make logs-falco`

### No Events Appearing
1. Generate test: `make test-alert`
2. Check Falcosidekick: `curl http://localhost:2801/healthz`
3. Verify Loki: `curl http://localhost:3100/ready`

### High Resource Usage
1. Reduce retention periods
2. Adjust Falco buffer sizes
3. Filter rules by priority

## Security Considerations

1. **Change default passwords** in `.env`
2. **Enable TLS** for production
3. **Restrict network access** to management ports
4. **Review rules** for your environment
5. **Monitor resource usage** to prevent DoS

## Links

- [Falco Documentation](https://falco.org/docs/)
- [Falcosidekick GitHub](https://github.com/falcosecurity/falcosidekick)
- [Grafana Loki](https://grafana.com/docs/loki/latest/)
- [Prometheus](https://prometheus.io/docs/)
