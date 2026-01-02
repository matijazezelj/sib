# Storage Stack

This directory contains Loki and Prometheus for storing security data.

## Components

| Service | Port | Description |
|---------|------|-------------|
| **Loki** | 3100 | Log aggregation for security events |
| **Prometheus** | 9090 | Metrics storage |

## Loki

Loki stores security events from Falcosidekick in a scalable, cost-efficient way.

### Features
- Label-based indexing (like Prometheus for logs)
- LogQL query language
- Integration with Grafana

### Configuration
Edit `config/loki-config.yml`:
- `retention_period`: How long to keep events (default: 7 days)
- `ingestion_rate_mb`: Max ingestion rate

### LogQL Examples

```logql
# All Falco events
{job="falco"}

# Critical priority events
{job="falco"} | json | priority = "Critical"

# Events from specific container
{job="falco"} | json | container_name = "nginx"

# Count by priority
sum by (priority) (count_over_time({job="falco"} [1h]))
```

## Prometheus

Prometheus collects metrics from Falcosidekick for monitoring.

### Metrics Available

- `falcosidekick_alerts_total`: Total alerts by priority
- `falcosidekick_outputs_total`: Output attempts by destination
- `falcosidekick_outputs_ok`: Successful outputs
- `falcosidekick_outputs_error`: Failed outputs

### PromQL Examples

```promql
# Alert rate by priority
sum(rate(falcosidekick_alerts_total[5m])) by (priority)

# Output success rate
sum(rate(falcosidekick_outputs_ok[5m])) / sum(rate(falcosidekick_outputs_total[5m]))
```

## Data Retention

| Component | Default | Config Location |
|-----------|---------|-----------------|
| Loki | 7 days | `config/loki-config.yml` |
| Prometheus | 15 days | `compose.yaml` |

## Troubleshooting

### Loki Not Accepting Events
```bash
# Check Loki health
curl http://localhost:3100/ready

# Check Loki logs
docker logs sib-loki
```

### High Memory Usage
Reduce retention periods or increase container limits.
