# Storage Stack

This directory contains the storage backends for SIB. Two stack configurations are available:

| Stack | Components | Compose File | Use Case |
|-------|------------|--------------|----------|
| **`vm`** (default) | VictoriaLogs + VictoriaMetrics + node_exporter | `compose-vm.yaml` | 10x less RAM, faster queries |
| **`grafana`** | Loki + Prometheus | `compose-grafana.yaml` | Grafana-native, familiar tools |

## Stack Selection

Configure your stack in `.env`:

```bash
# VictoriaMetrics ecosystem (default)
STACK=vm

# Grafana ecosystem (alternative)
STACK=grafana
```

Then run `make install` - it automatically deploys the correct stack.

## Components

### VM Stack (`STACK=vm`) - Default

| Service | Port | Description |
|---------|------|-------------|
| **Loki** | 3100 | Log aggregation for security events |
| **Prometheus** | 9090 | Metrics storage and scraping |

### VM Stack (`STACK=vm`)

| Service | Port | Description |
|---------|------|-------------|
| **VictoriaLogs** | 9428 | Log storage (fast full-text search) |
| **VictoriaLogs syslog** | 5514/UDP | Direct RFC3164/RFC5424 appliance log ingestion |
| **VictoriaMetrics** | 8428 | Metrics storage (10x less RAM than Prometheus) |
| **node_exporter** | 9100 | Host metrics (CPU, memory, disk, network) |

## Loki

Loki stores security events from Falcosidekick in a scalable, cost-efficient way.

### Features
- Label-based indexing (like Prometheus for logs)
- LogQL query language
- Native Grafana integration

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

## VictoriaLogs

VictoriaLogs is a high-performance log storage optimized for security events.

### Features
- 10x faster than Loki for full-text search
- Lower RAM usage
- VictoriaMetrics-compatible ecosystem
- Prometheus-like metrics endpoint

### VictoriaLogs Query Examples

```
# All Falco events
_stream:{job="falco"}

# Critical priority events  
_stream:{job="falco"} priority:Critical

# Events with specific rule
_stream:{job="falco"} AND rule:~".*shell.*"

# Events from specific host
_stream:{job="falco"} hostname:production-server-01

# UniFi syslog received in the last five minutes
_time:5m source:=unifi_syslog
```

### UniFi and appliance syslog

VictoriaLogs can ingest RFC3164/RFC5424 syslog directly. This is the log path;
SNMP exporters are separate polling tools for interface and device metrics.

Configure the SIB host `.env` with a specific LAN address rather than a wildcard:

```dotenv
SYSLOG_BIND_ADDR=192.168.1.25
SYSLOG_PORT=5514
SYSLOG_TIMEZONE=Europe/Zagreb
```

Then recreate only VictoriaLogs and configure the appliance to send UDP syslog
to that address and port. The receiver adds `source=unifi_syslog`, keeps the
sender address, and uses `source`, `hostname`, and `app_name` as stream fields.

Verify end to end rather than trusting an open socket:

```bash
docker compose --env-file .env -f storage/compose-vm.yaml up -d victorialogs
ss -lun | grep ':5514 '
curl -G -s http://192.168.1.25:9428/select/logsql/query \
  --data-urlencode 'query=_time:5m source:=unifi_syslog' \
  --data-urlencode 'limit=5'
```

UDP syslog has no delivery acknowledgement or encryption. Bind it only on a
trusted management address and use host firewall policy to limit senders.

The provisioned **UniFi Logs** Grafana dashboard
(`uid: sib-unifi-logs-victorialogs`) is dedicated to `source=unifi_syslog`. It
shows reporting devices, severity volume, per-device volume, a
disruption-focused log stream, and the complete searchable UniFi stream.
Device and message-regex variables apply across the dashboard. Repeated
`uplink-monitor.get_link_info` errors are counted separately and excluded from
the actionable-error and disruption panels so known firmware noise does not
bury real link transitions.

## Prometheus

Prometheus collects metrics from Falcosidekick and other SIB components.

### Metrics Available

- `falcosidekick_alerts_total`: Total alerts by priority
- `falcosidekick_outputs_total`: Output attempts by destination
- `falcosidekick_outputs_ok`: Successful outputs
- `falcosidekick_outputs_error`: Failed outputs

### PromQL Examples

```promql
# Alert rate by priority
rate(falcosidekick_alerts_total[5m])

# Total alerts in last hour
increase(falcosidekick_alerts_total[1h])

# Output success rate
falcosidekick_outputs_ok / falcosidekick_outputs_total
```

## VictoriaMetrics

VictoriaMetrics is a high-performance Prometheus-compatible metrics storage.

### Features
- 10x less RAM than Prometheus
- Faster queries
- Built-in metrics scraping (no separate scraper needed)
- Full PromQL compatibility

### Configuration
Edit `config/prometheus-vm.yml` for scrape targets.

## Remote Collectors

To accept data from remote hosts:

```bash
# Enable remote connections
make enable-remote

# This sets STORAGE_BIND=0.0.0.0 in .env and restarts storage
```

Then deploy collectors to remote hosts:
- **Grafana stack**: Use Alloy (`collectors/compose-grafana.yaml`)
- **VM stack**: Use vmagent + Vector (`collectors/compose-vm.yaml`)

## Manual Operations

```bash
# Start storage manually (based on STACK)
make start-storage-grafana   # or make start-storage-vm

# Stop storage
make stop-storage-grafana    # or make stop-storage-vm

# View logs
make logs-storage

# Restart
make restart-storage-grafana # or make restart-storage-vm
```
