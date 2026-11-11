# Grafana Stack

This directory contains Grafana for unified security visualization.

## Components

| Service | Port | Description |
|---------|------|-------------|
| **Grafana** | 3000 | Unified dashboard |

## Pre-configured Datasources

Datasources are provisioned based on the `STACK` setting in `.env`:

| Datasource | Stack | Description |
|------------|-------|-------------|
| **VictoriaLogs** | `vm` | Security events and logs |
| **VictoriaMetrics** | `vm` | Host and service metrics |
| **Loki** | `grafana` | Security events and logs |
| **Prometheus** | `grafana` | Metrics from Falcosidekick |

## Dashboards

SIB ships 11 dashboards — 5 for the Loki backend and 6 for VictoriaLogs (only the active `STACK`'s set is provisioned):

| Dashboard | Description |
|-----------|-------------|
| **Security Overview** | High-level security posture: event counts by severity, events over time, top rules, recent alerts |
| **Events Explorer** | Search and filter security events with query builder and AI analysis links (filter dropdowns in the Loki and AI-analysis variants) |
| **MITRE ATT&CK Coverage** | Detection events mapped to ATT&CK tactics with coverage matrix and technique breakdown |
| **Fleet Overview** | Multi-host monitoring: CPU, memory, disk, network, and log volume per host |
| **Risk Scores** | Host risk assessment based on event severity and frequency |
| **UniFi Logs** | UniFi syslog events and senders (VictoriaLogs only) |

> **Note:** The Loki Events Explorer (and the AI-analysis variants installed by `make install-analysis`) has hostname, priority and rule dropdowns. The base VictoriaLogs Events Explorer has none.

## Access

Open http://localhost:3000

Default credentials:
- Username: `admin`
- Password: Set in `.env` file

## Adding Custom Dashboards

1. Create dashboard in Grafana UI
2. Export as JSON (Share > Export > Save to file)
3. Place in `provisioning/dashboards/victorialogs/` (`vm` stack) or `provisioning/dashboards/loki/` (`grafana` stack)
4. Restart Grafana

## LogQL Examples

Query Falco events in Loki:

```logql
# All events
{job="falco"}

# Critical and error events
{job="falco"} | json | priority =~ "Critical|Error"

# Events from specific container
{job="falco"} | json | container_name = "my-app"

# Events matching rule
{job="falco"} | json | rule = "Terminal shell in container"

# Count events by priority
sum by (priority) (count_over_time({job="falco"} [1h]))
```
