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

SIB ships 10 dashboards — 5 for each storage backend (Loki and VictoriaLogs variants):

| Dashboard | Description |
|-----------|-------------|
| **Security Overview** | High-level security posture: event counts by severity, events over time, top rules, recent alerts |
| **Events Explorer** | Search and filter security events with query builder, severity filter dropdown, and AI analysis links |
| **MITRE ATT&CK Coverage** | Detection events mapped to ATT&CK tactics with coverage matrix and technique breakdown |
| **Fleet Overview** | Multi-host monitoring: CPU, memory, disk, network, and log volume per host |
| **Risk Scores** | Host risk assessment based on event severity and frequency |

> **Note:** The Events Explorer includes a **severity filter dropdown** to quickly filter events by priority level (Critical, Error, Warning, Notice).

## Access

Open http://localhost:3000

Default credentials:
- Username: `admin`
- Password: Set in `.env` file

## Adding Custom Dashboards

1. Create dashboard in Grafana UI
2. Export as JSON (Share > Export > Save to file)
3. Place in `provisioning/dashboards/json/`
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
