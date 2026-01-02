# Grafana Stack

This directory contains Grafana for unified security visualization.

## Components

| Service | Port | Description |
|---------|------|-------------|
| **Grafana** | 3000 | Unified dashboard |

## Pre-configured Datasources

| Datasource | Description |
|------------|-------------|
| **Loki** | Security events and logs |
| **Prometheus** | Metrics from Falcosidekick |

## Dashboards

### Security Overview
High-level security posture with:
- Total events count by severity
- Events over time
- Top triggered rules
- Recent alerts

### Events Explorer
Search and filter security events with:
- LogQL query builder
- Time range selection
- Field extraction
- Export capabilities

### Alert History
Historical view of all alerts with:
- Timeline visualization
- Rule-based filtering
- Container/host breakdown

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
