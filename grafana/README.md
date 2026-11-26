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
| **Prometheus** (points at VictoriaMetrics) | `vm` | Host and service metrics |
| **Loki** | `grafana` | Security events and logs |
| **Prometheus** | `grafana` | Metrics |

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

> **Note:** The Loki Events Explorer (also its AI-analysis variant, installed by `make install-analysis`) has hostname, priority and rule dropdowns. The VictoriaLogs Events Explorer has none; its AI-analysis variant has a severity filter.

## Alert Rules

`make install-grafana` also provisions alert rules into the **SIB** folder:
Falco liveness for every expected host (from the Ansible inventory), pipeline
health (Falco drops, Sidekick down or failing), detection spikes
(Critical/Error bursts, a host or rule far above its daily average),
resources (disk, memory, storage backends) and
[HIB](../docs/hib-integration.md) events. To get notified, set
`GRAFANA_ALERT_WEBHOOK_URL` or `GRAFANA_ALERT_TELEGRAM_BOT_TOKEN` and
`GRAFANA_ALERT_TELEGRAM_CHAT_ID` in `.env`, then run `make install-grafana`.
After editing the Ansible inventory, run `make refresh-alerts`. See
[docs/grafana-alerts.md](../docs/grafana-alerts.md).

## Access

Open http://localhost:3000. It listens on loopback only; change
`GRAFANA_BIND_ADDR` and `GRAFANA_PORT` in `.env`.

Default credentials:
- Username: `admin`
- Password: `GRAFANA_ADMIN_PASSWORD` in `.env` (applies when the database is first created)

## Adding Custom Dashboards

1. Create dashboard in Grafana UI
2. Export as JSON (Share > Export > Save to file)
3. Place in `provisioning/dashboards/victorialogs/` (`vm` stack) or `provisioning/dashboards/loki/` (`grafana` stack)
4. Run `make restart-grafana`

## LogQL Examples

Query Falco events in Loki:

```logql
# All events
{source="syscall"}

# Critical and error events
{source="syscall", priority=~"Critical|Error"}

# Events mentioning a container
{source="syscall"} |= "my-app"

# Events matching rule
{source="syscall", rule="Terminal shell in container"}

# Count events by priority
sum by (priority) (count_over_time({source="syscall"}[1h]))
```
