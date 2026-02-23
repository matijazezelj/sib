---
layout: default
title: VictoriaMetrics Stack - SIEM in a Box
---

# VictoriaMetrics Stack (Default)

VictoriaLogs and VictoriaMetrics are the default storage backends for SIB.

[← Back to Home](index.md)

---

## Why VictoriaMetrics?

**VictoriaLogs** (logs storage):
- Fast full‑text search over large volumes
- Better handling of high‑cardinality fields
- LogsQL support for analytics‑style queries
- Loki-compatible ingestion API

**VictoriaMetrics** (metrics storage):
- 10x lower memory usage than Prometheus
- Better compression (stores more in less disk space)
- Faster queries on large datasets
- PromQL-compatible (existing dashboards work)

---

## Quick Start

The VictoriaMetrics stack is the default. Just run:

```bash
cp .env.example .env
make install
```

This automatically:
- Installs VictoriaLogs + VictoriaMetrics + node_exporter
- Configures Falcosidekick to send alerts to VictoriaLogs
- Sets up Grafana with VictoriaLogs and VictoriaMetrics datasources
- Provisions VictoriaLogs-compatible dashboards

### Using the Grafana Stack Instead

If you prefer Loki + Prometheus:

```bash
# Edit .env
STACK=grafana

make install
```

---

## Architecture

When using `STACK=vm` (default):

```
┌─────────────────────────────────────────────────────────┐
│                      SIB Server                          │
│                                                          │
│  ┌─────────┐     ┌──────────────┐     ┌──────────────┐  │
│  │  Falco  │────▶│ Falcosidekick│────▶│ VictoriaLogs │  │
│  └─────────┘     └──────────────┘     │   (:9428)    │  │
│                                        └──────────────┘  │
│  ┌──────────────┐                      ┌──────────────┐  │
│  │node_exporter │─────────────────────▶│VictoriaMetrics│ │
│  │              │                      │   (:8428)    │  │
│  └──────────────┘                      └──────────────┘  │
│                                                          │
│  ┌──────────────┐                                        │
│  │   Grafana    │◀───── queries both ─────────────────   │
│  │   (:3000)    │                                        │
│  └──────────────┘                                        │
└─────────────────────────────────────────────────────────┘
```

---

## Access Points

| Service | URL | Description |
|---------|-----|-------------|
| **Grafana** | http://localhost:3000 | Dashboards and visualization |
| **VictoriaLogs** | http://localhost:9428 | Log storage and querying |
| **VictoriaMetrics** | http://localhost:8428 | Metrics storage and querying |
| **Sidekick API** | http://localhost:2801 | Alert routing UI |

---

## VictoriaLogs Dashboards

Dashboards are available under **SIEM in a Box**:
- **Events Explorer** — Security events with AI analysis links. Includes a **severity filter dropdown** to quickly filter by priority level (Critical, Error, Warning, Notice).
- **Security Overview** — High-level security posture
- **MITRE ATT&CK Coverage** — Detection mapping to ATT&CK
- **Fleet Overview** — Host metrics and log volumes
- **Risk Scores** — Host risk assessment

---

## LogsQL Query Examples

VictoriaLogs uses LogsQL for queries. Here are some examples:

```logsql
# All events
*

# Events by priority
priority:Critical

# Events from a specific host
hostname:web-server-01

# Events with a specific rule
rule:"Read sensitive file trusted after startup"

# Aggregate by rule
* | stats by (rule) count() as Count

# Time-based filtering
_time:1h AND priority:Error
```

---

## AI Analysis

AI Analysis works with VictoriaLogs out of the box:

```bash
make install-analysis
```

The Events Explorer dashboard includes AI analysis links that send events to the analysis API for contextual security insights.

If Grafana shows "Plugin not registered" (offline or restricted networks), install manually:

```bash
docker exec sib-grafana grafana cli plugins install victoriametrics-logs-datasource
docker restart sib-grafana
```

---

## Switching to Grafana Stack

To switch from VictoriaMetrics to the Grafana stack (Loki + Prometheus):

```bash
# Edit .env
STACK=grafana

# Reinstall
make uninstall
make install
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STACK` | `vm` | Storage stack: `vm` (VictoriaMetrics) or `grafana` (Loki + Prometheus) |
| `VICTORIALOGS_RETENTION_PERIOD` | `168h` | Log retention (7 days) |
| `VICTORIAMETRICS_RETENTION_PERIOD` | `15d` | Metrics retention |

---

[← Back to Home](index.md)
