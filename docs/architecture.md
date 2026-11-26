---
layout: default
title: Architecture - SIEM in a Box
---

# Architecture

How SIB is put together, what each component does, where the files live, and how it compares with other SIEMs.

[← Back to Home](index.md)

---

## Components

| Component | Role |
|-----------|------|
| **Falco** | Runtime detection. Watches system calls through eBPF (`modern_ebpf` on kernel 5.8+) and matches them against rules. |
| **Falcosidekick** | Receives Falco events and fans them out: to log storage, and to any outputs you configure (Slack, PagerDuty, webhooks and the rest of Falcosidekick's 50+ outputs). |
| **VictoriaLogs** | Stores security events and collected logs (`vm` stack, the default). Queried with LogsQL. |
| **VictoriaMetrics** | Stores host metrics (`vm` stack). PromQL-compatible. |
| **node_exporter** | Host metrics for the SIB server (`vm` stack), scraped by VictoriaMetrics. |
| **Loki + Prometheus** | The alternative storage pair (`grafana` stack), in place of VictoriaLogs and VictoriaMetrics. |
| **Grafana** | Dashboards and alert rules. See [Dashboards](dashboards.md) and [Grafana Alerts](grafana-alerts.md). |
| **Analysis API** *(optional)* | LLM-based analysis of single alerts, linked from the Events Explorer. See [AI Analysis](ai-analysis.md). |

Everything runs in containers on a shared Docker network (`sib-network`). Falco needs privileged access to the host kernel; the other services do not.

### Not a network sniffer

SIB does not inspect network packets. Falco watches what programs do at the kernel level (process starts, file opens, connections). You don't need mirror ports, TAPs or bridge interfaces. Install it on a Linux host and it sees what that host does. To cover more hosts, run a Falco sensor on each one ([Fleet Management](fleet.md)).

## Data flow

```
┌───────────────────────────────────────────────────────────────────┐
│                         SIB server                                │
│                                                                   │
│  ┌──────────────┐    ┌───────────────┐    ┌───────────────────┐   │
│  │    Falco     │───▶│ Falcosidekick │───▶│   VictoriaLogs    │   │
│  │ (modern_ebpf)│    │   (fan-out)   │    │  (events, logs)   │   │
│  └──────────────┘    └───────┬───────┘    └─────────┬─────────┘   │
│                              │                      │             │
│                              ▼                      ▼             │
│                     Slack, PagerDuty,     ┌───────────────────┐   │
│                     webhook, ...          │      Grafana      │   │
│                                           │ dashboards, alerts│   │
│  ┌──────────────┐    ┌───────────────┐    └───────────────────┘   │
│  │ node_exporter│───▶│VictoriaMetrics│──────────────▲             │
│  └──────────────┘    │   (metrics)   │                            │
│                      └───────────────┘                            │
└───────────────────────────────────────────────────────────────────┘
        ▲                                    ▲
        │ Falco events (mTLS)                │ logs + metrics
   remote Falco sensors                 remote collectors
```

With `STACK=grafana`, Loki takes the place of VictoriaLogs and Prometheus the place of VictoriaMetrics.

### Remote hosts

Remote hosts send data to the central server in two ways (details in [Fleet Management](fleet.md)):

- **Falco sensors** send events to Falcosidekick on port 2801, preferably over mTLS with one client certificate per sensor.
- **Collectors** ship logs and metrics straight to storage: Vector and vmagent on the `vm` stack, Grafana Alloy on the `grafana` stack. Run `make enable-remote` on the server first so storage accepts remote connections.

```
   ┌──────────┐   ┌──────────┐   ┌──────────┐
   │  web-01  │   │  web-02  │   │  db-01   │
   │collectors│   │collectors│   │collectors│
   └────┬─────┘   └────┬─────┘   └────┬─────┘
        └──── logs + metrics (remote write) ───┐
                                               ▼
                                  ┌────────────────────────┐
                                  │       SIB server       │
                                  │ VictoriaLogs  (or Loki)│
                                  │ VictoriaMetrics (or    │
                                  │   Prometheus)          │
                                  │ Grafana: Fleet Overview│
                                  └────────────────────────┘
```

## Storage stacks

Choose the stack with `STACK` in `.env`. `make install` deploys the matching storage, points Falcosidekick at it and provisions the matching Grafana datasources and dashboards.

| `STACK` | Components | Notes |
|---------|------------|-------|
| `vm` (default) | VictoriaLogs + VictoriaMetrics + node_exporter | Lighter on memory; see [VictoriaMetrics Stack](victorialogs.md) |
| `grafana` | Loki + Prometheus | Grafana ecosystem; remote hosts use Alloy |

## Project structure

```
sib/
├── Makefile                 # Main entry point (make help)
├── .env.example             # Configuration template
├── detection/               # Falco
│   ├── compose.yaml
│   └── config/
│       ├── falco.yaml.template   # falco.yaml is generated from this
│       └── rules/                # Rule packs (see detection.md)
├── alerting/                # Falcosidekick
│   ├── compose.yaml
│   └── config/
│       ├── config.yaml                   # Generated from .env, do not edit
│       └── custom-outputs.yaml.example   # Extra outputs you manage
├── storage/                 # Log and metric storage
│   ├── compose-vm.yaml      # VictoriaLogs + VictoriaMetrics (default)
│   ├── compose-grafana.yaml # Loki + Prometheus
│   └── config/
├── grafana/                 # Grafana and provisioning
│   └── provisioning/
│       ├── datasources/
│       └── dashboards/      # loki/, victorialogs/, templates/
├── analysis/                # Optional AI Analysis API
├── collectors/              # Remote log and metric collectors
├── ansible/                 # Dockerized Ansible for fleet deployment
├── certs/                   # mTLS certificates (generated)
├── secrets/                 # Optional secret files for the Analysis API
├── sigma/                   # Sigma rules and the sigma2sib converter
├── threatintel/             # Threat intel feed downloader and lookup
├── scripts/                 # Config generators, demo and test scripts
├── examples/                # Example rules
└── docs/                    # This documentation
```

## Comparison with other SIEMs

| Tool | Strengths | Trade-offs | Good fit for |
|------|-----------|------------|--------------|
| **SIB** | One-command setup, Falco runtime detection, ready-made Grafana dashboards, self-hosted | Not a full log SIEM; detection is Linux-only | Homelabs, startups, small security teams |
| **Wazuh** | Host-based SIEM, broad OS support, built-in agents | Heavier setup, more tuning, several components | Teams that need HIDS plus a log SIEM |
| **Splunk** | Powerful search and analytics, enterprise scale | Expensive at scale, complex to operate | Large enterprises with a dedicated SIEM team |
| **Elastic SIEM** | Flexible, open-source core, strong search | Needs careful sizing and tuning | Teams already running the Elastic Stack |

SIB puts speed of deployment and runtime detection first. For large-scale log analytics and compliance reporting, Wazuh, Splunk or Elastic may fit better.

---

[← Back to Home](index.md)
