# 🛡️ SIB - SIEM in a Box

**One-command security monitoring** for containers and Linux systems, powered by Falco and VictoriaMetrics.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

🌐 **Website**: [in-a-box-tools.tech](https://in-a-box-tools.tech)

SIB provides a complete, self-hosted security monitoring stack for detecting threats in real-time. Built on Falco's runtime security engine with VictoriaLogs for log storage and Grafana for visualization. Loki/Prometheus available as an alternative backend.

## 🌟 Features

- **Runtime Security**: Detect suspicious behavior in real-time using Falco's eBPF-based syscall monitoring
- **Alert Forwarding**: Falcosidekick routes alerts to 50+ destinations (Slack, PagerDuty, Loki, etc.)
- **Log Aggregation**: VictoriaLogs (default) or Loki stores security events with efficient querying
- **Pre-built Dashboards**: Grafana dashboards for security overview and event exploration
- **MITRE ATT&CK Coverage**: Dashboard mapping detections to the ATT&CK framework
- **Demo Mode**: Generate realistic security events to see dashboards in action
- **Sigma Rules**: Convert Sigma rules to Falco/LogsQL format
- **Threat Intel**: IP blocklists from Abuse.ch, Spamhaus, and more
- **Remote Collectors**: Ship logs from multiple hosts with Grafana Alloy
- **Fleet Management**: Dockerized Ansible for deploying agents across infrastructure (no local Ansible needed)
- **Smart Deployment**: Auto-detects Docker, installs from static binaries if needed — works on any Linux
- **AI-Powered Analysis** *(Beta)*: LLM-based alert analysis with attack vectors, MITRE ATT&CK mapping, and mitigation strategies
- **One Command Setup**: Get started with `make install`

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SIEM in a Box                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌─────────────────┐     ┌───────────────────────────┐ │
│  │    Falco     │     │  Falcosidekick  │     │      VictoriaLogs         │ │
│  │  (Detection) │────▶│   (Fan-out)     │────▶│      (Log Storage)        │ │
│  │  modern_ebpf │     │                 │     │                           │ │
│  └──────────────┘     └─────────────────┘     └───────────────────────────┘ │
│                                                            │                 │
│                                                            ▼                 │
│  ┌──────────────┐                             ┌───────────────────────────┐ │
│  │ node_exporter│                             │        Grafana            │ │
│  │   (Metrics)  │────────────────────────────▶│   • Security Overview     │ │
│  └──────────────┘                             │   • Events Explorer       │ │
│         │                                     │   • MITRE ATT&CK          │ │
│         ▼                                     │   • Fleet Overview        │ │
│  ┌──────────────┐                             └───────────────────────────┘ │
│  │VictoriaMetrics│                                         ▲                │
│  │   (Metrics)  │──────────────────────────────────────────┘                │
│  └──────────────┘                                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

- **Docker CE** 20.10+ from [docker.com](https://docs.docker.com/engine/install/) with Docker Compose v2+, or **Podman** 4.0+ in rootful mode with podman-compose
  - ⚠️ Podman must run as root (rootful mode) — Falco requires kernel access to monitor syscalls
- **Linux kernel** 5.8+ (for modern_ebpf driver)
- **4GB+ RAM** recommended

> ⚠️ **Note**: Docker Desktop is not supported. Install Docker CE (Community Edition) directly from docker.com or use Podman.

### Hardware Requirements

| Deployment | CPU | RAM | Disk | Notes |
|------------|-----|-----|------|-------|
| **SIB Server** (single host) | 2 cores | 4GB | 20GB | Runs Falco + full stack |
| **SIB Server** (with fleet) | 4 cores | 8GB | 50GB+ | More storage for logs from multiple hosts |
| **Fleet Agent** | 1 core | 512MB | 1GB | Falco + Alloy only |

> 💡 **Not a network sniffer!** SIB uses Falco's eBPF-based syscall monitoring — it watches what programs do at the kernel level, not network packets. No mirror ports, TAPs, or bridge interfaces needed. Just install on any Linux host and it sees everything that host does.

```bash
# Docker CE
docker --version          # Should be 20.10+
docker compose version    # Should be v2+

# Or Podman
podman --version          # Should be 4.0+
podman-compose --version  # Alternative to docker compose

# Kernel (both)
uname -r                  # Should be 5.8+ for eBPF
```

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/matijazezelj/sib.git
cd sib

# Configure environment
cp .env.example .env
# Edit .env if needed (defaults work for local testing)

# Install everything
make install

# Verify it's working
./scripts/test-pipeline.sh
```

### Storage Backend

SIB supports two monitoring stacks. Choose based on your preferences:

| Stack | Components | Best For |
|-------|------------|----------|
| **`vm`** (default) | VictoriaLogs + VictoriaMetrics + node_exporter | 10x less RAM, faster queries, recommended |
| **`grafana`** | Loki + Prometheus + Alloy | Grafana ecosystem, native integration |

```bash
# In .env - choose your stack (one simple setting)
STACK=vm         # Default - VictoriaMetrics ecosystem (recommended)
STACK=grafana    # Alternative - Grafana ecosystem (Loki + Prometheus)
```

The `make install` command automatically:
- Deploys the correct storage stack
- Configures Falcosidekick to send alerts to the chosen backend
- Sets up Grafana with the appropriate datasources and dashboards
- For VM stack: includes node_exporter for host metrics

## 🌐 Access Points

| Service | URL | Stack |
|---------|-----|-------|
| **Grafana** | http://localhost:3000 | Both |
| **Sidekick API** | http://localhost:2801 | Both |
| **Loki** | http://localhost:3100 | `grafana` only |
| **Prometheus** | http://localhost:9090 | `grafana` only |
| **VictoriaLogs** | http://localhost:9428 | `vm` only |
| **VictoriaMetrics** | http://localhost:8428 | `vm` only |

Default Grafana credentials: `admin` / `admin`

> **Note:** Only the services for your selected `STACK` will be running.

> ⚠️ **Fleet Security Note:** Sidekick API (2801) is exposed externally so fleet hosts can send events. Use firewall rules to restrict access to your fleet nodes only:
> ```bash
> # UFW example: allow only from fleet subnet
> ufw allow from 192.168.1.0/24 to any port 2801
> ```

## 🎯 What Gets Detected?

| Category | Examples |
|----------|----------|
| **Credential Access** | Reading /etc/shadow, SSH key access |
| **Container Security** | Shells in containers, privileged operations |
| **File Integrity** | Writes to /etc, sensitive config changes |
| **Process Anomalies** | Unexpected binaries, shell spawning |
| **Persistence** | Cron modifications, systemd changes |
| **Cryptomining** | Mining processes, pool connections |

## 🔍 Comparison (Wazuh, Splunk, Elastic)

| Tool | Pros | Cons | Best for |
|------|------|------|----------|
| **SIB** | One-command setup, Falco runtime detection, curated Grafana dashboards, self-hosted | Not a full log SIEM platform, Linux-only detection | Homelabs, startups, lean SecOps teams | 
| **Wazuh** | Strong host-based SIEM, broad OS support, built-in agents | Heavier setup, more tuning required, multi-component stack | Organizations needing HIDS + log SIEM | 
| **Splunk** | Powerful search/analytics, enterprise-grade scale | Expensive at scale, complex operations | Large enterprises with budget and dedicated SIEM team | 
| **Elastic SIEM** | Flexible, open-source core, great search | Requires careful sizing/tuning, operational overhead | Teams already using Elastic Stack | 

**Takeaway:** SIB prioritizes **speed of deployment** and **actionable runtime detection**. For large-scale log analytics and complex compliance reporting, Wazuh/Splunk/Elastic may be a better fit.

## 📊 Dashboards

### Security Overview
- Total events, Critical/Error/Warning/Notice counts
- Events over time by priority
- Events by rule (pie chart)
- **🚨 Critical Events panel** - Dedicated view for high-priority events
- Recent security events log

### Events Explorer
- Query help with LogQL examples
- Event volume by rule
- Filterable log view with priority and rule filters

### MITRE ATT&CK Coverage
- Detection events mapped to ATT&CK tactics
- Visual matrix showing coverage across 12 tactics
- Events over time by tactic
- Technique breakdown and priority distribution
- **Hostname filter** to focus on specific hosts

### Fleet Overview
- Active hosts with collectors
- CPU, memory, disk usage per host
- Network traffic graphs
- Log volume by host
- **Hostname selector** to filter all panels by host

## 🛠️ Commands

```bash
# Installation (reads STACK from .env: vm or grafana)
make install              # Install all stacks (auto-configures based on STACK)
make uninstall            # Remove everything

# Storage (Manual override)
make install-storage-vm              # Install VictoriaLogs + VictoriaMetrics (default)
make install-storage-grafana         # Install Loki + Prometheus (alternative)

# Management
make start                # Start all services
make stop                 # Stop all services
make restart              # Restart all services
make status               # Show service status
make health               # Quick health check
make doctor               # Diagnose common issues

# Logs
make logs                 # Tail all logs
make logs-falco           # Tail Falco logs
make logs-sidekick        # Tail Falcosidekick logs
make logs-storage         # Tail storage logs (auto-detects stack)
make logs-grafana         # Tail Grafana logs

# Demo & Testing
make demo                 # Run comprehensive security demo (~30 events)
make demo-quick           # Run quick demo (1s delay)
make test-alert           # Generate a test security alert
./scripts/test-pipeline.sh  # Run full pipeline test

# Threat Intel & Sigma
make update-threatintel   # Download threat intel feeds
make convert-sigma        # Convert Sigma rules to Falco/LogsQL

# AI Analysis (Optional)
make install-analysis     # Install AI analysis API (integrated with Grafana)
make logs-analysis        # View analysis API logs

# Utilities
make open                 # Open Grafana in browser
make info                 # Show all endpoints
```

## 📚 Documentation

- [docs/installation.md](docs/installation.md)
- [docs/minimal-install.md](docs/minimal-install.md)
- [docs/quickstart.md](docs/quickstart.md)
- [docs/security-hardening.md](docs/security-hardening.md)
- [docs/troubleshooting.md](docs/troubleshooting.md)
- [docs/faq.md](docs/faq.md)
- [ROADMAP.md](ROADMAP.md)
- Kubernetes deployment: [sib-k8s](https://github.com/matijazezelj/sib-k8s)
- VictoriaLogs backend: [docs/victorialogs.md](docs/victorialogs.md)

## 📁 Project Structure

```
sib/
├── Makefile                    # Main entry point
├── .env.example                # Environment template (STACK config)
├── scripts/
│   └── test-pipeline.sh        # Pipeline verification script
├── detection/                  # Falco stack
│   ├── compose.yaml
│   └── config/
│       ├── falco.yaml          # Falco config (modern_ebpf)
│       └── rules/
│           └── custom_rules.yaml  # Custom detection rules
├── alerting/                   # Falcosidekick
│   ├── compose.yaml
│   └── config/
│       ├── config.yaml.template  # Sidekick config template
│       └── config.yaml         # Generated from template on install
├── storage/                    # Log storage backends
│   ├── compose-vm.yaml         # VictoriaLogs + VictoriaMetrics (default)
│   ├── compose-grafana.yaml    # Loki + Prometheus (alternative)
│   └── config/
│       ├── loki-config.yml
│       └── prometheus.yml
├── grafana/                    # Dashboards
│   ├── compose.yaml
│   └── provisioning/
│       ├── datasources/
│       │   └── templates/      # Datasource templates
│       └── dashboards/
│           ├── loki/           # Loki-specific dashboards
│           └── victorialogs/   # VictoriaLogs-specific dashboards
├── ansible/                    # Fleet management (Dockerized)
│   ├── inventory/
│   │   ├── hosts.yml.example   # Host inventory template
│   │   └── group_vars/all.yml  # Deployment settings
│   ├── roles/
│   │   ├── falco/              # Falco deployment role
│   │   └── alloy/              # Alloy deployment role
│   └── playbooks/
├── collectors/                 # Remote host collectors
│   ├── compose-vm.yaml         # VictoriaMetrics stack collectors
│   ├── compose-grafana.yaml    # Grafana stack collectors
│   ├── config/
│   │   └── config.alloy        # Alloy configuration
│   └── scripts/
│       └── deploy.sh           # Remote deployment script
└── examples/
    └── rules/                  # Example custom rules
```

## 🔧 Configuration

### Custom Rules

Add detection rules in `detection/config/rules/custom_rules.yaml`:

```yaml
- rule: Detect Cryptocurrency Mining
  desc: Detect cryptocurrency mining processes
  condition: >
    spawned_process and 
    proc.name in (xmrig, minerd, cpuminer)
  output: "Crypto miner detected (user=%user.name cmd=%proc.cmdline)"
  priority: CRITICAL
  tags: [cryptomining, mitre_impact]
```

### Alert Outputs

Configure additional outputs in `alerting/config/config.yaml`:

```yaml
slack:
  webhookurl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
  minimumpriority: "warning"

pagerduty:
  routingkey: "your-routing-key"
  minimumpriority: "critical"
```

### Environment Variables

Key variables in `.env`:

```bash
# Auto-generated on install (leave as CHANGE_ME to regenerate)
GRAFANA_ADMIN_PASSWORD=<auto-generated>
GRAFANA_PORT=3000
LOKI_PORT=3100
PROMETHEUS_PORT=9090
SIDEKICK_PORT=2801
```

## 🔒 Security Notes

- Internal services (Loki, Prometheus) bind to localhost only
- Grafana and Sidekick API are externally accessible (for fleet support)
- Falco requires privileged access for syscall monitoring
- Change default Grafana password in production
- **mTLS available** for encrypted fleet communication

### Hardening Checklist

- Restrict external ports to trusted IPs
- Put Grafana behind TLS + auth (reverse proxy)
- Rotate default credentials before production use
- Set retention limits for Loki/Prometheus
- Back up Grafana and Loki volumes
- Enable mTLS for production fleet deployments (`make generate-certs`)

See [docs/security-hardening.md](docs/security-hardening.md) for full guidance.

## 🤖 AI-Powered Alert Analysis (Beta)

SIB includes an optional AI-powered analysis feature that uses LLMs to analyze security alerts and provide:

- **Attack Vector Identification** - What technique is being used
- **MITRE ATT&CK Mapping** - Tactic and technique IDs
- **Risk Assessment** - Severity, confidence, and potential impact
- **Mitigation Strategies** - Immediate, short-term, and long-term actions
- **False Positive Assessment** - Likelihood and common legitimate causes

### Privacy-First Design

Sensitive data is **obfuscated before sending to the LLM**:
- IPs → `[INTERNAL-IP-1]`, `[EXTERNAL-IP-1]`
- Usernames → `[USER-1]`
- Hostnames → `[HOST-1]`
- Container IDs → `[CONTAINER-1]`
- Secrets/credentials → `[REDACTED]`

### Quick Start

```bash
# Install the Analysis API service
make install-analysis
```

You'll be prompted for your server's IP/hostname. Then open Grafana and use the Events Explorer dashboard to analyze any event with AI.

### Grafana Integration

Once installed, the **Events Explorer** dashboard includes a table where you can click any event to analyze it with AI:

1. Open **Events Explorer** dashboard in Grafana
2. Scroll to the **"🤖 Select Event to Analyze"** table
3. Click on any log line to see the **"🤖 Analyze with AI"** link
4. View the analysis with attack vectors, MITRE mapping, and mitigations

The analysis page shows:
- **Original Alert** - The raw event
- **What Was Sent to AI** - The obfuscated version (your sensitive data stays private)
- **Attack Vector & MITRE ATT&CK** mapping
- **Risk Assessment** with severity and confidence
- **Mitigations** (immediate, short-term, long-term)
- **False Positive Assessment**

### LLM Providers

| Provider | Privacy | Setup |
|----------|---------|-------|
| **Ollama** (local) | ✅ Data stays on-premises | `ollama pull llama3.1:8b` |
| OpenAI | ⚠️ Data sent to API (obfuscated) | Set `OPENAI_API_KEY` |
| Anthropic | ⚠️ Data sent to API (obfuscated) | Set `ANTHROPIC_API_KEY` |

Configure in `analysis/config.yaml`. See [analysis/README.md](analysis/README.md) for full documentation.

## 📡 Remote Collectors (Alloy)

SIB uses **Grafana Alloy** as a unified telemetry collector for remote hosts. Deploy lightweight collectors to ship logs and metrics to your central SIB server.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Hub and Spoke Model                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │   Host A     │    │   Host B     │    │   Host C     │                   │
│  │   (Alloy)    │    │   (Alloy)    │    │   (Alloy)    │                   │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                   │
│         │                   │                   │                            │
│         │     Logs (Loki Push)  +  Metrics (Remote Write)                   │
│         │                   │                   │                            │
│         └───────────────────┼───────────────────┘                            │
│                             ▼                                                │
│                   ┌──────────────────┐                                       │
│                   │    SIB Server    │                                       │
│                   │  ┌────────────┐  │                                       │
│                   │  │    Loki    │  │  ◀── Logs with host labels           │
│                   │  └────────────┘  │                                       │
│                   │  ┌────────────┐  │                                       │
│                   │  │ Prometheus │  │  ◀── Node metrics                    │
│                   │  └────────────┘  │                                       │
│                   │  ┌────────────┐  │                                       │
│                   │  │  Grafana   │  │  ◀── Fleet Overview dashboard        │
│                   │  └────────────┘  │                                       │
│                   └──────────────────┘                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Enable Remote Mode

On the SIB server, enable external access for collectors:

```bash
make enable-remote
```

This exposes Loki (3100) and Prometheus (9090) externally. Ensure your firewall is configured appropriately.

### Deploy Collector to Remote Host

```bash
# Using the Makefile (recommended)
make deploy-collector HOST=user@remote-host

# Or using the deploy script directly
./collectors/scripts/deploy.sh user@192.168.1.50 192.168.1.163
```

The deploy script will:
1. Copy Alloy configuration to the remote host
2. Configure the SIB server address
3. Start Alloy via Docker Compose
4. Verify the deployment

### What Gets Collected

| Type | Sources | Labels |
|------|---------|--------|
| **System Logs** | `/var/log/syslog`, `/var/log/messages` | `job="syslog"` |
| **Auth Logs** | `/var/log/auth.log`, `/var/log/secure` | `job="auth"` |
| **Kernel Logs** | `/var/log/kern.log` | `job="kernel"` |
| **Journal** | systemd journal | `job="journal"` |
| **Docker Logs** | All containers | `job="docker"`, `container=...` |
| **Node Metrics** | CPU, memory, disk, network | `job="node"`, `collector="alloy"` |

All data is tagged with:
- `host` - hostname of the remote machine
- `collector="alloy"` - identifies data from Alloy collectors

### Manual Deployment

If you prefer manual deployment:

```bash
# On the remote host
mkdir -p ~/sib-collector/config

# Copy and edit the config
scp collectors/config/config.alloy user@remote:~/sib-collector/config/
# Edit config.alloy - replace SIB_SERVER_IP with your SIB server IP

# Copy compose file (use compose-vm.yaml or compose-grafana.yaml based on your stack)
scp collectors/compose-vm.yaml user@remote:~/sib-collector/compose.yaml

# Start the collector
ssh user@remote "cd ~/sib-collector && HOSTNAME=\$(hostname) docker compose up -d"
```

### Verify Collector is Working

```bash
# Check Alloy logs on remote host
ssh user@remote "docker logs sib-alloy --tail 20"

# Query VictoriaLogs for collector data (default stack)
curl -s "http://localhost:9428/select/logsql/query?query=*" | head

# Check metrics in VictoriaMetrics (default stack)
curl -s 'http://localhost:8428/api/v1/query?query=node_uname_info'

# Or for Grafana stack: Loki at :3100, Prometheus at :9090
```

### Fleet Overview Dashboard

The **Fleet Overview** dashboard in Grafana shows:
- Number of active hosts with collectors
- CPU, memory, disk utilization per host
- Network traffic graphs
- Log volume by host

## 🚀 Fleet Management with Ansible

For managing multiple hosts at scale, SIB includes a Dockerized Ansible setup. **No local Ansible installation required.**

### Deployment Strategy

SIB supports both **native packages** (default) and **Docker containers**:

| Strategy | Description |
|----------|-------------|
| `native` (default) | Falco from repo + Alloy as systemd service. **Recommended for best visibility.** |
| `docker` | Run agents as containers |
| `auto` | Use Docker if available, otherwise native |

**Why native is recommended:** Native deployment sees all host processes, while Docker-based Falco may miss events from processes outside its container namespace.

> ⚠️ **LXC Limitation:** Falco cannot run in LXC containers due to kernel access restrictions. Use VMs or run Falco on the LXC host itself.

### Quick Start

```bash
# Configure your hosts
cp ansible/inventory/hosts.yml.example ansible/inventory/hosts.yml
vim ansible/inventory/hosts.yml  # Add your servers

# Test connectivity
make fleet-ping

# Deploy to all hosts
make deploy-fleet

# Or target specific hosts
make deploy-fleet LIMIT=webserver
```

### Fleet Commands

| Command | Description |
|---------|-------------|
| `make deploy-fleet` | Deploy Falco + Alloy to all fleet hosts |
| `make update-rules` | Push detection rules to fleet |
| `make fleet-health` | Check health of all agents |
| `make fleet-docker-check` | Check/install Docker on fleet hosts |
| `make fleet-ping` | Test SSH connectivity |
| `make fleet-shell` | Open shell in Ansible container |
| `make remove-fleet` | Remove agents from fleet |

See [ansible/README.md](ansible/README.md) for detailed configuration options.

## 🎭 Demo Mode

Generate realistic security events **locally on your SIB server** — no fleet setup required! Perfect for first-time users, demonstrations, or testing detection capabilities.

```bash
# Run comprehensive demo (~30 events across 9 MITRE ATT&CK categories)
make demo

# Quick demo with 1-second delays
make demo-quick
```

The demo spins up a temporary container and triggers various Falco rules. Watch your Grafana dashboards light up in real-time at http://localhost:3000.

### Demo Coverage

The demo script generates events across these MITRE ATT&CK categories:

| Tactic | Events Generated |
|--------|------------------|
| **Credential Access** | Shadow file access, /etc/passwd reads |
| **Execution** | Shell spawning, script execution |
| **Persistence** | Cron job creation, systemd manipulation |
| **Defense Evasion** | Log clearing, history deletion |
| **Discovery** | System enumeration, network scanning |
| **Impact** | Crypto miner detection |
| **Container Escape** | Docker socket access, namespace breakout |
| **Lateral Movement** | SSH key access, authorized_keys reads |
| **File Integrity** | /etc/ file modifications |

Each event triggers corresponding Falco rules and flows through to Grafana in real-time.

## 📐 Sigma Rules Integration

[Sigma](https://sigmahq.io/) is the universal language for security detection rules. SIB includes a converter to translate Sigma rules to Falco rules and LogsQL alerts (VictoriaLogs).

```bash
# Convert all Sigma rules in sigma/rules/
make convert-sigma

# Convert to LogsQL for VictoriaLogs (default)
./sigma/sigma2sib.py sigma/rules/ -o logsql

# Convert a specific rule
./sigma/sigma2sib.py sigma/rules/crypto_mining.yml
```

### Included Sample Rules

| Rule | Description | MITRE Tactic |
|------|-------------|--------------|
| `crypto_mining.yml` | Detects cryptocurrency miners | Impact (T1496) |
| `shadow_access.yml` | Password file access | Credential Access (T1003) |
| `ssh_keys.yml` | SSH private key access | Credential Access (T1552) |
| `reverse_shell.yml` | Reverse shell patterns | Execution (T1059) |
| `container_escape.yml` | Container breakout attempts | Privilege Escalation (T1611) |

### Adding More Sigma Rules

1. Download rules from the [Sigma community rules repo](https://github.com/SigmaHQ/sigma)
2. Place `.yml` files in `sigma/rules/`
3. Run `make convert-sigma`
4. Copy generated Falco rules to `detection/config/rules/custom_rules.yaml`

## 🎯 MITRE ATT&CK Coverage

SIB includes a MITRE ATT&CK dashboard that maps all detections to the ATT&CK framework, providing visibility into your security coverage.

### Dashboard Features

- **Tactic Coverage**: 12 stat panels showing detection counts for each ATT&CK tactic
- **Timeline View**: Events over time grouped by tactic
- **Technique Breakdown**: Table showing most-triggered techniques
- **Priority Distribution**: Pie chart of event severities

### Covered Tactics

The dashboard tracks events across all ATT&CK tactics:

```
┌──────────────┬───────────────┬────────────────┬───────────────────┐
│ Initial      │ Execution     │ Persistence    │ Privilege         │
│ Access       │               │                │ Escalation        │
├──────────────┼───────────────┼────────────────┼───────────────────┤
│ Defense      │ Credential    │ Discovery      │ Lateral           │
│ Evasion      │ Access        │                │ Movement          │
├──────────────┼───────────────┼────────────────┼───────────────────┤
│ Collection   │ Command &     │ Exfiltration   │ Impact            │
│              │ Control       │                │                   │
└──────────────┴───────────────┴────────────────┴───────────────────┘
```

### Viewing the Dashboard

1. Open Grafana at http://localhost:3000
2. Navigate to **Dashboards** → **MITRE ATT&CK Coverage**
3. Run `make demo` to generate events across multiple tactics

## 🕵️ Threat Intelligence

SIB can enrich detections with threat intelligence from public IP blocklists.

```bash
# Download/update threat intel feeds
make update-threatintel
```

### Included Feeds

| Source | Feed Type | URL |
|--------|-----------|-----|
| **Feodo Tracker** | C&C IPs | abuse.ch |
| **SSL Blacklist** | SSL abuse IPs | abuse.ch |
| **Emerging Threats** | Compromised IPs | rules.emergingthreats.net |
| **Spamhaus DROP** | Spam/DDoS | spamhaus.org |
| **Blocklist.de** | Attack IPs | blocklist.de |
| **CINSscore** | Bad reputation | cinsscore.com |

### Generated Files

After running `make update-threatintel`:

```
threatintel/
├── feeds/                      # Individual feed downloads
│   ├── feodo_ipblocklist.txt
│   ├── sslbl_aggressive.txt
│   ├── emerging_threats.txt
│   ├── spamhaus_drop.txt
│   ├── blocklist_de_ssh.txt
│   ├── blocklist_de_all.txt
│   └── cinsscore.txt
├── combined_blocklist.txt      # Unified blocklist
├── falco_threatintel_rules.yaml # Generated Falco rules
└── lookup-ip.sh                # IP lookup utility
```

### Using Threat Intel

```bash
# Look up an IP against all feeds
./threatintel/lookup-ip.sh 1.2.3.4

# Add generated rules to Falco
cat threatintel/falco_threatintel_rules.yaml >> detection/config/rules/custom_rules.yaml
make restart
```

### Automating Updates

Add to crontab to update feeds daily:

```bash
# Update threat intel every day at 2 AM
0 2 * * * cd /path/to/sib && make update-threatintel
```

## 🐛 Troubleshooting

### Falco won't start

```bash
# Check kernel version (need 5.8+ for modern_ebpf)
uname -r

# Check Falco logs
docker logs sib-falco

# Verify privileged mode is working
docker run --rm --privileged alpine echo "OK"
```

### No events in Grafana

```bash
# Run the pipeline test
./scripts/test-pipeline.sh

# Check Falcosidekick is receiving events
docker logs sib-sidekick --tail 20

# Query Loki directly
curl -s "http://localhost:3100/loki/api/v1/query?query={source=\"syscall\"}" | jq .
```

## 📜 License

Apache 2.0 License - See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [Falco](https://falco.org/) - Cloud native runtime security
- [Falcosidekick](https://github.com/falcosecurity/falcosidekick) - Alert routing
- [Grafana](https://grafana.com/) - Observability platform
- [Loki](https://grafana.com/oss/loki/) - Log aggregation
- [Prometheus](https://prometheus.io/) - Metrics monitoring
- [VictoriaMetrics](https://victoriametrics.com/) - Fast metrics & logs storage (thanks [@valyala](https://github.com/valyala) for the suggestion!)
