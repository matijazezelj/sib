---
layout: default
title: Fleet Management - SIEM in a Box
---

# Fleet Management

Deploy and manage SIB security agents across your infrastructure.

[← Back to Home](index.md)

---

## Overview

SIB includes Ansible-based fleet management to deploy security agents across multiple hosts. **No local Ansible installation required** — it runs in Docker.

```
┌─────────────────────────────────────────────────────────┐
│                    SIB Central Server                    │
│  ┌─────────┐ ┌──────────────┐ ┌────────────────┐        │
│  │ Grafana │ │ VictoriaLogs │ │ VictoriaMetrics│        │
│  └─────────┘ └──────────────┘ └────────────────┘        │
└─────────────────────────▲──────────────▲────────────────┘
                          │              │
     ┌────────────────────┼──────────────┼────────────────┐
     │   Host A           │   Host B     │   Host C       │
     │ Falco + Alloy ─────┴──────────────┴─── ...         │
     └────────────────────────────────────────────────────┘
```

Each fleet host gets:
- **Falco** — Runtime security detection
- **Alloy** — Ships logs and metrics to central SIB

All events from all hosts appear in your central Grafana dashboards.

---

## Deployment Strategies

SIB supports both **native packages** (default) and **Docker containers**:

| Strategy | Description |
|----------|-------------|
| `native` (default) | Falco from repo + Alloy as systemd service. **Recommended for best visibility.** |
| `docker` | Run agents as containers |
| `auto` | Use Docker if available, otherwise native |

**Why native is recommended:** Native deployment sees all host processes, while Docker-based Falco may miss events from processes outside its container namespace.

> ⚠️ **LXC Limitation:** Falco cannot run in LXC containers due to kernel access restrictions. Use VMs or run Falco on the LXC host itself.

---

## Quick Start

### 1. Configure Inventory

```bash
# Copy example inventory
cp ansible/inventory/hosts.yml.example ansible/inventory/hosts.yml

# Edit with your hosts
vim ansible/inventory/hosts.yml
```

Example inventory:
```yaml
all:
  vars:
    sib_server: 192.168.1.100  # Your SIB server IP
    ansible_user: ubuntu
    ansible_ssh_private_key_file: ~/.ssh/id_rsa
    
  children:
    fleet:
      hosts:
        webserver:
          ansible_host: 192.168.1.10
        database:
          ansible_host: 192.168.1.11
        appserver:
          ansible_host: 192.168.1.12
```

### 2. Test Connectivity

```bash
make fleet-ping
```

### 3. Deploy to Fleet

```bash
# Deploy to all hosts (native by default)
make deploy-fleet

# Or target specific hosts
make deploy-fleet LIMIT=webserver

# Force Docker deployment instead of native
make deploy-fleet ARGS="-e deployment_strategy=docker"
```

---

## Fleet Commands

| Command | Description |
|---------|-------------|
| `make deploy-fleet` | Deploy Falco + Alloy to all fleet hosts |
| `make update-rules` | Push detection rules to fleet |
| `make fleet-health` | Check health of all agents |
| `make fleet-docker-check` | Check/install Docker on fleet hosts |
| `make fleet-ping` | Test SSH connectivity |
| `make fleet-shell` | Open shell in Ansible container |
| `make remove-fleet` | Remove agents from fleet |

---

## Configuration Options

Edit `ansible/inventory/group_vars/all.yml` to customize deployment:

```yaml
# Deployment strategy: native, docker, or auto
deployment_strategy: native

# Falco settings
falco_version: latest
falco_driver: modern_ebpf

# Alloy settings  
alloy_version: latest

# SIB server endpoints
sib_loki_url: "http://{{ sib_server }}:3100"
sib_prometheus_url: "http://{{ sib_server }}:9090"
sib_sidekick_url: "http://{{ sib_server }}:2801"

# What to collect
collect_system_logs: true
collect_auth_logs: true
collect_docker_logs: true
collect_metrics: true
```

---

## Enable Remote Access on SIB Server

Before deploying fleet agents, enable remote access:

```bash
make enable-remote
```

This exposes:
- **Loki** (3100) — For receiving logs
- **Prometheus** (9090) — For receiving metrics
- **Sidekick** (2801) — For receiving Falco events (already external)

### Firewall Configuration

Restrict access to fleet nodes only:

```bash
# UFW example
ufw allow from 192.168.1.0/24 to any port 3100  # Loki
ufw allow from 192.168.1.0/24 to any port 9090  # Prometheus  
ufw allow from 192.168.1.0/24 to any port 2801  # Sidekick

# iptables example
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 3100 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 9090 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 2801 -j ACCEPT
```

---

## Manual Collector Deployment

If you prefer manual deployment without Ansible:

### Using Deploy Script

```bash
# Deploy to a single host
make deploy-collector HOST=user@remote-host

# Or directly
./collectors/scripts/deploy.sh user@192.168.1.50 192.168.1.163
```

The script will:
1. Copy Alloy configuration to the remote host
2. Configure the SIB server address
3. Start Alloy via Docker Compose
4. Verify the deployment

### Full Manual Setup

```bash
# On the remote host
mkdir -p ~/sib-collector/config

# Copy and edit the config
scp collectors/config/config.alloy user@remote:~/sib-collector/config/
# Edit config.alloy - replace SIB_SERVER_IP with your SIB server IP

scp collectors/compose.yaml user@remote:~/sib-collector/

# Start the collector
ssh user@remote "cd ~/sib-collector && HOSTNAME=\$(hostname) docker compose up -d"
```

---

## What Gets Collected

| Type | Sources | Labels |
|------|---------|--------|
| **System Logs** | `/var/log/syslog`, `/var/log/messages` | `job="syslog"` |
| **Auth Logs** | `/var/log/auth.log`, `/var/log/secure` | `job="auth"` |
| **Kernel Logs** | `/var/log/kern.log` | `job="kernel"` |
| **Journal** | systemd journal | `job="journal"` |
| **Docker Logs** | All containers | `job="docker"`, `container=...` |
| **Node Metrics** | CPU, memory, disk, network | `job="node"`, `collector="alloy"` |
| **Falco Events** | Security detections | Sent via Falcosidekick |

All data is tagged with:
- `host` — Hostname of the remote machine
- `collector="alloy"` — Identifies data from Alloy collectors

---

## Verifying Fleet Deployment

### Check Collector Status

```bash
# Check Alloy logs on remote host
ssh user@remote "docker logs sib-alloy --tail 20"

# Or for native deployment
ssh user@remote "systemctl status alloy"
```

### Verify Data in SIB

```bash
# Query Loki for collector data
curl -s "http://localhost:3100/loki/api/v1/label/host/values"

# Check metrics in Prometheus
curl -s 'http://localhost:9090/api/v1/query?query=node_uname_info{collector="alloy"}'
```

### Fleet Overview Dashboard

Open Grafana and navigate to **Dashboards** → **Fleet Overview**:

![Fleet Overview](assets/images/fleet-overview.png)

This shows:
- Number of active hosts with collectors
- CPU, memory, disk utilization per host
- Network traffic graphs
- Log volume by host
- Hostname selector to filter all panels

---

## Updating Fleet

### Push Rule Updates

```bash
make update-rules
```

This pushes the latest detection rules from `detection/config/rules/` to all fleet hosts.

### Health Check

```bash
make fleet-health
```

Checks:
- Falco is running
- Alloy is running and shipping data
- Connectivity to SIB server

---

## Troubleshooting

### SSH Connection Issues

```bash
# Test SSH manually
ssh -i ~/.ssh/id_rsa user@remote-host

# Check SSH key permissions
chmod 600 ~/.ssh/id_rsa
```

### Falco Not Starting

```bash
# Check kernel version on remote host
ssh user@remote "uname -r"  # Need 5.8+

# Check Falco logs
ssh user@remote "docker logs sib-falco"
# Or for native
ssh user@remote "journalctl -u falco -n 50"
```

### No Data in Grafana

1. Check Alloy is running:
   ```bash
   ssh user@remote "docker ps | grep alloy"
   ```

2. Check Alloy logs for errors:
   ```bash
   ssh user@remote "docker logs sib-alloy --tail 50"
   ```

3. Verify network connectivity:
   ```bash
   ssh user@remote "curl -s http://SIB_SERVER:3100/ready"
   ```

---

## Removing Fleet Agents

```bash
# Remove from all hosts
make remove-fleet

# Remove from specific host
make remove-fleet LIMIT=webserver
```

This stops and removes:
- Falco (native or Docker)
- Alloy collector
- Associated systemd services (for native deployment)

---

[← Back to Home](index.md) | [AI Analysis →](ai-analysis.md)
