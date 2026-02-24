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
     │ Falco + collectors ┴──────────────┴─── ...         │
     └────────────────────────────────────────────────────┘
```

Each fleet host gets:
- **Falco** — Runtime security detection (events sent directly to Falcosidekick)
- **VM stack (default):** Vector (logs → VictoriaLogs) + vmagent + node_exporter (metrics → VictoriaMetrics)
- **Grafana stack:** Alloy (logs → Loki, metrics → Prometheus)

All events from all hosts appear in your central Grafana dashboards.

---

## Deployment Strategies

SIB supports both **native packages** and **Docker containers**:

| Strategy | Description |
|----------|-------------|
| `docker` | Run agents as containers. **Recommended for simplicity.** |
| `native` | Falco from repo as systemd service |
| `auto` (default) | Use Docker if available, otherwise native |

> **Note:** VM stack collectors (Vector, vmagent, node_exporter) always run as Docker containers regardless of strategy. The strategy setting primarily affects Falco deployment.

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
| `make deploy-fleet` | Deploy Falco + collectors to all fleet hosts |
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
# Stack type: vm (default) or grafana
sib_stack: vm

# Deployment strategy: auto, docker, or native
deployment_strategy: auto

# Falco settings
falco_version: "0.40.0"
falco_driver: modern_ebpf

# SIB server endpoints (VM stack — default)
sib_victorialogs_url: "http://{{ sib_server }}:9428"
sib_victoriametrics_url: "http://{{ sib_server }}:8428"
sib_sidekick_url: "http://{{ sib_server }}:2801"

# mTLS — encrypt fleet-to-server communication
mtls_enabled: false
mtls_cert_dir: /etc/sib/certs
```

---

## Enable Remote Access on SIB Server

Before deploying fleet agents, enable remote access:

```bash
make enable-remote
```

This exposes (depending on your stack):
- **VM stack (default):** VictoriaLogs (9428), VictoriaMetrics (8428)
- **Grafana stack:** Loki (3100), Prometheus (9090)
- **Sidekick** (2801) — For receiving Falco events (always external)

### Firewall Configuration

Restrict access to fleet nodes only:

```bash
# UFW example (VM stack)
ufw allow from 192.168.1.0/24 to any port 9428  # VictoriaLogs
ufw allow from 192.168.1.0/24 to any port 8428  # VictoriaMetrics
ufw allow from 192.168.1.0/24 to any port 2801  # Sidekick

# iptables example (VM stack)
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 9428 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 8428 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 2801 -j ACCEPT
```

---

## Enable mTLS for Encrypted Fleet Communication

For production deployments, enable mutual TLS (mTLS) to encrypt all communication between fleet agents and the SIB server.

### Quick mTLS Setup

> **Fresh Install?** If setting up a new SIB server with mTLS, generate certificates **before** running `make install`:
> ```bash
> sed -i 's/MTLS_ENABLED=false/MTLS_ENABLED=true/' .env
> make generate-certs
> make install
> ```

For existing SIB installations:

```bash
# 1. Generate CA and server certificates
make generate-certs

# 2. Generate client certificates for all fleet hosts
make generate-fleet-certs

# 3. Enable mTLS on SIB server
echo "MTLS_ENABLED=true" >> .env
make install-alerting
make install-detection

# 4. Enable mTLS in Ansible configuration
# Edit ansible/inventory/group_vars/all.yml:
# mtls_enabled: true

# 5. Deploy fleet with mTLS
make deploy-fleet
```

### Per-Host Certificate Generation

If you add a new host later:

```bash
# Generate certificate for the new host
make generate-client-cert HOST=new-server

# Deploy to just that host
make deploy-fleet LIMIT=new-server
```

### Verify mTLS is Working

```bash
# Check Falcosidekick logs for TLS connections
docker logs sib-sidekick 2>&1 | grep -i tls

# Test mTLS connection manually
openssl s_client -connect localhost:2801 \
  -CAfile certs/ca/ca.crt \
  -cert certs/clients/local.crt \
  -key certs/clients/local.key
```

See [Security Hardening](security-hardening.md) for complete mTLS documentation.

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
1. Copy collector configuration to the remote host
2. Configure the SIB server address
3. Start collectors via Docker Compose
4. Verify the deployment

### Full Manual Setup (VM Stack)

```bash
# On the remote host
mkdir -p ~/sib-collector/config

# Copy configs
scp collectors/config/vector.toml user@remote:~/sib-collector/config/
scp collectors/config/vmagent.yml user@remote:~/sib-collector/config/
# Edit configs - replace SIB_SERVER_IP with your SIB server IP

# Copy compose file
scp collectors/compose-vm.yaml user@remote:~/sib-collector/compose.yaml

# Start the collectors
ssh user@remote "cd ~/sib-collector && HOSTNAME=\$(hostname) docker compose up -d"
```

---

## What Gets Collected

| Type | Sources | Labels/Fields |
|------|---------|---------------|
| **System Logs** | `/var/log/syslog`, `/var/log/messages` | `hostname` field |
| **Auth Logs** | `/var/log/auth.log`, `/var/log/secure` | `hostname` field |
| **Kernel Logs** | `/var/log/kern.log` | `hostname` field |
| **Docker Logs** | All containers | `hostname` field, `container_name` |
| **Node Metrics** | CPU, memory, disk, network | `host` label, `job="node"` |
| **Falco Events** | Security detections | `hostname` field (via Falcosidekick) |

Data labeling convention:
- **Metrics** (VictoriaMetrics): tagged with `host` label (set by vmagent's `-remoteWrite.label`)
- **Logs** (VictoriaLogs): tagged with `hostname` field (set by Vector transform)
- **Falco events**: tagged with `hostname` field (set by Falcosidekick)

---

## Verifying Fleet Deployment

### Check Collector Status

```bash
# VM stack (default) — check Vector and vmagent
ssh user@remote "docker logs sib-vector --tail 20"
ssh user@remote "docker logs sib-vmagent --tail 20"

# Grafana stack — check Alloy
ssh user@remote "docker logs sib-alloy --tail 20"
```

### Verify Data in SIB

```bash
# Query VictoriaLogs for collector data (default stack)
curl -s "http://localhost:9428/select/logsql/query?query=*" | head

# Check metrics in VictoriaMetrics (default stack)
curl -s 'http://localhost:8428/api/v1/query?query=node_uname_info'

# Or for Grafana stack: Loki at :3100, Prometheus at :9090
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
- Collectors are running and shipping data (Vector/vmagent or Alloy)
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

1. Check collectors are running:
   ```bash
   # VM stack (default)
   ssh user@remote "docker ps | grep -E 'sib-(vector|vmagent|node-exporter)'"
   # Grafana stack
   ssh user@remote "docker ps | grep alloy"
   ```

2. Check collector logs for errors:
   ```bash
   ssh user@remote "docker logs sib-vector --tail 50"
   ssh user@remote "docker logs sib-vmagent --tail 50"
   ```

3. Verify network connectivity:
   ```bash
   # VM stack (default)
   ssh user@remote "curl -s http://SIB_SERVER:9428/health"
   ssh user@remote "curl -s http://SIB_SERVER:8428/-/healthy"
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
- Collectors (Vector/vmagent/node_exporter or Alloy depending on stack)
- Associated configuration files

---

[← Back to Home](index.md) | [AI Analysis →](ai-analysis.md)
