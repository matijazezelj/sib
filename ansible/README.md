# SIB Fleet Management with Ansible

Deploy and manage SIB security agents across your infrastructure.

**No local Ansible installation required** — everything runs in Docker.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      SIB Central Server                      │
│  ┌─────────┐ ┌──────────────┐ ┌────────────────┐ ┌────────┐ │
│  │ Grafana │ │ VictoriaLogs │ │ VictoriaMetrics│ │Sidekick│ │
│  └─────────┘ └──────────────┘ └────────────────┘ └────────┘ │
└─────────────────────────▲──────────────▲────────────────────┘
                          │              │
            ┌─────────────┼──────────────┼─────────────┐
            │             │   (mTLS)     │             │
     ┌──────┴──────┐ ┌────┴────┐ ┌──────┴──────┐      │
     │   Host A    │ │  Host B │ │   Host C    │  ... │
     │ Falco+vmagent││ Falco+  │ │Falco+vmagent│      │
     └─────────────┘ └─────────┘ └─────────────┘      │
            └─────────────────────────────────────────┘
                     Managed by Ansible (in Docker)
```

Fleet hosts run:
- **Falco** → Security events → Sidekick (with mTLS)  
- **vmagent + node_exporter** → Metrics → VictoriaMetrics (VM stack)
- **Alloy** → Logs/Metrics → Loki/Prometheus (Grafana stack)

## Quick Start

### 1. Configure Inventory

```bash
# Copy example inventory
cp ansible/inventory/hosts.yml.example ansible/inventory/hosts.yml

# Edit with your hosts
vim ansible/inventory/hosts.yml
```

Update the following:
- `sib_server`: IP of your central SIB server
- `fleet.hosts`: Add your target hosts
- SSH credentials

### 2. Test Connectivity

```bash
# Ping all fleet hosts (tests SSH connectivity)
make fleet-ping
```

### 3. Deploy Fleet Agents

```bash
# Deploy to all hosts
make deploy-fleet

# Or deploy to specific host
make deploy-fleet LIMIT=webserver
```

### 4. Verify Deployment

```bash
# Run health check
make fleet-health
```

## Commands

| Command | Description |
|---------|-------------|
| `make fleet-build` | Build Ansible Docker image (auto-runs on first deploy) |
| `make deploy-fleet` | Deploy Falco + collectors to all fleet hosts |
| `make update-rules` | Push updated detection rules to fleet |
| `make fleet-health` | Check health of all fleet agents |
| `make fleet-docker-check` | Check if Docker is installed, install if missing |
| `make fleet-ping` | Test SSH connectivity to fleet hosts |
| `make fleet-shell` | Open shell in Ansible container for manual commands |
| `make remove-fleet` | Remove agents from fleet (requires confirmation) |

### Target Specific Hosts

```bash
make deploy-fleet LIMIT=webserver
make deploy-fleet LIMIT='webserver,database'
make fleet-health LIMIT=webserver
```

### Pass Extra Arguments

Use `ARGS` to pass additional Ansible variables:

```bash
# Check Docker without auto-installing
make fleet-docker-check ARGS="-e auto_install=false"

# Specify Docker version
make fleet-docker-check ARGS="-e docker_version=24.0.7"

# Verbose output
make deploy-fleet ARGS="-vvv"
```

## SSH Key Setup

The Ansible container mounts your `~/.ssh` directory. Make sure:

1. Your SSH keys are in `~/.ssh/`
2. Target hosts have your public key in `~/.ssh/authorized_keys`
3. Keys have correct permissions (`chmod 600 ~/.ssh/id_*`)

### Using SSH Agent

If you use ssh-agent, it's automatically forwarded to the container:

```bash
# Add your key to agent
ssh-add ~/.ssh/id_rsa

# Then run fleet commands
make deploy-fleet
```

### Password Authentication (Not Recommended)

If you must use passwords, use `fleet-shell` and run manually:

```bash
make fleet-shell
# Inside container:
ansible-playbook -i inventory/hosts.yml playbooks/deploy-fleet.yml --ask-pass --ask-become-pass
```

## What Gets Deployed

### Falco
- Runtime security detection using eBPF
- Configured to send events to central Falcosidekick (with optional mTLS)
- Custom rules from `detection/config/rules/`

### Collectors (stack-dependent)

**VM stack (default, `sib_stack: vm`)**
- vmagent + node_exporter for metrics → VictoriaMetrics
- No log shipping (Falco events go via Sidekick)

**Grafana stack (`sib_stack: grafana`)**
- Alloy (Grafana Agent)
- Logs → Loki, Metrics → Prometheus

## Configuration

### Stack Selection

Set in `ansible/inventory/group_vars/all.yml`:

```yaml
# VM stack (default) - vmagent + node_exporter for metrics
sib_stack: vm

# Grafana stack - Alloy for logs/metrics
# sib_stack: grafana
```

### Host Labels

Add labels to hosts for filtering in Grafana:

```yaml
fleet:
  hosts:
    webserver:
      ansible_host: 192.168.1.10
      host_labels:
        role: web
        environment: production
        team: platform
```

These appear in Loki/Prometheus as labels.

### Docker Installation

**No package manager required!** SIB installs Docker using static binaries with systemd services.

```bash
# Check Docker status on all hosts (installs if missing)
make fleet-docker-check

# Check only, don't install
make fleet-docker-check ARGS="-e auto_install=false"

# Specify Docker version
make fleet-docker-check ARGS="-e docker_version=24.0.7"
```

The playbook will:
1. Check if Docker is already installed
2. Download Docker static binaries (supports x86_64 and aarch64)
3. Create systemd services for `containerd` and `docker`
4. Configure Docker with overlay2 storage driver
5. Start and enable services

This approach works on any Linux distribution without requiring apt/yum/dnf access.

### Deployment Strategy

SIB supports both native package installation and Docker containers. **Native is recommended** for Falco visibility.

| Strategy | Description |
|----------|-------------|
| `native` (default) | Install Falco from repo. VM collectors always use Docker. |
| `docker` | Run Falco as container |
| `auto` | Use Docker if available, otherwise native |

Configure in `inventory/group_vars/all.yml`:

```yaml
# Deployment Strategy (for Falco)
# native - Native packages (recommended, better process visibility)
# docker - Docker containers (requires Docker)
# auto   - Use Docker if available, otherwise native
deployment_strategy: native

# Collector deployment (VM stack: vmagent + node_exporter)
# docker - Always use Docker (recommended, only option for VM collectors)
collector_deployment: docker

# Install Docker if not present? (only applies when strategy is 'auto' or 'docker')
install_docker_if_missing: true
```

### LXC Container Limitations

**Falco does not work in LXC containers** due to kernel access limitations:
- LXC containers share the host kernel
- eBPF/kernel module support is not available
- Falco will be skipped with a warning on LXC hosts

**Recommendations for LXC:**
- Run Falco on the Proxmox/LXC host itself
- Use VMs instead of LXC for full security monitoring
- Alloy (logs/metrics) still works in LXC

**What happens on deployment:**

1. **Check Docker** → Is Docker installed and running?
2. **Decide method** → Based on `deployment_strategy` and Docker availability
3. **Install Docker** → If needed, install static binaries as systemd services
4. **Deploy agents:**
   - **Docker mode**: Run Falco and Alloy as containers
   - **Native mode**: Install Falco from repo, Alloy as static binary

### Per-Host Override

Force specific deployment on individual hosts:

```yaml
fleet:
  hosts:
    # This host will always use containers
    docker-host:
      ansible_host: 192.168.1.10
    
    # This host will use native packages (no Docker)
    bare-metal-host:
      ansible_host: 192.168.1.11
      deployment_strategy: native
```

### Custom Rules

Add custom Falco rules to `detection/config/rules/`, then push to fleet:

```bash
make update-rules
```

## Troubleshooting

### Check agent status on a host
```bash
# Native Falco deployment
ssh user@host "systemctl status falco-modern-bpf"

# Docker deployment (Falco + VM collectors)
ssh user@host "docker ps | grep -E 'sib-falco|sib-vmagent|sib-node-exporter'"

# Grafana stack (Alloy)
ssh user@host "docker ps | grep -E 'sib-falco|sib-alloy'"
```

### View Falco logs
```bash
# Native deployment
ssh user@host "journalctl -u falco-modern-bpf -f"

# Docker deployment  
ssh user@host "docker logs sib-falco --tail 100"
```

### View VM collectors logs
```bash
ssh user@host "docker logs sib-vmagent --tail 100"
ssh user@host "docker logs sib-node-exporter --tail 100"
```

### View Alloy logs (Grafana stack)
```bash
# Native deployment
ssh user@host "journalctl -u alloy -f"

# Docker deployment
ssh user@host "docker logs sib-alloy --tail 100"
```

### Test connectivity to central
```bash
# VM stack
ssh user@host "curl -s http://SIB_SERVER:8428/health"
ssh user@host "curl -s http://SIB_SERVER:2801/healthz"

# Grafana stack
ssh user@host "curl -s http://SIB_SERVER:3100/ready"
ssh user@host "curl -s http://SIB_SERVER:2801/healthz"
```

### Re-deploy a single host
```bash
make deploy-fleet LIMIT=problematic-host
```

## mTLS Encryption

For production deployments, enable mutual TLS (mTLS) to encrypt all communication between fleet agents and the SIB server.

### Quick mTLS Setup

```bash
# 1. Generate certificates on SIB server
make generate-certs
make generate-fleet-certs

# 2. Enable mTLS on SIB server
echo "MTLS_ENABLED=true" >> .env
make install-alerting
make install-detection

# 3. Enable mTLS in Ansible
# Edit ansible/inventory/group_vars/all.yml:
# mtls_enabled: true

# 4. Deploy fleet with mTLS
make deploy-fleet
```

### Configuration

In `inventory/group_vars/all.yml`:

```yaml
# Enable mTLS for Falco → Falcosidekick communication
mtls_enabled: true

# Certificate paths on fleet hosts (set by certs role)
mtls_cert_dir: /etc/sib/certs
mtls_ca_cert: "{{ mtls_cert_dir }}/ca.crt"
mtls_client_cert: "{{ mtls_cert_dir }}/client.crt"
mtls_client_key: "{{ mtls_cert_dir }}/client.key"
```

See [Security Hardening](../docs/security-hardening.md) for complete mTLS documentation.

---

## Security Notes

1. **SSH Keys**: Use SSH keys, not passwords
2. **Become**: Playbooks use `become: true` (sudo)
3. **Network**: Fleet hosts need outbound access to SIB server ports:
   - 2801 (Falcosidekick) - for Falco events (supports mTLS)
   - 8428 (VictoriaMetrics) - for metrics (VM stack)
   - 3100 (Loki) + 9090 (Prometheus) - for logs/metrics (Grafana stack)

4. **Firewall**: Restrict access to fleet nodes only:
   ```bash
   # UFW example
   ufw allow from 192.168.1.0/24 to any port 2801
   ufw allow from 192.168.1.0/24 to any port 8428
   
   # iptables example
   iptables -A INPUT -p tcp --dport 2801 -s 192.168.1.0/24 -j ACCEPT
   iptables -A INPUT -p tcp --dport 8428 -s 192.168.1.0/24 -j ACCEPT
   iptables -A INPUT -p tcp --dport 2801 -j DROP
   iptables -A INPUT -p tcp --dport 8428 -j DROP
   ```

## File Structure

```
ansible/
├── inventory/
│   ├── hosts.yml.example      # Example inventory
│   └── group_vars/
│       └── all.yml            # Global variables
├── playbooks/
│   ├── deploy-fleet.yml       # Full deployment
│   ├── update-rules.yml       # Push rule updates
│   ├── health-check.yml       # Verify fleet health
│   └── remove-fleet.yml       # Uninstall agents
├── roles/
│   ├── common/                # Prerequisites
│   ├── certs/                 # mTLS certificate distribution
│   ├── falco/                 # Falco installation
│   ├── alloy/                 # Alloy installation (Grafana stack)
│   └── vm_collectors/         # vmagent + node_exporter (VM stack)
├── requirements.yml           # Ansible collections
└── README.md                  # This file
```
