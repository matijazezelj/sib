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
- **vmagent + node_exporter** → Metrics → VictoriaMetrics, **Vector** → Logs → VictoriaLogs (VM stack)
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

On the SIB server, open the ports the fleet needs: `make enable-remote` for storage, and `SIDEKICK_BIND_ADDR=0.0.0.0` in `.env` followed by `make install-alerting` for Falcosidekick. Both listen on localhost by default. Firewall them (see [Security Notes](#security-notes)).

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
| `make deploy-fleet` | Deploy Falco + collectors to all fleet hosts, then run `make refresh-alerts` |
| `make update-rules` | Push custom rules to fleet (Docker or native, detected per host) |
| `make fleet-certs` | Push mTLS certificates without a full redeploy |
| `make fleet-health` | Check health of all fleet agents |
| `make fleet-docker-check` | Check if Docker is installed, install if missing |
| `make fleet-ping` | Test SSH connectivity to fleet hosts |
| `make fleet-shell` | Open shell in Ansible container for manual commands |
| `make remove-fleet` | Remove agents from fleet (no confirmation prompt, see [Removing Agents](#removing-agents)) |

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
- Custom rules listed in `falco_custom_rules` (default `custom_rules.yaml`), from `detection/config/rules/`
- Falco `falco_version` 0.45.2 (keep in sync with `FALCO_VERSION`); native installs are pinned to it
- Falco `/metrics` on `127.0.0.1`, scraped by the host collector; Grafana's "Falco not reporting" alert uses it. Every fleet host is expected unless it sets `sib_expected: false` (see [docs/grafana-alerts.md](../docs/grafana-alerts.md))

### Collectors (stack-dependent)

**VM stack (default, `sib_stack: vm`)**
- vmagent + node_exporter for metrics → VictoriaMetrics
- Vector for host logs → VictoriaLogs (Falco events still go via Sidekick)

**Grafana stack (`sib_stack: grafana`)**
- Grafana Alloy
- Logs (systemd journal, Docker) → Loki, metrics → Prometheus

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

On the Grafana stack, add labels to hosts for filtering in Grafana (the VM stack ignores them):

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

Alloy adds them to Loki and Prometheus data.

### HIB Events

Set `hib_events_dir` on a host that runs [HIB](../docs/hib-integration.md) to ship its security event log. The directory must already exist.

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

SIB supports both native package installation and Docker containers. **Docker is recommended** for simplicity; `native` gives Falco direct process visibility.

| Strategy | Description |
|----------|-------------|
| `auto` (default) | Docker, installing it if missing; native only if Docker is missing and `install_docker_if_missing: false` |
| `docker` | Run Falco as a container, installing Docker if missing |
| `native` | Install Falco from the package repo. VM collectors always use Docker, which `native` doesn't install. |

Configure in `inventory/group_vars/all.yml`:

```yaml
# Deployment Strategy (for Falco)
# auto   - Docker, installed if missing and install_docker_if_missing is true (default)
# docker - Docker containers (installs Docker if missing)
# native - Native packages (better process visibility)
deployment_strategy: auto

# Collector deployment (VM stack: vector + vmagent + node_exporter)
# auto   - Use Docker if available, otherwise skip (VM collectors require Docker)
# docker - Force Docker containers
collector_deployment: auto

# Install Docker if not present? (only applies when strategy is 'auto' or 'docker')
install_docker_if_missing: true
```

### LXC Container Limitations

**Falco does not work in LXC containers** due to kernel access limitations:
- LXC containers share the host kernel
- eBPF/kernel module support is not available
- With a Docker deployment, Falco is skipped with a warning on LXC hosts

**Recommendations for LXC:**
- Run Falco on the Proxmox/LXC host itself
- Use VMs instead of LXC for full security monitoring
- Set `sib_expected: false` on LXC hosts so the liveness alert doesn't expect them
- Log and metric collectors still work in LXC

**What happens on deployment:**

1. **Check Docker** → Is Docker installed and running?
2. **Decide method** → Based on `deployment_strategy` and Docker availability
3. **Install Docker** → If needed, install static binaries as systemd services
4. **Deploy agents:**
   - **Docker mode**: Run Falco and the stack's collectors as containers
   - **Native mode**: Install Falco from the repo; Grafana stack: Alloy as a static binary

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

Only the files listed in `falco_custom_rules` are pushed. They are copied to the Docker (`/etc/sib/falco/rules.d`) or native (`/etc/falco/rules.d`) location, validated together with `falco_rules.yaml`, and Falco is restarted only if validation passes.

## Troubleshooting

### Check agent status on a host
```bash
# Native Falco deployment
ssh user@host "systemctl status falco-modern-bpf"

# Docker deployment (Falco + VM collectors)
ssh user@host "docker ps | grep -E 'sib-falco|sib-vector|sib-vmagent|sib-node-exporter'"

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
ssh user@host "docker logs sib-vector --tail 100"
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
ssh user@host "curl -s http://SIB_SERVER:9428/health"
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

For production deployments, enable mutual TLS (mTLS) for Falco events (Falco → Falcosidekick). Log and metric traffic to storage stays plain HTTP.

### Quick mTLS Setup

```bash
# 1. Generate certificates on SIB server
make generate-certs
make generate-fleet-certs

# 2. Enable mTLS on SIB server: set MTLS_ENABLED=true in .env
sed -i 's/^MTLS_ENABLED=.*/MTLS_ENABLED=true/' .env
make install-alerting
make install-detection
make install-storage-vm        # or install-storage-grafana (scrapes Sidekick over https)

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
   - 9428 (VictoriaLogs) - for Vector logs (VM stack)
   - 3100 (Loki) + 9090 (Prometheus) - for logs/metrics (Grafana stack)

4. **Firewall**: Restrict these ports to approved fleet hosts. Docker-published ports bypass `ufw` and the `INPUT` chain, so filter in the `DOCKER-USER` chain or on an upstream firewall; see [Security Hardening](../docs/security-hardening.md#4-restrict-fleet-ingress).

## Removing Agents

```bash
make remove-fleet LIMIT=webserver
```

This runs right away, without asking; without `LIMIT` it covers the whole fleet. It removes native Falco and Alloy, their configuration, the SIB directories and the `sib-alloy`, `sib-vmagent` and `sib-node-exporter` containers. It leaves `sib-falco` and `sib-vector` running:

```bash
ssh user@host "docker rm -f sib-falco sib-vector"
```

Then remove the host from the inventory and run `make refresh-alerts`.

## File Structure

```
ansible/
├── inventory/
│   ├── hosts.yml.example      # Example inventory (copy to hosts.yml)
│   └── group_vars/
│       └── all.yml            # Global variables
├── playbooks/
│   ├── deploy-fleet.yml       # Full deployment
│   ├── update-rules.yml       # Push rule updates
│   ├── deploy-certs.yml       # Push mTLS certificates
│   ├── docker-check.yml       # Check/install Docker
│   ├── health-check.yml       # Verify fleet health
│   └── remove-fleet.yml       # Uninstall agents
├── roles/
│   ├── common/                # Prerequisites
│   ├── certs/                 # mTLS certificate distribution
│   ├── falco/                 # Falco installation
│   ├── alloy/                 # Alloy installation (Grafana stack)
│   └── vm_collectors/         # vmagent + node_exporter (VM stack)
├── scripts/
│   └── expected-hosts.py      # Hosts the Falco liveness alert expects
├── compose.yaml               # Ansible control container
├── Dockerfile
├── ansible.cfg
├── requirements.yml           # Ansible collections
└── README.md                  # This file
```
