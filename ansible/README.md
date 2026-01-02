# SIB Fleet Management with Ansible

Deploy and manage SIB security agents across your infrastructure.

**No local Ansible installation required** — everything runs in Docker.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SIB Central Server                    │
│  ┌─────────┐ ┌──────┐ ┌────────────┐ ┌─────────┐       │
│  │ Grafana │ │ Loki │ │ Prometheus │ │Sidekick │       │
│  └─────────┘ └──────┘ └────────────┘ └─────────┘       │
└─────────────────────────▲──────────────▲────────────────┘
                          │              │
            ┌─────────────┼──────────────┼─────────────┐
            │             │              │             │
     ┌──────┴──────┐ ┌────┴────┐ ┌──────┴──────┐      │
     │   Host A    │ │  Host B │ │   Host C    │  ... │
     │ Falco+Alloy │ │ Falco+  │ │ Falco+Alloy │      │
     └─────────────┘ └─────────┘ └─────────────┘      │
            └─────────────────────────────────────────┘
                     Managed by Ansible (in Docker)
```

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
| `make deploy-fleet` | Deploy Falco + Alloy to all fleet hosts |
| `make update-rules` | Push updated detection rules to fleet |
| `make fleet-health` | Check health of all fleet agents |
| `make fleet-ping` | Test SSH connectivity to fleet hosts |
| `make fleet-shell` | Open shell in Ansible container for manual commands |
| `make remove-fleet` | Remove agents from fleet (requires confirmation) |

### Target Specific Hosts

```bash
make deploy-fleet LIMIT=webserver
make deploy-fleet LIMIT='webserver,database'
make fleet-health LIMIT=webserver
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
- Configured to send events to central Falcosidekick
- Custom rules from `detection/config/rules/`

### Alloy (Grafana Agent)
- Collects and ships logs to central Loki
- Collects and ships metrics to central Prometheus
- Includes Docker container logs
- Includes systemd journal logs

## Configuration

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

### Deployment Methods

**Docker (default)** - Falco runs in a container:
```yaml
docker_hosts:
  hosts:
    webserver:
  vars:
    falco_deployment: docker
```

**Native** - Falco installed via package manager:
```yaml
bare_metal_hosts:
  hosts:
    database:
  vars:
    falco_deployment: native
```

### Custom Rules

Add custom Falco rules to `detection/config/rules/`, then push to fleet:

```bash
make update-rules
```

## Troubleshooting

### Check agent status on a host
```bash
ssh user@host "docker ps | grep -E 'falco|alloy'"
```

### View Falco logs
```bash
ssh user@host "docker logs falco --tail 100"
```

### View Alloy logs
```bash
ssh user@host "docker logs sib-alloy --tail 100"
```

### Test connectivity to central
```bash
ssh user@host "curl -s http://SIB_SERVER:3100/ready"
ssh user@host "curl -s http://SIB_SERVER:2801/healthz"
```

### Re-deploy a single host
```bash
make deploy-fleet LIMIT=problematic-host
```

## Security Notes

1. **SSH Keys**: Use SSH keys, not passwords
2. **Become**: Playbooks use `become: true` (sudo)
3. **Network**: Fleet hosts need outbound access to SIB server ports:
   - 3100 (Loki)
   - 2801 (Falcosidekick)
   - 9090 (Prometheus, if using remote write)

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
│   ├── falco/                 # Falco installation
│   └── alloy/                 # Alloy installation
├── requirements.yml           # Ansible collections
└── README.md                  # This file
```
