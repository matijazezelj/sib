---
layout: default
title: Installation Guide - SIEM in a Box
---

# Installation Guide

Get SIB up and running on your system.

[← Back to Home](index.md)

---

## Prerequisites

### Container Runtime

**Docker CE** 20.10+ from [docker.com](https://docs.docker.com/engine/install/) with Docker Compose v2+

**OR**

**Podman** 4.0+ in rootful mode with podman-compose

> ⚠️ **Docker Desktop is not supported.** Install Docker CE (Community Edition) directly from docker.com or use Podman.

> ⚠️ **Podman must run as root (rootful mode)** — Falco requires kernel access to monitor syscalls.

### System Requirements

- **Linux kernel** 5.8+ (for modern_ebpf driver)
- **4GB+ RAM** recommended

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

### Hardware Requirements

| Deployment | CPU | RAM | Disk | Notes |
|------------|-----|-----|------|-------|
| **SIB Server** (single host) | 2 cores | 4GB | 20GB | Runs Falco + full stack |
| **SIB Server** (with fleet) | 4 cores | 8GB | 50GB+ | More storage for logs from multiple hosts |
| **Fleet Agent** | 1 core | 512MB | 1GB | Falco + Alloy only |

---

## Quick Install

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

That's it! Your SIB instance is now running.

---

## Access Points

| Service | URL | Binding | Stack |
|---------|-----|---------|-------|
| **Grafana** | http://localhost:3000 | External (0.0.0.0) | Both |
| **Sidekick API** | http://localhost:2801 | External (0.0.0.0) | Both |
| VictoriaLogs | http://localhost:9428 | Localhost only | VM (default) |
| VictoriaMetrics | http://localhost:8428 | Localhost only | VM (default) |
| Loki | http://localhost:3100 | Localhost only | Grafana |
| Prometheus | http://localhost:9090 | Localhost only | Grafana |

Default Grafana credentials: `admin` / `admin`

---

## Step-by-Step Installation

### 1. Install Docker CE

**Ubuntu/Debian:**
```bash
# Remove old versions
sudo apt-get remove docker docker-engine docker.io containerd runc

# Install dependencies
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

**RHEL/CentOS/Fedora:**
```bash
# Install Docker
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### 2. Verify Kernel Version

```bash
uname -r
# Should output 5.8 or higher
```

If your kernel is older, you'll need to upgrade. On Ubuntu:
```bash
sudo apt-get update
sudo apt-get upgrade linux-generic
sudo reboot
```

### 3. Clone and Configure

```bash
git clone https://github.com/matijazezelj/sib.git
cd sib

# Copy the example environment file
cp .env.example .env

# (Optional) Edit environment variables
vim .env
```

### 4. Install SIB

```bash
# Install all components
make install
```

This will start:
- **Falco** — Runtime security detection
- **Falcosidekick** — Alert routing to log storage
- **VictoriaLogs** — Log storage (default stack)
- **VictoriaMetrics** — Metrics storage (default stack)
- **Grafana** — Visualization dashboards

> **Note:** To use the Grafana stack (Loki + Prometheus) instead, set `STACK=grafana` in your `.env` file before running `make install`.

### 5. Verify Installation

```bash
# Run the pipeline test
./scripts/test-pipeline.sh

# Check all services are running
make status

# View logs
make logs
```

---

## Post-Installation

### Grafana Password

A secure password is **auto-generated** during `make install` and saved to `.env`.

To view your password:
```bash
grep GRAFANA_ADMIN_PASSWORD .env
```

To change it:
1. Log in to Grafana at http://localhost:3000
2. Click your profile icon (bottom left)
3. Select "Change password"

Or regenerate by setting `GRAFANA_ADMIN_PASSWORD=CHANGE_ME` in `.env` and running `make install` again.

### Enable Remote Access

If you want to collect logs from other hosts:
```bash
make enable-remote
```

This exposes VictoriaLogs (9428) and VictoriaMetrics (8428) externally — or Loki (3100) and Prometheus (9090) if using the Grafana stack. Configure your firewall appropriately.

### Enable mTLS (Recommended for Production)

For encrypted communication between components:

```bash
# Generate certificates
make generate-certs

# Enable mTLS
echo "MTLS_ENABLED=true" >> .env

# Reinstall with mTLS
make install-alerting
make install-detection
```

> **Tip:** For fresh installs, set `MTLS_ENABLED=true` and run `make generate-certs` **before** `make install`. See [Security Hardening](security-hardening.md) for the complete fresh install workflow.

### Install AI Analysis (Optional)

```bash
make install-analysis
```

See [AI Analysis](ai-analysis.md) for configuration details.

---

## Component Installation

Install components individually if needed:

```bash
make install-detection       # Falco + Falcosidekick
make install-storage-vm      # VictoriaLogs + VictoriaMetrics (default)
make install-storage-grafana # Loki + Prometheus (alternative)
make install-grafana         # Grafana dashboards
make install-analysis        # AI analysis (optional)
```

---

## Uninstallation

```bash
# Stop and remove all containers
make uninstall

# Remove all data (logs, metrics, etc.)
# Warning: This is destructive!
docker volume prune
```

---

## Troubleshooting

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

# Query VictoriaLogs directly (default stack)
curl -s "http://localhost:9428/select/logsql/query?query=*" | jq .

# Or query Loki directly (Grafana stack)
curl -s "http://localhost:3100/loki/api/v1/query?query={source=\"syscall\"}" | jq .
```

### Permission Denied Errors

Ensure your user is in the docker group:
```bash
sudo usermod -aG docker $USER
# Log out and back in
```

---

## Next Steps

- [Quick Start Demo](quickstart.md) — Generate sample events
- [Fleet Management](fleet.md) — Deploy to multiple hosts
- [AI Analysis](ai-analysis.md) — Enable AI-powered analysis

---

[← Back to Home](index.md)
