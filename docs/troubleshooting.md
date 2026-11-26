---
layout: default
title: Troubleshooting - SIEM in a Box
---

# Troubleshooting Guide

Common issues and their solutions.

[← Back to Home](index.md)

---

## Quick Diagnostics

Run the built-in diagnostics:

```bash
# Full pipeline test
./scripts/test-pipeline.sh

# Check service status
make status

# Quick health check
make health

# Diagnose common issues
make doctor

# View all logs
make logs
```

---

## Installation Issues

### Docker Desktop Not Supported

**Error**: Various permission or networking issues

**Solution**: Install Docker CE directly, not Docker Desktop:
```bash
# Uninstall Docker Desktop first, then:
# Ubuntu/Debian
curl -fsSL https://get.docker.com | sh

# Add your user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### Kernel Too Old for eBPF

**Error**: `Falco driver failed to load` or `modern_ebpf not supported`

**Solution**: Upgrade your kernel to 5.8+:
```bash
# Check current version
uname -r

# Ubuntu
sudo apt-get update && sudo apt-get upgrade linux-generic
sudo reboot
```

### Permission Denied

**Error**: `Got permission denied while trying to connect to the Docker daemon`

**Solution**: Add your user to the docker group:
```bash
sudo usermod -aG docker $USER
# Log out and back in completely
```

---

## Falco Issues

### Falco Won't Start

```bash
# Check logs
docker logs sib-falco

# Verify privileged mode works
docker run --rm --privileged alpine echo "OK"

# Check kernel version
uname -r  # Need 5.8+
```

### Falco High CPU Usage

**Cause**: Too many rules or very active system

**Solutions**:
1. Disable rules you don't need (`enabled: false`, or remove a file from `rules_files` in `detection/config/falco.yaml.template`)
2. Run `make install-detection` after editing the template

If Falco drops events, raise `buf_size_preset` in `scripts/generate-falco-config.sh` (it writes the engine block of `falco.yaml`), then run `make install-detection`.

### No Falco Events

```bash
# Trigger a detection (make test-alert only tests Falcosidekick, not Falco)
docker run --rm alpine cat /etc/shadow

# Check if Falco sees it
docker logs sib-falco --tail 20

# Check that the syscall source was opened
docker logs sib-falco 2>&1 | grep -i "syscall"
```

---

## Log Pipeline Issues

### Events Not Reaching Grafana

**Step-by-step diagnosis**:

1. **Check Falco is detecting**:
   ```bash
   docker logs sib-falco --tail 10
   ```

2. **Check Sidekick is receiving**:
   ```bash
   docker logs sib-sidekick --tail 10
   ```

3. **Check storage backend is storing**:

   **VictoriaLogs (default):**
   ```bash
   curl -s "http://localhost:9428/select/logsql/query?query=source:syscall&limit=5" | jq
   ```

   **Loki (Grafana stack):**
   ```bash
   curl -sG http://localhost:3100/loki/api/v1/query_range \
     --data-urlencode 'query={source="syscall"}' | jq '.data.result | length'
   ```

4. **Check Grafana datasource**:
   - Go to Grafana → Connections → Data sources
   - Click on VictoriaLogs or Loki → Click "Test" button

### VictoriaLogs Query Returns Empty

```bash
# Check VictoriaLogs is healthy
curl http://localhost:9428/health

# Check what fields exist
curl "http://localhost:9428/select/logsql/field_names?query=*"

# Try a simple query
curl "http://localhost:9428/select/logsql/query?query=*&limit=10"
```

### Loki Query Returns Empty

```bash
# Check Loki is healthy
curl http://localhost:3100/ready

# Check what labels exist
curl http://localhost:3100/loki/api/v1/labels

# Try a simple query
curl -G http://localhost:3100/loki/api/v1/query_range --data-urlencode 'query={source="syscall"}'
```

### Sidekick Not Forwarding

Check the generated `alerting/config/config.yaml` (it is rewritten on every `make install-alerting`, so do not edit it; change `.env` or `alerting/config/custom-outputs.yaml` instead). The `loki:` output points at the storage backend for your stack:

**VictoriaLogs (default):**
```yaml
loki:
  hostport: "http://sib-victorialogs:9428"
  endpoint: "/insert/loki/api/v1/push"
```

**Loki (Grafana stack):**
```yaml
loki:
  hostport: "http://sib-loki:3100"
  endpoint: "/loki/api/v1/push"
```

Regenerate after changes (this also restarts Sidekick):
```bash
make install-alerting
```

`make install-alerting` fails if Falcosidekick can't read its config (`Error when reading config file`). It then runs with defaults: plain HTTP, no mTLS, no outputs. The file's group must match `SIDECAR_CONFIG_GID` in `.env`. The generator sets it, which only fails if you aren't a member of that group (it then warns): set `SIDECAR_CONFIG_GID` to a group you're in, usually your own (`id -g`). A half-configured Telegram output (`TELEGRAM_TOKEN` without `TELEGRAM_CHAT_ID`, or the reverse) also fails the install; see [Grafana Alerts](grafana-alerts.md#notifications).

### "Falcosidekick down" Fires With mTLS On

With `MTLS_ENABLED=true`, a plain `http://` scrape of Sidekick's `/metrics` is rejected. Re-run `make install-storage-vm` (or `install-storage-grafana`) to regenerate the scrape config with the `metrics-scraper` client certificate. See [Grafana Alerts](grafana-alerts.md#scraping-falcosidekick-over-mtls).

---

## Dashboard Issues

### Dashboards Missing

```bash
# Check dashboard provisioning
docker logs sib-grafana | grep -i dashboard

# Re-provision dashboards
make install-grafana
```

### Dashboards Show "No Data"

1. **Check time range**: Ensure it covers when events occurred
2. **Check datasource**: Verify VictoriaLogs/Loki datasource is working
3. **Generate events**: Run `make demo` to create test data
4. **Check query**: Open panel → Edit → check for errors

### Grafana Won't Start

```bash
# Check logs
docker logs sib-grafana

# Common issues:
# - Port 3000 already in use
# - Permission issues on data directory

# Last resort: start with fresh data. Deletes everything created in the
# Grafana UI (dashboards, users, password changes).
make uninstall-grafana
make install-grafana
```

---

## Fleet/Remote Collector Issues

### SSH Connection Fails

```bash
# Test SSH manually
ssh -v -i ~/.ssh/id_rsa user@remote-host

# Check key permissions
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh

# Verify remote host accepts the key
ssh-copy-id -i ~/.ssh/id_rsa user@remote-host
```

### Collectors Not Sending Data

On the remote host:
```bash
# VM stack (default) — check Vector and vmagent
docker logs sib-vector --tail 50
docker logs sib-vmagent --tail 50

# Grafana stack — check Alloy
docker logs sib-alloy --tail 50

# Verify network connectivity to SIB server
# VictoriaLogs (default):
curl -s http://SIB_SERVER:9428/health
curl -s http://SIB_SERVER:8428/-/healthy

# Loki (Grafana stack):
curl -s http://SIB_SERVER:3100/ready
curl -s http://SIB_SERVER:9090/-/ready
```

### Fleet Host Not Appearing

1. Check the collector is running on remote host
2. Verify firewall allows traffic to SIB server ports
   - **VictoriaMetrics stack**: 9428, 8428, 2801
   - **Grafana stack**: 3100, 9090, 2801
3. Check metrics `host` label in VictoriaMetrics:
   ```bash
   curl 'http://localhost:8428/api/v1/label/host/values'
   ```
4. Check logs in VictoriaLogs. Falco events and Ansible-deployed collectors use the `hostname` field (collectors started with `make deploy-collector` label their logs `host`):
   ```bash
   curl 'http://localhost:9428/select/logsql/query?query=hostname:*|stats+by(hostname)+count()&limit=10'
   ```

---

### "Falco not reporting" Fires for a Host

The alert means no successful scrape of that host's Falco `/metrics` for 5 minutes. Check Falco and the collector (`make fleet-health`), and that `up{job="falco"}` has the host:

```bash
# VM stack; use port 9090 on the Grafana stack
curl -s http://localhost:8428/api/v1/query --data-urlencode 'query=up{job="falco"}'
```

A host that was never redeployed since the alert was added has no `falco` scrape job: run `make deploy-fleet` once. A host retired on purpose, or one without Falco (LXC, collector-only), should be removed from the inventory or marked `sib_expected: false`, then `make refresh-alerts`. See [Falco liveness](grafana-alerts.md#falco-liveness).

---

## AI Analysis Issues

### Analysis Returns Empty

```bash
# With LLM_PROVIDER=ollama, check Ollama is running
curl http://localhost:11434/api/tags

# Check analysis service logs
make logs-analysis

# Test the API directly
curl "http://localhost:5000/health"
```

### Ollama Connection Refused

The analysis container must be able to reach Ollama. `localhost` is the container itself; the default `host.docker.internal` is the Docker host. Make Ollama listen on an address the container can reach (`OLLAMA_HOST`), set `OLLAMA_URL` in `.env` if it runs elsewhere, and firewall the port:

```bash
OLLAMA_URL=http://192.0.2.10:11434
```

Then run `make install-analysis`.

### Slow Analysis

- Use a smaller Ollama model (`OLLAMA_MODEL` in `.env`, for example `llama3.1:8b`), then `make install-analysis`
- Consider cloud LLM providers (OpenAI/Anthropic)

---

## Performance Issues

### High Memory Usage

```bash
# Check container memory
docker stats
```

The VM stack (default) uses less memory than the Grafana stack. To keep less data, see [retention settings](security-hardening.md#6-reduce-data-retention).

### Disk Space Full

```bash
# Check disk usage
df -h
sudo du -sh /var/lib/docker/*
docker system df -v

# Remove unused images, stopped containers and build cache (not volume data).
# Affects every project on this Docker host.
docker system prune -a
```

To free space used by logs and metrics, [reduce retention](security-hardening.md#6-reduce-data-retention).

### Slow Dashboard Loading

1. Reduce time range for queries
2. Add more specific filters

---

## Container Issues

### Container Keeps Restarting

```bash
# Check logs for the specific container
docker logs <container-name>

# Check exit code
docker inspect <container-name> --format='{{.State.ExitCode}}'

# Common causes:
# - Port already in use
# - Volume permission issues
# - Out of memory
```

### Port Already in Use

```bash
# Find what's using the port
sudo lsof -i :3000
sudo netstat -tulpn | grep 3000

# Change SIB ports in .env file
GRAFANA_PORT=3001
```

Re-run the component's install target (here `make install-grafana`). `make status`, `make health` and `./scripts/test-pipeline.sh` still check the default Grafana and Sidekick ports.

### Cannot Pull Images

```bash
# Check Docker Hub access
docker pull alpine

# If behind proxy, configure Docker
# /etc/docker/daemon.json
{
  "proxies": {
    "http-proxy": "http://proxy:8080",
    "https-proxy": "http://proxy:8080"
  }
}
```

---

## Getting Help

### Collect Diagnostic Information

```bash
# Create a diagnostic bundle
{
  echo "=== System Info ==="
  uname -a
  docker --version
  docker compose version
  
  echo "=== Container Status ==="
  docker ps -a | grep sib
  
  echo "=== Recent Logs ==="
  docker logs sib-falco --tail 20 2>&1
  docker logs sib-sidekick --tail 20 2>&1
  docker logs sib-victorialogs --tail 20 2>&1   # sib-loki on the grafana stack
  
  echo "=== Disk Usage ==="
  df -h
  
  echo "=== Memory ==="
  free -h
} > sib-diagnostics.txt
```

### Where to Get Help

- **GitHub Issues**: [github.com/matijazezelj/sib/issues](https://github.com/matijazezelj/sib/issues)
- **Email**: [sib@rtfm.hr](mailto:sib@rtfm.hr)

When reporting issues, please include:
1. SIB version (git commit hash)
2. Linux distribution and version
3. Kernel version (`uname -r`)
4. Docker version
5. Error messages from logs
6. Steps to reproduce

---

[← Back to Home](index.md)
