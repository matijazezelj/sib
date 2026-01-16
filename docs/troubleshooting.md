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
1. Disable unused rules in `detection/config/rules/`
2. Increase rule buffer size in `detection/config/falco.yaml`
3. Use output rate limiting

### No Falco Events

```bash
# Generate a test event
make test-alert

# Check if Falco sees it
docker logs sib-falco --tail 20

# Verify syscall source is working
docker exec sib-falco falco --list
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

3. **Check Loki is storing**:
   ```bash
   curl -s "http://localhost:3100/loki/api/v1/query?query={source=\"syscall\"}" | jq '.data.result | length'
   ```

4. **Check Grafana datasource**:
   - Go to Grafana → Settings → Data sources → Loki
   - Click "Test" button

### Loki Query Returns Empty

```bash
# Check Loki is healthy
curl http://localhost:3100/ready

# Check what labels exist
curl http://localhost:3100/loki/api/v1/labels

# Try a simple query
curl -G http://localhost:3100/loki/api/v1/query --data-urlencode 'query={job=~".+"}'
```

### Sidekick Not Forwarding

Check configuration in `alerting/config/config.yaml`:
```yaml
loki:
  hostport: http://loki:3100
  # Ensure this matches your Loki service name
```

Restart after changes:
```bash
docker compose -f alerting/compose.yaml restart
```

---

## Dashboard Issues

### Dashboards Missing

```bash
# Check dashboard provisioning
docker logs sib-grafana | grep -i dashboard

# Re-provision dashboards
docker compose -f grafana/compose.yaml restart
```

### Dashboards Show "No Data"

1. **Check time range**: Ensure it covers when events occurred
2. **Check datasource**: Verify Loki datasource is working
3. **Generate events**: Run `make demo` to create test data
4. **Check query**: Open panel → Edit → check for errors

### Grafana Won't Start

```bash
# Check logs
docker logs sib-grafana

# Common issues:
# - Port 3000 already in use
# - Permission issues on data directory

# Try with fresh data
docker volume rm sib_grafana_data
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

### Alloy Not Sending Data

On the remote host:
```bash
# Check Alloy logs
docker logs sib-alloy --tail 50

# Or for native deployment
journalctl -u alloy -n 50

# Verify network connectivity to SIB server
curl -s http://SIB_SERVER:3100/ready
curl -s http://SIB_SERVER:9090/-/ready
```

### Fleet Host Not Appearing

1. Check the collector is running on remote host
2. Verify firewall allows traffic to SIB server ports (3100, 9090, 2801)
3. Check `host` label in Loki:
   ```bash
   curl http://localhost:3100/loki/api/v1/label/host/values
   ```

---

## AI Analysis Issues

### Analysis Returns Empty

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Check analysis service logs
make logs-analysis

# Test the API directly
curl "http://localhost:5000/health"
```

### Ollama Connection Refused

Ensure Ollama is accessible from Docker:
```bash
# Check analysis/config.yaml
# Use host.docker.internal for Ollama on host machine
llm:
  base_url: http://host.docker.internal:11434
```

### Slow Analysis

- Use smaller models (`llama3.1:8b` instead of larger)
- Enable caching in config
- Consider cloud LLM providers (OpenAI/Anthropic)

---

## Performance Issues

### High Memory Usage

```bash
# Check container memory
docker stats

# Reduce Loki retention
# Edit storage/config/loki-config.yml
retention_period: 168h  # Reduce from default

# Limit Prometheus retention
# Edit storage/config/prometheus.yml
storage.tsdb.retention.time: 7d
```

### Disk Space Full

```bash
# Check disk usage
df -h
du -sh /var/lib/docker/*

# Clean up old data
docker system prune -a

# Reduce log retention (see above)
```

### Slow Dashboard Loading

1. Reduce time range for queries
2. Add more specific label filters
3. Increase Grafana memory limit in compose.yaml

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
  docker logs sib-loki --tail 20 2>&1
  
  echo "=== Disk Usage ==="
  df -h
  
  echo "=== Memory ==="
  free -h
} > sib-diagnostics.txt
```

### Where to Get Help

- **GitHub Issues**: [github.com/matijazezelj/sib/issues](https://github.com/matijazezelj/sib/issues)
- **Reddit**: [u/matijaz](https://reddit.com/u/matijaz)

When reporting issues, please include:
1. SIB version (git commit hash)
2. Linux distribution and version
3. Kernel version (`uname -r`)
4. Docker version
5. Error messages from logs
6. Steps to reproduce

---

[← Back to Home](index.md)
