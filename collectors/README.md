# 📡 Collectors

Deploy lightweight telemetry collectors to remote hosts to ship logs and metrics to SIB.

These are collectors only. To also deploy Falco and manage many hosts, use [fleet management](../docs/fleet.md) (`make deploy-fleet`).

## Stack Options

Choose the collector stack that matches your SIB server:

| SIB Stack | Collector Stack | Components | Compose File |
|-----------|-----------------|------------|--------------|
| `vm` (default) | VM Collectors | vmagent + node_exporter + Vector | `compose-vm.yaml` |
| `grafana` | Alloy | Grafana Alloy | `compose-grafana.yaml` |

## What Gets Collected

### Logs
- System, auth and kernel logs (`/var/log/syslog`, `messages`, `auth.log`, `secure`, `kern.log`)
- Journal logs (systemd)
- Docker container logs

### Metrics
- CPU, memory, disk, network
- System load, uptime
- Filesystem usage

## Quick Deploy

### 1. Configure SIB for Remote Connections

On your SIB server, expose the storage ports:
```bash
cd /path/to/sib
make enable-remote
```

### 2. Deploy Collector to Remote Host

```bash
# From SIB directory; the stack comes from STACK in .env
./collectors/scripts/deploy.sh user@remote-host sib-server-ip

# Or, using this server's first IP address
make deploy-collector HOST=user@remote-host
```

On the VM stack the script writes `SIB_SERVER` to `~/sib-collector/.env` on the remote host; vmagent sends metrics there.

### 3. Verify Connection

Check the Fleet Overview dashboard in Grafana.

---

## Grafana Stack Collectors (Alloy)

[Grafana Alloy](https://grafana.com/docs/alloy/latest/) is a unified telemetry collector that handles:
- Log collection (replaces Promtail)
- System metrics (replaces node_exporter)
- OpenTelemetry traces

### Docker Deployment

```bash
# On the remote host, in a copy of this collectors/ directory (not on the SIB server)
cd collectors
export SIB_SERVER=192.168.1.100   # your SIB server IP
export HOSTNAME=$(hostname)

# Edit config to set SIB_SERVER_IP
sed -i "s/SIB_SERVER_IP/$SIB_SERVER/g" config/config.alloy

# Start
docker compose -f compose-grafana.yaml up -d
```

### Configuration

`config/config.alloy` sends logs to Loki (`:3100`) and metrics to Prometheus (`:9090`) at `SIB_SERVER_IP`, which the `sed` above (or `deploy.sh`) replaces.

---

## VM Stack Collectors (vmagent + Vector)

For the VictoriaMetrics ecosystem, use lightweight VM-native collectors:

- **vmagent**: Scrapes node_exporter and sends to VictoriaMetrics
- **node_exporter**: Exports host metrics
- **Vector**: Collects logs and sends to VictoriaLogs

### Docker Deployment

```bash
# On the remote host, in a copy of this collectors/ directory (not on the SIB server)
cd collectors
# Set your SIB server IP and hostname
export SIB_SERVER=192.168.1.100
export HOSTNAME=$(hostname)

# Start
docker compose -f compose-vm.yaml up -d

# If node_exporter already runs on the host
docker compose -f compose-vm.yaml up -d --scale node-exporter=0
```

### Configuration

#### vmagent (`config/vmagent.yml`)
```yaml
global:
  scrape_interval: 30s

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
```

#### Vector (`config/vector.toml`)

Sends to VictoriaLogs at `http://${SIB_SERVER}:9428/insert/jsonline`. Logs are tagged with a `host` field. Fleet Overview log panels filter on `hostname` (which Ansible-deployed collectors set), so they don't include these logs.

---

## Native Installation

For agents without Docker, use [fleet management](../docs/fleet.md) with the Grafana stack and `deployment_strategy: native`. The VM stack collectors need Docker.

---

## Troubleshooting

### Check Collector Status

```bash
# Alloy
docker logs sib-alloy
curl http://localhost:12345/metrics

# vmagent  
docker logs sib-vmagent
curl http://localhost:8429/targets

# Vector
docker logs sib-vector
```

### Test Connectivity

```bash
# VM stack
curl http://SIB_SERVER:9428/health    # VictoriaLogs
curl http://SIB_SERVER:8428/health    # VictoriaMetrics

# Grafana stack
curl http://SIB_SERVER:3100/ready     # Loki
curl http://SIB_SERVER:9090/-/ready   # Prometheus
```
