# 📡 Collectors

Deploy lightweight telemetry collectors to remote hosts to ship logs and metrics to SIB.

## Stack Options

Choose the collector stack that matches your SIB server:

| SIB Stack | Collector Stack | Components | Compose File |
|-----------|-----------------|------------|--------------|
| `grafana` | Alloy | Grafana Alloy | `compose-grafana.yaml` |
| `vm` | VM Collectors | vmagent + node_exporter + Vector | `compose-vm.yaml` |

## What Gets Collected

### Logs
- System logs (`/var/log/syslog`, `/var/log/auth.log`)
- Journal logs (systemd)
- Docker container logs
- Custom application logs

### Metrics
- CPU, memory, disk, network
- System load, uptime
- Filesystem usage
- Network connections

## Quick Deploy

### 1. Configure SIB for Remote Connections

On your SIB server, enable external access:
```bash
cd /path/to/sib
make enable-remote
```

### 2. Deploy Collector to Remote Host

```bash
# From SIB directory
./collectors/scripts/deploy.sh user@remote-host sib-server-ip
```

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
# Set your SIB server IP
export SIB_SERVER=192.168.1.100

# Edit config to set SIB_SERVER_IP
sed -i "s/SIB_SERVER_IP/$SIB_SERVER/g" config/config.alloy

# Start
docker compose -f compose-grafana.yaml up -d
```

### Configuration

Edit `config/config.alloy`:

```alloy
// Ship logs to Loki
loki.write "default" {
  endpoint {
    url = "http://YOUR_SIB_SERVER:3100/loki/api/v1/push"
  }
}

// Ship metrics to Prometheus
prometheus.remote_write "default" {
  endpoint {
    url = "http://YOUR_SIB_SERVER:9090/api/v1/write"
  }
}
```

---

## VM Stack Collectors (vmagent + Vector)

For the VictoriaMetrics ecosystem, use lightweight VM-native collectors:

- **vmagent**: Scrapes node_exporter and sends to VictoriaMetrics
- **node_exporter**: Exports host metrics
- **Vector**: Collects logs and sends to VictoriaLogs

### Docker Deployment

```bash
# Set your SIB server IP and hostname
export SIB_SERVER=192.168.1.100
export HOSTNAME=$(hostname)

# Start
docker compose -f compose-vm.yaml up -d
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
```toml
# Ship logs to VictoriaLogs
[sinks.victorialogs]
type = "http"
uri = "http://${SIB_SERVER}:9428/insert/jsonline?_stream_fields=host,collector&_msg_field=message"
```

---

## Manual Installation

### Native Alloy Install (systemd)

```bash
# Install Alloy
curl -fsSL https://apt.grafana.com/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y alloy

# Copy config (edit SIB_SERVER_IP first)
sudo cp config/config.alloy /etc/alloy/config.alloy
sudo systemctl enable --now alloy
```

### Native node_exporter Install

```bash
# Download and install
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xzf node_exporter-*.tar.gz
sudo mv node_exporter-*/node_exporter /usr/local/bin/

# Create systemd service
sudo tee /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now node_exporter
```

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
# Test log endpoint (Grafana stack)
curl -X POST http://SIB_SERVER:3100/loki/api/v1/push \
  -H "Content-Type: application/json" \
  -d '{"streams":[{"labels":"{test=\"true\"}","entries":[{"ts":"2024-01-01T00:00:00Z","line":"test"}]}]}'

# Test log endpoint (VM stack)
curl -X POST "http://SIB_SERVER:9428/insert/jsonline" \
  -d '{"message":"test","host":"test"}'

# Test metrics endpoint
curl http://SIB_SERVER:8428/api/v1/write
```
