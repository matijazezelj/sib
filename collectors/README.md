# 📡 Collectors - Grafana Alloy

Deploy lightweight telemetry collectors to remote hosts to ship logs and metrics to SIB.

## Overview

[Grafana Alloy](https://grafana.com/docs/alloy/latest/) is a unified telemetry collector that replaces:
- Promtail (log collection)
- Node Exporter (system metrics)
- OpenTelemetry Collector (traces)

Single binary, single config, ships everything to your central SIB instance.

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

### 2. Deploy Alloy to Remote Host

```bash
# From SIB directory
./collectors/scripts/deploy.sh user@remote-host sib-server-ip
```

### 3. Verify Connection

Check the Fleet Overview dashboard in Grafana.

## Manual Installation

### On Remote Host

```bash
# Install Alloy
curl -fsSL https://apt.grafana.com/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y alloy

# Copy config (edit SIB_SERVER_IP first)
sudo cp config.alloy /etc/alloy/config.alloy
sudo systemctl enable --now alloy
```

### Docker Deployment

```bash
docker compose up -d
```

## Configuration

Edit `config/config.alloy` to customize:

```alloy
// Change the SIB server address
loki.write "default" {
  endpoint {
    url = "http://YOUR_SIB_SERVER:3100/loki/api/v1/push"
  }
}

prometheus.remote_write "default" {
  endpoint {
    url = "http://YOUR_SIB_SERVER:9090/api/v1/write"
  }
}
```

### Adding Custom Log Paths

```alloy
local.file_match "app_logs" {
  path_targets = [
    {__path__ = "/var/log/myapp/*.log", job = "myapp"},
  ]
}

loki.source.file "app_logs" {
  targets    = local.file_match.app_logs.targets
  forward_to = [loki.write.default.receiver]
}
```

## Troubleshooting

```bash
# Check Alloy status
sudo systemctl status alloy

# View Alloy logs
sudo journalctl -u alloy -f

# Test connectivity to SIB
curl -s http://SIB_SERVER:3100/ready
curl -s http://SIB_SERVER:9090/-/ready
```
