# Alerting Stack

This directory contains Falcosidekick for forwarding Falco alerts to various outputs.

## Components

| Service | Port | Description |
|---------|------|-------------|
| **Falcosidekick** | 2801 | Alert forwarding daemon |

## What is Falcosidekick?

Falcosidekick is a simple daemon that takes Falco events and forwards them to different outputs. It supports 50+ destinations including:

### Chat
- Slack, Discord, Teams, Mattermost, Telegram

### Alerting
- PagerDuty, Opsgenie, AlertManager

### Logs/SIEM
- Elasticsearch, Loki, Splunk, Datadog

### Message Queues
- Kafka, NATS, RabbitMQ, SQS

### Serverless
- AWS Lambda, GCP Cloud Functions

## Configuration

`config/config.yaml` is generated from `.env` on every install, so don't edit it. Events always go to the log storage for your `STACK` (VictoriaLogs or Loki). Set the common outputs (Slack, Discord, PagerDuty, Opsgenie, Teams, Telegram, Elasticsearch, generic webhook) in `.env`, then run `make install-alerting`; `.env.example` lists the variables. A half-configured Telegram output (token without chat ID, or the other way round) fails `make install-alerting` instead of being skipped. Every event Falcosidekick forwards carries Falco's full output (command lines, paths, users); see [docs/grafana-alerts.md](../docs/grafana-alerts.md#notifications) before sending it to an external chat, and put any other output in `config/custom-outputs.yaml` (copy from `custom-outputs.yaml.example`); it is appended to the generated config.

The snippets below show the Falcosidekick settings that end up in the generated config.

### Example: Slack
```yaml
slack:
  webhookurl: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
  channel: "#security-alerts"
  minimumpriority: "warning"
```

### Example: Elasticsearch
```yaml
elasticsearch:
  hostport: "http://elasticsearch:9200"
  index: "falco"
```

### Server settings

| `.env` variable | Default | Purpose |
|---|---|---|
| `SIDEKICK_BIND_ADDR` | `127.0.0.1` | Set `0.0.0.0` for fleet sensors |
| `SIDEKICK_PORT` | `2801` | Published port |
| `SIDEKICK_MINIMUM_PRIORITY` | `notice` | Minimum priority to forward |
| `SIDEKICK_DEBUG` | `false` | Debug logging |
| `SIDECAR_CONFIG_GID` | `1000` | Host group that can read `config.yaml`; use one you belong to (`id -g`) |

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Main endpoint for Falco events |
| `/healthz` | Health check |
| `/test` | Generate test event |
| `/metrics` | Prometheus metrics |

## mTLS Configuration

For production deployments, enable mTLS to require client certificate authentication.

### Enable mTLS

```bash
# Generate certificates (if not already done)
make generate-certs

# Set these two in .env
#   MTLS_ENABLED=true
#   SIDEKICK_URL=https://sib-sidekick:2801/

# Reinstall Sidekick, Falco (its client) and storage (it scrapes /metrics)
make install-alerting
make install-detection
make install-storage-vm   # or install-storage-grafana
```

### Configuration

When `MTLS_ENABLED=true`, Falcosidekick is configured with:

```yaml
tlsserver:
  deploy: true
  certfile: /certs/server/server.crt
  keyfile: /certs/server/server.key
  mutualtls: true
  cacertfile: /certs/ca/ca.crt
```

### Test mTLS Connection

```bash
# Without client cert (should fail)
curl https://localhost:2801/healthz --cacert certs/ca/ca.crt

# With client cert (should succeed)
curl https://localhost:2801/healthz \
  --cacert certs/ca/ca.crt \
  --cert certs/clients/local.crt \
  --key certs/clients/local.key
```

See [Security Hardening](../docs/security-hardening.md) for complete mTLS documentation.

---

## Testing

Generate a test alert with `make test-alert`, or directly:
```bash
# HTTP mode
curl -X POST http://localhost:2801/test

# mTLS mode
curl -X POST https://localhost:2801/test \
  --cacert certs/ca/ca.crt \
  --cert certs/clients/local.crt \
  --key certs/clients/local.key
```
