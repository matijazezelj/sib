# Alerting Stack

This directory contains Falcosidekick and its UI for forwarding Falco alerts to various outputs.

## Components

| Service | Port | Description |
|---------|------|-------------|
| **Falcosidekick** | 2801 | Alert forwarding daemon |
| **Falcosidekick UI** | 2802 | Web UI for viewing events |

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

Edit `config/config.yaml` to configure outputs.

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
  type: "_doc"
```

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Main endpoint for Falco events |
| `/healthz` | Health check |
| `/test` | Generate test event |
| `/metrics` | Prometheus metrics |

## Testing

Generate a test alert:
```bash
curl -X POST http://localhost:2801/test
```

## UI Access

Open http://localhost:2802 to view the Falcosidekick UI.
