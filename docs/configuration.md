---
layout: default
title: Configuration - SIEM in a Box
---

# Configuration

SIB reads its settings from `.env` in the repository root. Start from the template:

```bash
cp .env.example .env
```

The defaults work for a single local host. This page lists the variables you are likely to change, grouped by purpose. `.env.example` is the full reference, with a comment on each variable.

[← Back to Home](index.md)

---

## Applying changes

Most settings are read when a stack is installed. After editing `.env`, re-run the install target for the part you changed, for example:

| You changed | Run |
|-------------|-----|
| Falco settings | `make install-detection` |
| Alert outputs, Falcosidekick settings | `make install-alerting` |
| Storage ports, retention, bind addresses | `make install-storage-vm` or `make install-storage-grafana` |
| Grafana settings, Grafana alert notifications | `make install-grafana` |
| AI analysis settings | `make install-analysis` |
| Several of these | `make install` |

See [Commands](commands.md) for the full list of targets.

## Stack selection

| Variable | Default | Description |
|----------|---------|-------------|
| `STACK` | `vm` | `vm`: VictoriaLogs + VictoriaMetrics + node_exporter. `grafana`: Loki + Prometheus. See [Architecture](architecture.md#storage-stacks). |

## Grafana

| Variable | Default | Description |
|----------|---------|-------------|
| `GRAFANA_ADMIN_PASSWORD` | `CHANGE_ME` | Admin password. Left empty or `CHANGE_ME`, a random one is generated into `.env` on install. Log in as `admin`. |
| `GRAFANA_BIND_ADDR` | `127.0.0.1` | Address Grafana listens on. Set `0.0.0.0` to reach it from the LAN. |
| `GRAFANA_PORT` | `3000` | Grafana port. |

Grafana alert notifications (`GRAFANA_ALERT_WEBHOOK_URL`, `GRAFANA_ALERT_WEBHOOK_TYPE`, `GRAFANA_ALERT_TELEGRAM_BOT_TOKEN`, `GRAFANA_ALERT_TELEGRAM_CHAT_ID`, `GRAFANA_HEARTBEAT_URL`, `GRAFANA_MANAGE_NOTIFICATION_POLICY`, `GRAFANA_METRICS_DS_UID`, `GRAFANA_LOGS_DS_UID`) are described in [Grafana Alerts](grafana-alerts.md).

## Falco

| Variable | Default | Description |
|----------|---------|-------------|
| `FALCO_VERSION` | `0.45.2` | Falco image version. |
| `FALCO_PRIORITY` | `notice` | Lowest rule priority Falco reports: `debug`, `info`, `notice`, `warning`, `error`, `critical`, `alert`, `emergency`. |
| `FALCO_BUFFERED_OUTPUTS` | `false` | Keep `false` for low-latency delivery. Buffered output can hold back sparse events. |
| `FALCO_TIME_FORMAT` | `iso8601` | `iso8601` or `rfc2822`. |
| `FALCO_DRIVER_TYPE` | auto | Not in `.env.example`. Detected on install (`modern_ebpf` on kernel 5.8+, `ebpf` otherwise) and written to `.env`. Set it to force a driver. |
| `SIDEKICK_URL` | `http://sib-sidekick:2801/` | Where Falco sends events. On a remote sensor, point it at the central server, e.g. `https://192.0.2.10:2801/`. |
| `FALCO_CLIENT_CERT_NAME` | `local` | Client certificate name under `certs/clients/` when mTLS is on. Use one per sensor. |

## Falcosidekick

| Variable | Default | Description |
|----------|---------|-------------|
| `SIDEKICK_BIND_ADDR` | `127.0.0.1` | Address Falcosidekick listens on. Set `0.0.0.0` only for remote Falco sensors, preferably with mTLS and a firewall. |
| `SIDEKICK_PORT` | `2801` | Falcosidekick port. |
| `SIDEKICK_MINIMUM_PRIORITY` | `notice` | Lowest priority forwarded. Also the default for each output's `*_MINIMUM_PRIORITY`. |
| `SIDEKICK_DEBUG` | `false` | Verbose Falcosidekick logging. |
| `SIDECAR_CONFIG_GID` | `1000` | Host group given read access to the generated `alerting/config/config.yaml` (see below). |

## Alert outputs

An output is enabled only when its URL or key is set. Each `*_MINIMUM_PRIORITY` defaults to `SIDEKICK_MINIMUM_PRIORITY`. Run `make install-alerting` after a change.

| Output | Variables |
|--------|-----------|
| Generic webhook | `WEBHOOK_ADDRESS`, `WEBHOOK_HEADER_NAME`, `WEBHOOK_HEADER_VALUE`, `WEBHOOK_MINIMUM_PRIORITY` |
| Slack | `SLACK_WEBHOOK_URL`, `SLACK_CHANNEL`, `SLACK_MINIMUM_PRIORITY` |
| Discord | `DISCORD_WEBHOOK_URL`, `DISCORD_MINIMUM_PRIORITY` |
| PagerDuty | `PAGERDUTY_ROUTING_KEY`, `PAGERDUTY_MINIMUM_PRIORITY` |
| Opsgenie | `OPSGENIE_API_KEY`, `OPSGENIE_REGION`, `OPSGENIE_MINIMUM_PRIORITY` |
| Microsoft Teams | `TEAMS_WEBHOOK_URL`, `TEAMS_MINIMUM_PRIORITY` |
| Telegram | `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_MINIMUM_PRIORITY` |
| Elasticsearch | `ELASTICSEARCH_HOST_PORT`, `ELASTICSEARCH_INDEX` |

Example:

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
SLACK_CHANNEL=#security-alerts
SLACK_MINIMUM_PRIORITY=warning

PAGERDUTY_ROUTING_KEY=your-routing-key
PAGERDUTY_MINIMUM_PRIORITY=critical
```

### Other Falcosidekick outputs

For any other Falcosidekick output, copy `alerting/config/custom-outputs.yaml.example` to `alerting/config/custom-outputs.yaml` and edit it. It is appended to the generated config and never overwritten.

> `alerting/config/config.yaml` is regenerated on every install. Do not edit it by hand.

### Authenticated webhooks and agent-driven triage

The generic webhook sends each Falco event to a URL with a static header:

```bash
WEBHOOK_ADDRESS=http://incident-handler.example:8644/webhooks/falco
WEBHOOK_HEADER_NAME=X-Gitlab-Token
WEBHOOK_HEADER_VALUE=replace-with-route-secret
WEBHOOK_MINIMUM_PRIORITY=warning
```

This suits event-driven agents such as Hermes Agent: Falcosidekick forwards the raw Falco event, the webhook starts an incident-triage run, and the agent can deliver its result to Telegram. Use HTTPS or a trusted management network, because the header secret is sent with every request.

For an agent-backed output, start at `critical` and keep lower-priority events in storage for periodic tuning. Don't call an LLM for every warning: normal NSS reads of `/etc/passwd`, healthcheck probes, package-maintenance traffic and high destination ports are high-volume telemetry, not incidents. Add exclusions only after correlating the exact rule, process, container and command over several occurrences, and never suppress a whole detection class only because remediation needs a human. The exclusions the bundled rules already carry are listed in [Detection Rules](detection.md#tuning-already-in-the-bundled-rules).

### Details of the generated config

- **Loki-compatible output.** Falcosidekick's Loki output uses a host-only `loki.hostport` and a separate endpoint: `/insert/loki/api/v1/push` for VictoriaLogs, `/loki/api/v1/push` for Loki. Putting `/insert` into `hostport` makes Falcosidekick append its default endpoint to the wrong path, and events silently stop being stored after a restart.
- **File mode.** The generated config holds output credentials and is mode `0640`, not `0600`. Falcosidekick runs as uid `1234`, so Compose adds `SIDECAR_CONFIG_GID` as a supplementary group. With `0600` the file is unreadable inside the container: Falcosidekick starts with no outputs while its `/ping` healthcheck stays green.

## Storage

### VictoriaMetrics stack (`STACK=vm`)

| Variable | Default | Description |
|----------|---------|-------------|
| `VICTORIALOGS_PORT` | `9428` | VictoriaLogs port. |
| `VICTORIALOGS_RETENTION_PERIOD` | `168h` | How long events and logs are kept. |
| `VICTORIAMETRICS_PORT` | `8428` | VictoriaMetrics port. |
| `VICTORIAMETRICS_RETENTION_PERIOD` | `15d` | How long metrics are kept. |
| `SYSLOG_BIND_ADDR` | `127.0.0.1` | Address of the VictoriaLogs UDP syslog listener. Set it to the server's LAN address to receive syslog from an appliance such as UniFi (feeds the UniFi Logs dashboard). |
| `SYSLOG_PORT` | `5514` | Syslog UDP port. Restrict it to approved senders with the host firewall. |
| `SYSLOG_TIMEZONE` | `UTC` | Timezone assumed for syslog timestamps. |

### Grafana stack (`STACK=grafana`)

| Variable | Default | Description |
|----------|---------|-------------|
| `LOKI_PORT` | `3100` | Loki port. Loki retention is set in `storage/config/loki-config.yml` (`retention_period`). |
| `PROMETHEUS_PORT` | `9090` | Prometheus port. |
| `PROMETHEUS_RETENTION_TIME` | `15d` | Metrics retention by age. |
| `PROMETHEUS_RETENTION_SIZE` | `5GB` | Metrics retention by size. |

### Both stacks

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_BIND` | `127.0.0.1` | Address the storage APIs listen on. `make enable-remote` sets it to `0.0.0.0` so remote collectors can write. |

## Component versions

Image versions are pinned in `.env.example`: `FALCO_VERSION`, `VICTORIALOGS_VERSION`, `VICTORIAMETRICS_VERSION`, `VMAGENT_VERSION`, `NODE_EXPORTER_VERSION`, `VECTOR_VERSION`, `ALLOY_VERSION` and `SIB_ANSIBLE_VERSION`. See the [Upgrade Guide](upgrade.md) before changing them.

## mTLS

| Variable | Default | Description |
|----------|---------|-------------|
| `MTLS_ENABLED` | `false` | Require client certificates between Falco sensors and Falcosidekick. Run `make generate-certs` first. |
| `SIB_SERVER_IP` | auto | Not in `.env.example`. Set it when running `scripts/generate-certs.sh` to put a specific server IP in the certificate, e.g. `SIB_SERVER_IP=192.0.2.10 ./scripts/generate-certs.sh`. |

See [Security Hardening](security-hardening.md) and [Fleet Management](fleet.md) for the certificate workflow.

## AI analysis (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `anthropic` | `anthropic`, `openai` or `ollama`. |
| `ANALYSIS_BIND` | `127.0.0.1` | Address the Analysis API listens on. |
| `ANALYSIS_PORT` | `5000` | Analysis API port. |
| `ANALYSIS_HOST` | auto | Host used in Grafana's "Analyze with AI" links. Detected if empty. |
| `ANALYSIS_API_TOKEN` | `CHANGE_ME` | Shared secret for every endpoint except `/health`. Generated by `make install-analysis` if left as `CHANGE_ME`. |
| `ANALYSIS_CORS_ORIGINS` | empty | Comma-separated origins allowed to call the API cross-origin. |
| `ANTHROPIC_API_KEY` | | Anthropic API key. |
| `ANTHROPIC_MODEL` | empty | Unset: start on Haiku 5.5 and escalate answers that fail validation. Set to pin one model. |
| `ANTHROPIC_EFFORT` | `medium` | Effort level for Anthropic requests. |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | `gpt-4o` | OpenAI key and model. |
| `OLLAMA_URL`, `OLLAMA_MODEL` | `qwen2.5:14b` | Local Ollama endpoint and model. |
| `AIB_BASE_URL`, `AIB_API_TOKEN` | empty | Optional asset enrichment from Assets in a Box. See [AIB Integration](aib-integration.md). |

`ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `ANALYSIS_API_TOKEN` can also be read from files through `ANTHROPIC_API_KEY_FILE`, `OPENAI_API_KEY_FILE` and `ANALYSIS_API_TOKEN_FILE` (see [Security Hardening](security-hardening.md)). More on providers and the token in [AI Analysis](ai-analysis.md).

## Threat intel

These are read by `make update-threatintel` and are not in `.env.example`:

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_THREATINTEL_IPS` | `10000` | Most IP addresses loaded into the generated Falco rule. |
| `MAX_THREATINTEL_NETS` | `2000` | Most network ranges loaded into the generated Falco rule. |

See [Threat Intelligence](threat-intel.md).

## Bind addresses at a glance

Every listener binds to `127.0.0.1` by default. Open one up only on purpose:

| Variable | Service |
|----------|---------|
| `GRAFANA_BIND_ADDR` | Grafana |
| `SIDEKICK_BIND_ADDR` | Falcosidekick (remote Falco sensors) |
| `STORAGE_BIND` | VictoriaLogs/VictoriaMetrics or Loki/Prometheus (remote collectors) |
| `SYSLOG_BIND_ADDR` | VictoriaLogs syslog listener |
| `ANALYSIS_BIND` | AI Analysis API |

If remote Falco sensors send events to Falcosidekick on port 2801, require mTLS with a separate client certificate per sensor and allow only each sensor's address through the firewall, not a whole subnet:

```bash
SIB_SERVER_IP=192.0.2.10 ./scripts/generate-certs.sh
./scripts/generate-client-cert.sh web-01
# UFW: one approved sensor
ufw allow from 192.0.2.21 to any port 2801 proto tcp
```

On each remote sensor set `SIDEKICK_URL=https://<central-host>:2801/`, `FALCO_CLIENT_CERT_NAME=<sensor-name>` and `MTLS_ENABLED=true`. Copy only the CA certificate and that sensor's certificate and key to its `certs/` directory. Deploy central storage and Falcosidekick once, and run one Falco sensor per independent kernel.

---

[← Back to Home](index.md)
