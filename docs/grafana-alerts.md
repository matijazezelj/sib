---
layout: default
title: Grafana Alerts - SIEM in a Box
---

# Grafana Alerts

Falcosidekick forwards every Falco event to Slack, PagerDuty and its other
outputs. Grafana alerts cover what single events can't show: a sensor that
stopped reporting, a broken delivery path, a burst of detections, a disk
filling up.

`make install-grafana` provisions these rules into the **SIB** folder
(Grafana → Alerting → Alert rules), using the queries for your `STACK`.

## Rules

| Group | Rule | Fires when | Severity |
|-------|------|------------|----------|
| Fleet | Falco not reporting | An expected host's Falco hasn't been scraped successfully for 5 minutes (see [Falco liveness](#falco-liveness)) | critical |
| Pipeline health | Falco dropping syscall events | A host reports `Falco internal: syscall event drop` in 15 minutes | warning |
| | Falcosidekick output errors | An output (Slack, Loki, ...) failed a delivery in 15 minutes | warning |
| | Falcosidekick down | Sidekick can't be scraped for 5 minutes | critical |
| Detection | Burst of Critical/Error events | More than 10 Critical/Error events on one host in 10 minutes | critical |
| | Critical Falco event | Any Critical event (**paused**, see below) | critical |
| Detection baselines (every 5 min) | Event spike on a host | More than 50 events in 10 minutes and 5× the host's 24-hour average | warning |
| | Rule firing far above normal | Same, per rule | warning |
| Resources | Disk almost full | A filesystem over 85% for 10 minutes | warning |
| | Memory usage high | Memory over 90% for 15 minutes | warning |
| | Storage backend down | VictoriaLogs/VictoriaMetrics (or Loki/Prometheus) unreachable for 5 minutes | critical |
| HIB | HIB critical security event, authentication failures, agent denials burst, sandbox unavailable | from [HIB](https://github.com/matijazezelj/hib)'s event log, see [HIB Integration](hib-integration.md) | critical / warning |

Disk and memory rules cover the SIB server on the VM stack and every fleet host
that ships metrics.

**Critical Falco event** is paused because Falcosidekick already sends each
event. If Grafana is your only notification channel, set `isPaused: false` on
the `sib-critical-event` rule in the template for your stack (see
[Tuning](#tuning)) and re-run `make install-grafana`.

## Falco liveness

SIB can't tell a quiet host from a dead one by looking at events: Falco only
sends something when a rule matches. So liveness comes from Falco's own
metrics endpoint instead:

- **Observed:** every Falco serves `/metrics` (on fleet hosts only on
  `127.0.0.1:8765`). Each fleet host's collector (vmagent or Alloy) scrapes it
  and pushes `up{job="falco", host="<inventory name>"}` to SIB; SIB scrapes its
  own Falco as `host="sib-host"`.
- **Expected:** the hosts in the `fleet` group of
  `ansible/inventory/hosts.yml`, plus `sib-host` when local detection is
  installed. The list is read from the inventory, not from the hosts, so a host
  that is offline stays expected.

A host that is expected but not observed fires **Falco not reporting**, and
keeps firing for as long as it is down: Falco stopped, its collector stopped,
or the host is offline.

- `make deploy-fleet` refreshes the list automatically. After editing the
  inventory by hand, run `make refresh-alerts` (it reloads Grafana without a
  restart).
- **Retiring a host:** remove it from the inventory (after `make remove-fleet
  LIMIT=<host>`, if it still runs SIB agents) and run `make refresh-alerts`.
  The alert stops right away.
- **A fleet host without Falco** (an LXC container, a collector-only box): set
  `sib_expected: false` on it in the inventory.

Existing fleet hosts need one `make deploy-fleet` after upgrading, to enable
Falco's metrics endpoint and the collector's `falco` scrape job.

## Notifications

Set a webhook in `.env` and re-run `make install-grafana`:

```bash
# Slack incoming webhook (default type)
GRAFANA_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Or Grafana's generic JSON webhook to any URL
GRAFANA_ALERT_WEBHOOK_URL=https://alerts.example.com/hook
GRAFANA_ALERT_WEBHOOK_TYPE=webhook

# Telegram, as well as or instead of the webhook
GRAFANA_ALERT_TELEGRAM_BOT_TOKEN=123456789:replace-with-bot-token
GRAFANA_ALERT_TELEGRAM_CHAT_ID=-1001234567890
```

For Telegram, create a bot with [@BotFather](https://t.me/BotFather), add it to
the group or channel, and use that chat's ID (groups and channels have negative
IDs; a channel's `@name` works too). Webhook and Telegram are two integrations
on the same `sib-alerts` contact point, so every alert goes to both. Like the
webhook URL, the bot token is read from Grafana's environment and never written
to the provisioning files.

**Grafana alerts and Falcosidekick events are two different streams.**
Falcosidekick's Telegram output (`TELEGRAM_TOKEN` / `TELEGRAM_CHAT_ID`, see
`alerting/README.md`) sends every Falco event at or above
`TELEGRAM_MINIMUM_PRIORITY`. Grafana sends the alerts above: bursts, a sensor
gone silent, a full disk. Pointed at the same chat, one incident can produce
both a stream of single detections and an aggregate alert. Decide that on
purpose. A separate chat per stream is usually easier to read, or keep
Falcosidekick at `TELEGRAM_MINIMUM_PRIORITY=critical`.

**What leaves your network.** A Falcosidekick event carries Falco's full
output: command lines, file paths, user names, container and image names, and
IPs. SIB's AI-analysis obfuscation does not apply to Falcosidekick outputs.
Telegram bot chats are not end-to-end encrypted, so that text is stored on
Telegram's servers and readable by everyone in the chat. Grafana alerts carry
less: the rule's summary, host name, Falco rule name and counts, not command
lines. Choose who is in the chat accordingly.

**Check delivery before relying on it.**

- Grafana: Alerting → Contact points → `sib-alerts` → **Test**. This sends a
  test notification through every integration on it. For a real alert with
  recovery: stop Falco on a test host (`docker stop sib-falco`); after about
  5 minutes **Falco not reporting** arrives. Start it again, and the resolved
  message follows within a minute or two.
- Falcosidekick: `make test-alert`. Falcosidekick sends its test event to
  Telegram whatever `TELEGRAM_MINIMUM_PRIORITY` is set to.

This provisions a `sib-alerts` contact point and a notification policy:

| Severity | First notification | Repeated while firing |
|----------|--------------------|-----------------------|
| critical | after 10 seconds | every hour |
| warning | after 1 minute | every 4 hours |

Alerts are grouped per rule and per host (`hostname` for log-based rules,
`host` for metrics), so one host's burst doesn't hide another's. Alerts without
a host label are grouped per rule.

Without a webhook or Telegram configured, the rules still evaluate and show
their state in Grafana, but nobody is notified. For email, PagerDuty or other
channels, add a contact point in the Grafana UI instead.

Notification policies are organisation-wide, so SIB is careful with them:

- With a webhook, Telegram or `GRAFANA_HEARTBEAT_URL` configured, SIB
  provisions the whole policy tree above. A policy you built in the UI is
  replaced (your contact points are kept).
- With none of them set, SIB leaves the policy alone, so routing you manage
  yourself survives `make install-grafana`.
- Removing all of them after SIB managed the policy hands it back as
  Grafana's default policy and deletes SIB's contact points.
- With `GRAFANA_MANAGE_NOTIFICATION_POLICY=false`, SIB never touches the policy,
  even with a webhook or Telegram set. Use this on a Grafana that also serves other
  teams or systems; see [Shared or external Grafana](#shared-or-external-grafana).

Settings are read when the container starts. `make install-grafana` recreates
it, so changing `.env` and re-running the target is enough.

## External heartbeat

Grafana can't tell you that Grafana is down. Point an external monitor at it:

```bash
GRAFANA_HEARTBEAT_URL=https://uptime.example.com/api/push/XXXXXXXX
```

`make install-grafana` then adds an always-firing **SIB heartbeat** rule that
Grafana POSTs to that URL every 5 minutes. Create a push/heartbeat check in
your external monitor (Uptime Kuma push monitor, Healthchecks.io, ...) with a
period above 5 minutes, e.g. 10. It alerts when the pings stop: Grafana down,
alert evaluation stuck, or the metrics store unreachable (the heartbeat
queries it).

## Shared or external Grafana

On a Grafana that SIB doesn't own (shared with other teams, or SIB's rules
loaded into an existing Grafana), set in `.env`:

```bash
GRAFANA_MANAGE_NOTIFICATION_POLICY=false
# Datasource UIDs as named in that Grafana (defaults: prometheus, and
# victorialogs or loki depending on STACK)
GRAFANA_METRICS_DS_UID=sib-victoriametrics
GRAFANA_LOGS_DS_UID=victorialogs
# Optional, as above
GRAFANA_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
GRAFANA_HEARTBEAT_URL=https://uptime.example.com/api/push/XXXXXXXX
```

Then run `make refresh-alerts` (or `./scripts/generate-grafana-alerting.sh`
with those variables set). It writes into `grafana/provisioning/alerting/`:

| File | Contents |
|------|----------|
| `alert-rules.yml` | SIB's rules, pointing at your datasource UIDs |
| `falco-liveness.yml` | Falco not reporting, for the expected hosts |
| `heartbeat.yml` | SIB heartbeat (only with `GRAFANA_HEARTBEAT_URL`) |
| `notifications.yml` | contact points `sib-alerts` (webhook and/or Telegram integrations) / `sib-heartbeat`, plus deletions of SIB's own retired rules |

For an external Grafana, copy those files into its `provisioning/alerting/`
directory and set `GRAFANA_ALERT_WEBHOOK_URL` / `GRAFANA_HEARTBEAT_URL` in that
Grafana's environment: the contact points read the URLs from there, so the
URLs never land in the files.

In this mode SIB writes no `policies`, never `resetPolicies`, and never deletes
a contact point, not even its own. Grafana refuses to delete a contact point
that a policy still routes to, and your routes may point at SIB's. Nothing is
merged into your policy tree. Add two child routes to it yourself
(Alerting → Notification policies → New child policy), heartbeat first:

| Order | Matcher | Contact point | Timing |
|-------|---------|---------------|--------|
| 1 | `alertname = SIB heartbeat` | `sib-heartbeat` | group wait 0s, group interval 1m, repeat 5m; no other routes after it (turn off "continue matching") |
| 2 | `source = sib` | `sib-alerts` | group by `alertname`, `hostname`, `host`; repeat e.g. 1h for `severity = critical`, 4h for `warning` (optional nested routes) |

Every SIB rule carries `source=sib`. The heartbeat carries
`source=sib-heartbeat`, so the `source = sib` route can't send it to Slack
every 5 minutes even if the routes end up in a different order.

To retire SIB's notifications in this mode: remove the two routes, unset the
URLs, re-run `make refresh-alerts`, then delete the `sib-alerts` and
`sib-heartbeat` contact points in the UI.

### Falcosidekick metric names

The *Falcosidekick output errors* rule matches both metric names in use:
`falcosidekick_outputs` (Falcosidekick 2.29, which SIB ships) and
`falcosecurity_falcosidekick_outputs_total` (newer releases; checked on
2.35.0). *Falcosidekick down* uses `up{job="falcosidekick"}`, so the scrape
job must be called `falcosidekick`.

### Scraping Falcosidekick over mTLS

With mTLS on (`MTLS_ENABLED=true`, or your own TLS setup), Falcosidekick's
single listener requires a client certificate, so a plain `http://` scrape of
`:2801/metrics` fails and *Falcosidekick down* fires. Scrape it with a client
certificate instead of loosening the listener (no `insecure_skip_verify`, no
separate plain-HTTP port):

```yaml
  - job_name: 'falcosidekick'
    scheme: https
    metrics_path: '/metrics'
    tls_config:
      ca_file: /certs/ca/ca.crt
      cert_file: /certs/clients/metrics-scraper.crt
      key_file: /certs/clients/metrics-scraper.key
      # Must match a name in the server certificate. SIB's has sib-sidekick
      # (scripts/generate-certs.sh); set server_name if you scrape by IP.
      server_name: sib-sidekick
    static_configs:
      - targets: ['sib-sidekick:2801']
        labels:
          instance: 'sib-sidekick'
```

This works in both `prometheus.yml` and VictoriaMetrics' `-promscrape.config`.
Mount the certificates read-only into the scraper (for SIB's storage
containers: `../certs:/certs:ro`). Prefer a dedicated client certificate for
the scraper over reusing `local`: `make generate-client-cert HOST=metrics-scraper`
writes `certs/clients/metrics-scraper.{crt,key}`. The key is created `0600`, so
make it readable by the scraper's user without making it world-readable
(Prometheus' image runs as `nobody`, for example: `chown 65534`).

SIB's own storage stack does all of this automatically. With
`MTLS_ENABLED=true`, `make install-storage-vm` / `install-storage-grafana`
create the `metrics-scraper` certificate if needed, copy only `ca.crt` and that
certificate and key into a per-stack Docker volume (`sib-scraper-tls-vm` or
`sib-scraper-tls-grafana`, owned by the scraper's user, key `0400`; the CA key
stays in `certs/`), and generate the scrape config with the block above into
`storage/config/generated/prometheus-vm.yml` or `prometheus-grafana.yml`, from
the tracked `storage/config/prometheus-vm.yml` / `prometheus.yml` (keep the
`SIB_SIDEKICK_TLS` line in the falcosidekick job). Re-run the target after
changing `MTLS_ENABLED`; turning mTLS off empties the volume.

## Tuning

Provisioned rules are read-only in the Grafana UI. Thresholds live in:

- `grafana/provisioning/alerting/templates/alert-rules-vm.yml` (`STACK=vm`)
- `grafana/provisioning/alerting/templates/alert-rules-grafana.yml` (`STACK=grafana`)

Edit the `params` of a rule's threshold (or the numbers in a spike rule's math
expression), then run `make install-grafana`. The Falco liveness and heartbeat
rules are generated by `scripts/generate-grafana-alerting.sh`.
