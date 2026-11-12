---
layout: default
title: Grafana Alerts - SIEM in a Box
---

# Grafana Alerts

Falcosidekick forwards every Falco event to Slack, PagerDuty and its other
outputs. Grafana alerts cover what single events can't show: a pipeline that
went quiet, a host that stopped reporting, a burst of detections, a disk
filling up.

`make install-grafana` provisions 12 rules into the **SIB** folder
(Grafana → Alerting → Alert rules), using the queries for your `STACK`.

## Rules

| Group | Rule | Fires when | Severity |
|-------|------|------------|----------|
| Pipeline health | No Falco events from any host | No events for 2 hours (Falco sends a metrics snapshot hourly, so a healthy pipeline is never silent that long) or log storage can't be queried | critical |
| | Falco dropping syscall events | A host reports `Falco internal: syscall event drop` in 15 minutes | warning |
| | Falcosidekick output errors | An output (Slack, Loki, ...) failed a delivery in 15 minutes | warning |
| | Falcosidekick down | Sidekick can't be scraped for 5 minutes | critical |
| Detection | Burst of Critical/Error events | More than 10 Critical/Error events on one host in 10 minutes | critical |
| | Critical Falco event | Any Critical event (**paused**, see below) | critical |
| Detection baselines (every 5 min) | Host stopped sending Falco events | A host sent events in the last 24 hours but none in the last 2 | warning |
| | Event spike on a host | More than 50 events in 10 minutes and 5× the host's 24-hour average | warning |
| | Rule firing far above normal | Same, per rule | warning |
| Resources | Disk almost full | A filesystem over 85% for 10 minutes | warning |
| | Memory usage high | Memory over 90% for 15 minutes | warning |
| | Storage backend down | VictoriaLogs/VictoriaMetrics (or Loki/Prometheus) unreachable for 5 minutes | critical |

Disk and memory rules cover the SIB server on the VM stack and every fleet host
that ships metrics.

**Critical Falco event** is paused because Falcosidekick already sends each
event. If Grafana is your only notification channel, set `isPaused: false` on
the `sib-critical-event` rule in the template for your stack (see
[Tuning](#tuning)) and re-run `make install-grafana`.

## Notifications

Set a webhook in `.env` and re-run `make install-grafana`:

```bash
# Slack incoming webhook (default type)
GRAFANA_ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Or Grafana's generic JSON webhook to any URL
GRAFANA_ALERT_WEBHOOK_URL=https://alerts.example.com/hook
GRAFANA_ALERT_WEBHOOK_TYPE=webhook
```

This provisions a `sib-alerts` contact point and makes it the default
notification policy (grouped by rule, repeated every 4 hours while firing).
Without `GRAFANA_ALERT_WEBHOOK_URL`, the rules still evaluate and show their
state in Grafana, but nobody is notified. For email, PagerDuty or other
channels, add a contact point in the Grafana UI instead.

## Tuning

Provisioned rules are read-only in the Grafana UI. Thresholds live in:

- `grafana/provisioning/alerting/templates/alert-rules-vm.yml` (`STACK=vm`)
- `grafana/provisioning/alerting/templates/alert-rules-grafana.yml` (`STACK=grafana`)

Edit the `params` of a rule's threshold (or the numbers in a spike rule's math
expression), then run `make install-grafana`.
