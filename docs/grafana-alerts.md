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
```

This provisions a `sib-alerts` contact point and a notification policy:

| Severity | First notification | Repeated while firing |
|----------|--------------------|-----------------------|
| critical | after 10 seconds | every hour |
| warning | after 1 minute | every 4 hours |

Alerts are grouped per rule and per host (`hostname` for log-based rules,
`host` for metrics), so one host's burst doesn't hide another's. Alerts without
a host label are grouped per rule.

Without `GRAFANA_ALERT_WEBHOOK_URL`, the rules still evaluate and show their
state in Grafana, but nobody is notified. For email, PagerDuty or other
channels, add a contact point in the Grafana UI instead.

Notification policies are organisation-wide, so SIB is careful with them:

- With `GRAFANA_ALERT_WEBHOOK_URL` or `GRAFANA_HEARTBEAT_URL` set, SIB
  provisions the whole policy tree above. A policy you built in the UI is
  replaced (your contact points are kept).
- With neither set, SIB leaves the policy alone, so routing you manage
  yourself survives `make install-grafana`.
- Removing both settings after SIB managed the policy hands it back as
  Grafana's default policy and deletes SIB's contact points.

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

## Tuning

Provisioned rules are read-only in the Grafana UI. Thresholds live in:

- `grafana/provisioning/alerting/templates/alert-rules-vm.yml` (`STACK=vm`)
- `grafana/provisioning/alerting/templates/alert-rules-grafana.yml` (`STACK=grafana`)

Edit the `params` of a rule's threshold (or the numbers in a spike rule's math
expression), then run `make install-grafana`. The Falco liveness and heartbeat
rules are generated by `scripts/generate-grafana-alerting.sh`.
