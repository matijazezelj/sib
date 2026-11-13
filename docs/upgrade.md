---
layout: default
title: Upgrade Guide
nav_order: 9
---

# Upgrade Guide

## General process

1. Back up your data before upgrading:
   ```bash
   make backup
   ```

2. Pull the latest code:
   ```bash
   git pull origin main
   ```

3. Regenerate configs (picks up any template changes):
   ```bash
   make install-alerting install-detection
   ```

4. Restart all services:
   ```bash
   make restart
   ```

5. Verify everything is healthy:
   ```bash
   make health
   ```

---

## Version-specific notes

### Unreleased (after 0.6.0)

Re-run these once after `git pull`; each is safe to repeat.

**Storage: generated scrape config** (`make install-storage-vm` or `make install-storage-grafana`)

The metrics scrape config the storage container mounts is now generated into
`storage/config/generated/` from `storage/config/prometheus-vm.yml` /
`prometheus.yml`. With `MTLS_ENABLED=true`, Falcosidekick is scraped over https
with a dedicated `metrics-scraper` client certificate (kept in a Docker volume);
before, *Falcosidekick down* fired with mTLS on. Re-run the target for your
`STACK`, and again whenever you change `MTLS_ENABLED`.

**Alerting: Falcosidekick config permissions** (`make install-alerting`)

The generated config is now given the group from `SIDECAR_CONFIG_GID`, and the
install fails (instead of silently running without outputs or mTLS) if
Falcosidekick can't read it. Falcosidekick also gained a Telegram output
(`TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_MINIMUM_PRIORITY`).

**Grafana alerts** (`make install-grafana`)

Alert rules now live in a **SIB** folder, with Telegram, an optional heartbeat
and notification-policy control. Two rules are replaced: *No Falco events from
any host* and *Host stopped sending Falco events* are deleted, and **Falco not
reporting** takes over, based on Falco's `/metrics` instead of events. See
[Grafana Alerts](grafana-alerts.md). New `.env` settings are optional
(`GRAFANA_ALERT_WEBHOOK_URL`, `GRAFANA_ALERT_TELEGRAM_*`, `GRAFANA_HEARTBEAT_URL`,
`GRAFANA_MANAGE_NOTIFICATION_POLICY`, `GRAFANA_METRICS_DS_UID`,
`GRAFANA_LOGS_DS_UID`). If you manage Grafana's notification policy by hand, see
the policy rules in [Grafana Alerts](grafana-alerts.md#notifications) first.

**Fleet: Falco 0.44.1, metrics, rules.d** (`make deploy-fleet`, once)

Falco is now 0.44.1 (`falco_version` in `ansible/inventory/group_vars/all.yml`
and `FALCO_VERSION` in `.env`; keep them in sync). `make deploy-fleet` upgrades
native installs to it, loads `/etc/falco/config.d` and the container plugin,
mounts custom rules at `/etc/falco/rules.d` on Docker hosts, enables Falco's
`/metrics` (on `127.0.0.1:8765`) and adds the collector's `falco` scrape job.
Without it, **Falco not reporting** fires for every fleet host. The run also
refreshes the expected-hosts list (`make refresh-alerts`). On the SIB server,
`make install-detection` applies the same version and metrics settings. After
this, `make update-rules` detects Docker or native hosts itself.

**AI analysis** (`make install-analysis`)

The Anthropic provider now starts each alert on Claude Haiku 5.5 and escalates
to a higher effort, then Sonnet 5.5, only when the answer fails validation. A
pinned `ANTHROPIC_MODEL` skips this. `*_FILE` secrets (`ANTHROPIC_API_KEY_FILE`,
`OPENAI_API_KEY_FILE`, `ANALYSIS_API_TOKEN_FILE`) are read from `./secrets`,
mounted at `/app/secrets`. See [AI Analysis](ai-analysis.md).

---

### 0.5.0

**New container images on GHCR**

`sib-analysis` and `sib-ansible` are now published to GHCR. If you previously
built these locally, the pre-built images are available at
`ghcr.io/matijazezelj/sib-analysis` and `ghcr.io/matijazezelj/sib-ansible`.

The compose files in this repo still use `build:` (they do not reference the
GHCR images), so `docker compose pull` fetches nothing. Your local builds keep
working as before; rebuild them after upgrading with `make install-analysis`.

**New detection rules**

Five new rules were added to `custom_rules.yaml`. They activate automatically
on restart — no manual action needed.

---

### 0.4.0

**Environment variable changes**

Several new variables were added to `.env.example`. Compare your `.env` with
`.env.example` and add any missing variables:

```bash
diff .env .env.example
```

Key additions:
- `LLM_PROVIDER` — `anthropic`, `openai`, or `ollama`
- `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_URL`
- `MTLS_ENABLED` — set to `true` to enable encrypted fleet communication

**Backup/restore targets**

`make backup` and `make restore` are new. Backups are stored in `./backups/`.
No migration needed — existing data is unaffected.

**Ansible fleet deployment**

The `ansible/` directory is new. Existing single-host deployments are not
affected. See [Fleet Deployment](fleet.md) to opt in.

---

### 0.3.0

**Default stack changed to `vm`**

If you were running the `grafana` stack (Loki + Prometheus) and want to keep
it, set `STACK=grafana` in your `.env` before upgrading. The `vm` stack
(VictoriaLogs + VictoriaMetrics) is now the default.

To migrate from Loki to VictoriaLogs:
```bash
make backup                   # save existing data
make install-storage-vm       # start new storage
make restore BACKUP=backups/<name> # restore data (Loki → VictoriaLogs migration is manual)
```

> **Note:** Log data is not automatically migrated between storage backends.
> Use the backup to preserve Loki data for reference, then start fresh with
> VictoriaLogs.

---

## Rolling back

If something goes wrong after upgrading, restore from backup and check out the
previous version:

```bash
make restore BACKUP=backups/<name> # restore storage volumes
git checkout <previous-tag>        # revert code
make install-alerting install-detection && make restart
```

## Getting help

- Run `make doctor` to diagnose common issues
- See [Troubleshooting](troubleshooting.md)
- Open an issue at [github.com/matijazezelj/sib](https://github.com/matijazezelj/sib/issues)
