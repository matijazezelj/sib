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
   make generate-configs
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

### 0.5.0

**New container images on GHCR**

`sib-analysis` and `sib-ansible` are now published to GHCR. If you previously
built these locally, you can now pull pre-built images instead:

```bash
docker compose -f analysis/compose.yaml pull
docker compose -f ansible/compose.yaml pull
```

Your existing local builds still work — `build:` is kept in the compose files
as a fallback.

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
STACK=vm make install-storage # start new storage
make restore                  # restore data (Loki → VictoriaLogs migration is manual)
```

> **Note:** Log data is not automatically migrated between storage backends.
> Use the backup to preserve Loki data for reference, then start fresh with
> VictoriaLogs.

---

## Rolling back

If something goes wrong after upgrading, restore from backup and check out the
previous version:

```bash
make restore                       # restore storage volumes
git checkout <previous-tag>        # revert code
make generate-configs && make restart
```

## Getting help

- Run `make doctor` to diagnose common issues
- See [Troubleshooting](troubleshooting.md)
- Open an issue at [github.com/matijazezelj/sib](https://github.com/matijazezelj/sib/issues)
