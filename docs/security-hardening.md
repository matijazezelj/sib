---
layout: default
title: Security Hardening - SIEM in a Box
---

# Security Hardening

Practical steps to secure a production SIB deployment.

[← Back to Home](index.md)

---

## 1) Lock Down External Ports

Only expose what you need. By default:
- **Grafana** (3000) is bound to loopback (`GRAFANA_BIND_ADDR=127.0.0.1`); set `0.0.0.0` only to expose it
- **Sidekick API** (2801) is bound to loopback (`SIDEKICK_BIND_ADDR=127.0.0.1`); set `0.0.0.0` only for fleet collectors
- Storage backends should remain internal:
  - **VictoriaMetrics stack** (default): VictoriaLogs (9428), VictoriaMetrics (8428)
  - **Grafana stack**: Loki (3100), Prometheus (9090)
- Storage (`STORAGE_BIND`), the syslog listener (`SYSLOG_BIND_ADDR`) and the AI analysis API (`ANALYSIS_BIND`) also bind to 127.0.0.1 by default. [Configuration](configuration.md#bind-addresses-at-a-glance) lists them all.

Use a firewall to restrict access to trusted IP ranges.

---

## 2) Grafana Password

A secure password is **auto-generated** during `make install`.

To view it:
```bash
grep GRAFANA_ADMIN_PASSWORD .env
```

To set a custom password before install, put it in `.env`:
```bash
GRAFANA_ADMIN_PASSWORD=your-strong-password
```

To change it on a running install, see [Grafana Password](installation.md#grafana-password).

---

## 3) TLS and Reverse Proxy

Place Grafana behind a reverse proxy (Nginx/Caddy/Traefik) and enable TLS.
This lets you:
- Terminate HTTPS
- Add auth (basic auth/OIDC)
- Rate-limit access

---

## 4) Restrict Fleet Ingress

Fleet hosts need Sidekick (set `SIDEKICK_BIND_ADDR`, then `make install-alerting`) and the storage ports (`make enable-remote`). Allow only the fleet subnet to reach them.

Docker publishes ports with its own iptables rules, so `ufw` rules don't restrict them. Filter in the `DOCKER-USER` chain or on an upstream firewall. Replace `eth0` and the subnet with yours, and make the rules persistent:

```bash
# VM stack (default): Sidekick, VictoriaLogs, VictoriaMetrics.
# Grafana stack: use 2801 3100 9090.
for port in 2801 9428 8428; do
  sudo iptables -I DOCKER-USER -i eth0 -p tcp --dport "$port" ! -s 192.0.2.0/24 -j DROP
done
```

---

## 5) Enable mTLS for Fleet Communication

For encrypted and authenticated communication between fleet agents and SIB server, enable mutual TLS.

### Quick Setup

```bash
# 1. Fresh install only: create .env (keeps an existing one)
[ -f .env ] || cp .env.example .env

# 2. Generate certificates (CA, server, local client)
make generate-certs

# 3. Enable mTLS in .env
#      MTLS_ENABLED=true

# 4. (Re)install to apply
make install
```

With mTLS on, Falco sends to `https://sib-sidekick:2801/`; an `http://` `SIDEKICK_URL` is switched to `https://`.

Fleet hosts verify the server certificate against the address they connect to. It includes the server's detected IPv4 addresses (not `172.*` ones). To name another, generate the certificates with `SIB_SERVER_IP=192.0.2.10 make generate-certs`, or `SERVER_CN=sib.example.com` for a DNS name.

`./scripts/test-pipeline.sh` and the first-alert check at the end of `make install` check Sidekick from inside the Falco container, with its client certificate when mTLS is on. `make test-mtls` tests the connection on its own.

With mTLS on, Falcosidekick's listener requires a client certificate, so
`make install-storage-vm` / `install-storage-grafana` generate a scrape config
(`storage/config/generated/`) that scrapes it over https with a dedicated
`metrics-scraper` client certificate. After turning mTLS on or off, re-run your
storage target (turning it off also removes the scraper's key). See
[Grafana Alerts](grafana-alerts.md#scraping-falcosidekick-over-mtls).

### Fleet Deployment with mTLS

```bash
# Generate client certs for each fleet host
make generate-client-cert HOST=hostname

# Or generate for all hosts in Ansible inventory
make generate-fleet-certs

# Deploy via Ansible
make deploy-fleet  # Uses mtls_enabled from inventory
```

### What mTLS Protects

| Communication Path | Without mTLS | With mTLS |
|--------------------|--------------|-----------|
| Falco → Falcosidekick | HTTP (plaintext) | HTTPS + client cert |
| Fleet Falco → Sidekick | HTTP (plaintext) | HTTPS + client cert |
| Metrics scraper → Sidekick `/metrics` | HTTP (plaintext) | HTTPS + `metrics-scraper` client cert |
| Fleet collectors → storage (logs, metrics) | HTTP (plaintext) | Unchanged: not covered |

### Certificate Management

| Command | Description |
|---------|-------------|
| `make generate-certs` | Generate CA, server, and local client certs |
| `make generate-client-cert HOST=name` | Generate cert for specific host |
| `make generate-fleet-certs` | Generate certs for all fleet hosts |
| `make fleet-certs` | Push certs to fleet hosts without a full redeploy |
| `make verify-certs` | Verify certificate chain |
| `make rotate-certs` | Regenerate the CA, server, local and fleet certs; then reinstall storage to reissue the scraper cert (see [certs/README.md](https://github.com/matijazezelj/sib/blob/main/certs/README.md)) |
| `make test-mtls` | Test mTLS connection |

### Certificate Locations

| Location | Purpose |
|----------|---------|
| `certs/ca/ca.crt` | Certificate Authority (public) |
| `certs/ca/ca.key` | CA private key (SECRET!) |
| `certs/server/server.crt` | Server certificate |
| `certs/server/server.key` | Server private key |
| `certs/clients/*.crt` | Client certificates |

### Ansible Configuration

Enable mTLS in `ansible/inventory/group_vars/all.yml`:

```yaml
mtls_enabled: true
```

---

## 6) Reduce Data Retention

Adjust retention to avoid disk exhaustion. Configure in `.env`:

**VictoriaMetrics stack (default):**
```bash
VICTORIALOGS_RETENTION_PERIOD=168h    # 7 days
VICTORIAMETRICS_RETENTION_PERIOD=15d  # 15 days
```

**Grafana stack:**
```bash
PROMETHEUS_RETENTION_TIME=15d         # 15 days
PROMETHEUS_RETENTION_SIZE=5GB         # Disk-based limit
```

Loki retention is not an `.env` setting; set `retention_period` in `storage/config/loki-config.yml` (default `168h`), then run `make restart-storage-grafana`.

Apply `.env` changes with `make install-storage-vm` or `make install-storage-grafana`.

---

## 7) Backups

Back up Grafana and storage data volumes regularly. Ensure your backup target is secure and encrypted.

SIB includes built-in backup/restore commands:
```bash
make backup                          # Backup storage volumes, configs, rules, Grafana data
make restore BACKUP=backups/<name>   # Restore from a backup directory
```

`make backup` saves everything to `backups/sib_backup_<timestamp>/`:
- Storage volumes (VictoriaLogs/Metrics or Loki/Prometheus data)
- Grafana volume and provisioned dashboards
- `custom_rules.yaml` and the generated alerting config
- Datasource configuration
- `.env`, as `dot-env` (contains secrets, so protect the backup)

`certs/`, `secrets/`, `custom-outputs.yaml` and other rules files are not included.

`make restore` stops services and restores volumes, dashboards, custom rules and alerting config. It doesn't restore `.env` or the datasource config. Run `make start` afterwards.

**Docker volumes to back up:**
```bash
# Grafana
grafana_grafana-data

# VictoriaMetrics stack (default)
storage_victorialogs-data
storage_victoriametrics-data

# Grafana stack
storage_loki-data
storage_prometheus-data
```

---

## 8) Run Health Checks

```bash
make health
make doctor
```

---

## 9) Monitor Resource Usage

Track disk and memory growth. Tune retention and sampling as needed.

---

## 10) Docker Secrets for API Keys

SIB supports Docker Secrets for sensitive environment variables. The analysis service reads `_FILE` variants of `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `ANALYSIS_API_TOKEN`; `./secrets` is mounted at `/app/secrets` in the container (see `secrets/README.md`). Append `_FILE` to one of these and point it to a secrets file:

```bash
# Instead of:
OPENAI_API_KEY=sk-...

# Use:
OPENAI_API_KEY_FILE=/app/secrets/openai_api_key
```

This avoids storing secrets in `.env` or shell history.

---

[← Back to Home](index.md)
