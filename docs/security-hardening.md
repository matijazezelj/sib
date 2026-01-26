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
- **Grafana** (3000) is public-facing
- **Sidekick API** (2801) is public-facing (required for fleet)
- **Loki** (3100) and **Prometheus** (9090) should remain internal

Use a firewall to restrict access to trusted IP ranges.

---

## 2) Grafana Password

A secure password is **auto-generated** during `make install`.

To view it:
```bash
grep GRAFANA_ADMIN_PASSWORD .env
```

To set a custom password before install:
```bash
GRAFANA_ADMIN_PASSWORD=your-strong-password
```

---

## 3) TLS and Reverse Proxy

Place Grafana behind a reverse proxy (Nginx/Caddy/Traefik) and enable TLS.
This lets you:
- Terminate HTTPS
- Add auth (basic auth/OIDC)
- Rate-limit access

---

## 4) Restrict Fleet Ingress

Allow only fleet subnet to reach Sidekick (and Loki/Prometheus if remote enabled):

```bash
ufw allow from 192.168.1.0/24 to any port 2801
ufw allow from 192.168.1.0/24 to any port 3100
ufw allow from 192.168.1.0/24 to any port 9090
```

---

## 5) Reduce Data Retention

Adjust retention to avoid disk exhaustion:

- Loki: storage/config/loki-config.yml
- Prometheus: storage/config/prometheus.yml

---

## 6) Backups

Back up Grafana and Loki data volumes regularly. Ensure your backup target is secure and encrypted.

---

## 7) Run Health Checks

```bash
make health
make doctor
```

---

## 8) Monitor Resource Usage

Track disk and memory growth. Tune retention and sampling as needed.

---

[← Back to Home](index.md)
