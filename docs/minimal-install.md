---
layout: default
title: Minimal Install - SIEM in a Box
---

# Minimal Install

Get the **core SIEM stack** running with the smallest footprint and no optional services.

[← Back to Home](index.md)

---

## What This Includes

- **Falco** (detection)
- **Falcosidekick** (alert routing)
- **Log storage** (VictoriaLogs or Loki, depending on stack)
- **Grafana** (dashboards)

This excludes:
- AI analysis API
- Fleet management (Ansible)
- Remote collectors
- Threat intel updates
- Sigma conversion

---

## Prerequisites

- Docker CE 20.10+ or Podman 4.0+ (rootful)
- Linux kernel 5.8+
- 4GB RAM
- `git`, `make`, `curl`, `openssl`, and `jq` for the pipeline test

---

## Minimal Install

```bash
git clone https://github.com/matijazezelj/sib.git
cd sib
cp .env.example .env
make install
```

---

## Minimal + Manual (If You Prefer Explicit Steps)

After cloning and `cp .env.example .env`, set `GRAFANA_ADMIN_PASSWORD` in `.env`. These targets don't generate it; only `make install` does.

```bash
# For VictoriaMetrics stack (default, recommended)
make install-storage-vm
make install-grafana
make install-alerting
make install-detection

# Or for Grafana stack (Loki + Prometheus)
# make install-storage-grafana
# make install-grafana
# make install-alerting
# make install-detection
```

---

## Verify

```bash
make health
./scripts/test-pipeline.sh
```

---

## Next Steps

- [Quick Start](quickstart.md)
- [Troubleshooting](troubleshooting.md)
- [AI Analysis](ai-analysis.md) (optional)
- [Fleet Management](fleet.md) (optional)

---

[← Back to Home](index.md)
