---
layout: default
title: FAQ - SIEM in a Box
---

# FAQ

Common questions about SIB.

[← Back to Home](index.md)

---

## Is SIB a network sniffer?
No. SIB uses Falco’s eBPF syscall monitoring to observe **host activity**, not network packets.

## Does it work on macOS or Windows?
SIB is designed for Linux hosts. You can run the stack on Linux VMs on macOS/Windows, but Falco requires Linux kernel access.

## Does SIB require Docker Desktop?
No. Docker Desktop is not supported. Use Docker CE or Podman (rootful).

## Can I run it on a single server?
Yes. The default setup is a single‑host stack.

## Can I monitor multiple servers?
Yes. Use **Fleet Management** or **Remote Collectors** to ship logs/metrics to your central SIB server.

## Is there a cloud dependency?
No. The stack is self‑hosted. AI analysis is optional. It defaults to Anthropic (cloud); set `LLM_PROVIDER=ollama` to run it fully local.

## How do I update it?
Pull the latest changes and restart:
```
git pull
make restart
```

## Does it support custom rules?
Yes. Add rules in detection/config/rules/custom_rules.yaml. Other rule files copied into detection/config/rules/ are not loaded automatically: add the file's path to `rules_files` in detection/config/falco.yaml.template and re-run `make install-detection`.

## What about retention and disk usage?
On the default VM stack, set `VICTORIALOGS_RETENTION_PERIOD` and `VICTORIAMETRICS_RETENTION_PERIOD` in `.env`. On the Grafana stack, Loki retention is in storage/config/loki-config.yml and Prometheus retention is in `.env`. Monitor disk usage.

---

[← Back to Home](index.md)
