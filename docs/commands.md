---
layout: default
title: Commands - SIEM in a Box
---

# Commands

Everything is driven by `make` from the repository root. `make help` prints the main targets. Targets that act on "all stacks" read `STACK` from `.env` and pick the right storage (VictoriaLogs/VictoriaMetrics or Loki/Prometheus).

[← Back to Home](index.md)

---

## Installation

| Command | What it does |
|---------|--------------|
| `make install` | Install all stacks for the configured `STACK`: detection, alerting, storage and Grafana. |
| `make install-detection` | Install Falco. Regenerates `detection/config/falco.yaml`. |
| `make install-alerting` | Install Falcosidekick. Regenerates `alerting/config/config.yaml` from `.env`. |
| `make install-storage-vm` | Install VictoriaLogs + VictoriaMetrics + node_exporter. |
| `make install-storage-grafana` | Install Loki + Prometheus. |
| `make install-grafana` | Install Grafana with the datasources, dashboards and alert rules for the configured stack. |
| `make install-analysis` | Install the optional AI Analysis API and add the "Analyze with AI" links to the Events Explorer. |
| `make refresh-alerts` | Regenerate Grafana alerting (expected Falco hosts from the inventory) and reload it. |
| `make network` | Create the shared Docker network `sib-network`. Run by the install targets. |

See [Installation](installation.md) for the full walkthrough.

## Start, stop, remove

| Command | What it does |
|---------|--------------|
| `make start` / `make stop` / `make restart` | Start, stop or restart all stacks. |
| `make uninstall` | Remove all stacks and their volumes (asks for confirmation). |
| `make update` | Pull the latest images and restart all stacks. Read the [Upgrade Guide](upgrade.md) first. |

Each part also has its own targets, named `<action>-<part>`:

| Action | Parts |
|--------|-------|
| `start-`, `stop-`, `restart-` | `detection`, `alerting`, `storage-vm`, `storage-grafana`, `grafana`, `analysis` |
| `uninstall-` | `detection`, `alerting`, `storage`, `grafana`, `analysis`, `collectors` |
| `shell-` (open a shell in the container) | `falco`, `grafana`, `storage`, `analysis` |

For example `make restart-alerting` or `make shell-falco`.

## Status, health and logs

| Command | What it does |
|---------|--------------|
| `make status` | Status of all stacks with health indicators. |
| `make health` | Quick health check of all services. |
| `make doctor` | Diagnose common problems. |
| `make ps` | List running SIB containers. |
| `make info` | Show all endpoints and ports. |
| `make open` | Open Grafana in the browser. |
| `make logs` | Tail logs from all stacks. |
| `make logs-falco` | Tail Falco logs. |
| `make logs-sidekick` | Tail Falcosidekick logs. |
| `make logs-storage` | Tail storage logs for the configured stack. |
| `make logs-grafana` | Tail Grafana logs. |
| `make logs-analysis` | Tail AI Analysis API logs. |

## Testing and demo

| Command | What it does |
|---------|--------------|
| `make test-alert` | Generate one test security alert. |
| `make demo` | Run the full security demo (about 30 events). See [Quick Start](quickstart.md). |
| `make demo-quick` | Run the demo with a 1-second delay between events. |
| `make test-rules` | Validate the syntax of all Falco rule packs, loaded together. |
| `make e2e` | End-to-end test: HIB events to collector to storage to Grafana alerts (`STACK=vm` or `STACK=grafana`). |
| `./scripts/test-pipeline.sh` | Check the whole pipeline from Falco to storage. |

## Configuration checks and maintenance

| Command | What it does |
|---------|--------------|
| `make validate` | Validate all configuration files. |
| `make check-ports` | Check that the required ports are free. |
| `make clean` | Remove unused Docker resources. |
| `make backup` | Back up to `backups/sib_backup_<timestamp>/`: storage and Grafana volumes, dashboards, datasource config, `.env`, `custom_rules.yaml` and the alerting config. |
| `make restore BACKUP=backups/sib_backup_<timestamp>` | Restore from a backup. Without `BACKUP=` it lists the available backups. |

## Threat intel and Sigma

| Command | What it does |
|---------|--------------|
| `make update-threatintel` | Download or update the threat intel feeds and generate a Falco rule. See [Threat Intelligence](threat-intel.md). |
| `make convert-sigma` | Convert the Sigma rules in `sigma/rules/` to Falco rules (`sigma/rules/converted_falco_rules.yaml`). See [Sigma Rules](sigma-rules.md). |

## Remote collectors

| Command | What it does |
|---------|--------------|
| `make enable-remote` | Let remote collectors write to storage (sets `STORAGE_BIND=0.0.0.0`). |
| `make deploy-collector HOST=user@host` | Deploy a log and metric collector to a remote host. |

## Fleet management (Ansible)

Ansible runs in a container, so it doesn't need to be installed locally. See [Fleet Management](fleet.md).

| Command | What it does |
|---------|--------------|
| `make fleet-build` | Build the Ansible image. |
| `make fleet-ping` | Test SSH connectivity to all fleet hosts. |
| `make deploy-fleet` | Deploy Falco and collectors to fleet hosts, then run `make refresh-alerts`. `LIMIT=web-01` targets one host. |
| `make update-rules` | Push updated Falco rules to fleet hosts. |
| `make fleet-certs` | Push mTLS certificates to fleet hosts without a full redeploy. |
| `make fleet-health` | Check the health of all fleet agents. |
| `make fleet-docker-check` | Check Docker on fleet hosts and install it if missing (`ARGS="-e auto_install=false"` only checks). |
| `make fleet-shell` | Open a shell in the Ansible container. |
| `make remove-fleet` | Remove SIB agents from fleet hosts (asks for confirmation). |

## mTLS certificates

See [Security Hardening](security-hardening.md).

| Command | What it does |
|---------|--------------|
| `make generate-certs` | Generate the CA, server certificate and local client certificate. |
| `make generate-client-cert HOST=web-01` | Generate a client certificate for one host. |
| `make generate-fleet-certs` | Generate client certificates for every host in the Ansible inventory. |
| `make verify-certs` | Verify all certificates. |
| `make rotate-certs` | Regenerate all certificates (CA, server and clients). |
| `make test-mtls` | Test the mTLS connection to Falcosidekick. |
| `make test-alert-mtls` | Send a test alert over mTLS. |

---

[← Back to Home](index.md)
