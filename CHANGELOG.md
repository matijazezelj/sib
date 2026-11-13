# Changelog

All notable changes to SIB are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added
- HIB integration (docs/hib-integration.md): opt-in Falco rule pack for coding agents (`coding_agent_rules.yaml`: credential reads, persistence writes, hook tampering, HIB secret access), collection of HIB's security event log via `hib_events_dir` (Vector and Alloy), and a HIB alert group (critical events, auth failures, denial bursts, sandbox unavailable)
- "HIB daemon not running" alert from HIB's `daemon.alive` heartbeats
- `scripts/test-coding-agent-rules.sh`: runtime test of the coding agent Falco rules (7 positive, 6 negative cases) with live kernel events

### Changed
- Falco 0.45.2 on the SIB server and fleet hosts (was 0.44.1, whose modern eBPF probe doesn't load on Linux 7.2 aarch64)

### Fixed
- "Coding Agent Write Repository or Agent Hook" no longer fires on the `*.sample` hooks `git init`/`git clone` write
- The opt-in `cloud_rules.yaml` and `webserver_rules.yaml` packs failed to load (priority `HIGH` doesn't exist in Falco, now `ERROR`; `not in` operator), so enabling them stopped Falco

---

## [0.7.0] - 2026-11-13

### Added
- Grafana alert rules in a **SIB** folder (pipeline health, Critical/Error bursts, event spikes, disk/memory, storage down), installed by `make install-grafana`; see `docs/grafana-alerts.md`
- Falco liveness alert "Falco not reporting" for expected hosts (fleet inventory plus the SIB host); `sib_expected: false` opts a host out; `make refresh-alerts` regenerates the list and `make deploy-fleet` runs it
- Alert notifications: `GRAFANA_ALERT_WEBHOOK_URL` (Slack or generic webhook), `GRAFANA_ALERT_TELEGRAM_*`, severity routing and an external heartbeat (`GRAFANA_HEARTBEAT_URL`)
- Shared Grafana support: `GRAFANA_MANAGE_NOTIFICATION_POLICY=false`, `GRAFANA_METRICS_DS_UID`, `GRAFANA_LOGS_DS_UID`
- Falcosidekick Telegram output (`TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_MINIMUM_PRIORITY`) and an authenticated webhook output
- Authenticated multi-host Falco sensors with per-sensor client certificates, and `make fleet-certs`
- Appliance syslog ingestion in VictoriaLogs and a UniFi syslog dashboard
- AIB asset context for alerts (obfuscated before it reaches the LLM); `AIB_BASE_URL` / `AIB_API_TOKEN` work in Docker
- `_FILE` secrets for `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `ANALYSIS_API_TOKEN` (`./secrets` mounted in the analysis container)
- `config/custom-outputs.yaml` for extra Falcosidekick outputs

### Changed
- Claude alert analysis starts each alert on Haiku 5.5 and escalates answers that fail validation (Haiku high, then Sonnet 5.5); `ANTHROPIC_MODEL` / `ANTHROPIC_EFFORT` pin one model
- Fleet hosts run Falco 0.44.1 like the SIB host (fleet was on 0.40.0); native fleet installs are pinned to it
- The analysis API requires a token; placeholder tokens are rejected
- With `MTLS_ENABLED=true`, VictoriaMetrics/Prometheus scrape Falcosidekick over https with a dedicated `metrics-scraper` client certificate (per-stack generated scrape config)
- `make test-rules` validates with `FALCO_VERSION` from `.env`

### Fixed
- Configuration in `.env` now takes effect (Makefile, compose and generators); the Grafana alert settings reach the container on every `make install-grafana`
- "Falcosidekick down" no longer fires permanently with mTLS enabled
- `make install-alerting` fails when Falcosidekick cannot read its config (it used to run on defaults) or when Telegram is half-configured
- Custom rules are now loaded on Docker fleet hosts; `make update-rules` works for Docker and native hosts
- Paranoid obfuscation now applies the generic secret patterns
- Grafana notification policies SIB does not manage are no longer reset
- Detection tuning: non-mutating kernel module probes, root/qBittorrent rules and local VictoriaLogs queries no longer alert noisily
- UniFi dashboard counts unique senders and separates uplink-monitor noise

### Removed
- Grafana rules "No Falco events from any host" and "Host stopped sending Falco events" (replaced by Falco liveness; deleted from existing installs)
- `LOKI_RETENTION_PERIOD` from `.env.example` (nothing read it)

---

## [0.6.0] - 2026-04-08

### Added
- 6 new obfuscator tests for real Falco alert patterns (`container_id=host`, system users, hex IDs)
- Auto-detection of host IP for `make install-analysis` (no interactive prompt)
- `ANALYSIS_BIND` and `ANALYSIS_HOST` settings in `.env.example`
- Rule packs for cloud and web server environments (`cloud_rules.yaml`, `webserver_rules.yaml`)
- `docs/upgrade.md` with upgrade instructions
- `docs/kubernetes.md` documenting sib-k8s integration

### Fixed
- Falco upgraded from 0.39.2 to 0.40.0 (fixes `scap_init` crash on kernel 6.12+)
- `make test-rules` pinned to `falco:0.40.0` (was using `:latest`)
- `test-pipeline.sh` access URLs now correctly show `127.0.0.1` for localhost-bound services
- Privacy banner in analysis UI no longer claims data was obfuscated when nothing changed
- Falco config generator improved with output format and metrics settings

### Changed
- `make install-analysis` no longer prompts for IP — auto-detects via `hostname -I` with fallback chain (CLI arg → `.env` → auto-detect)
- Detection rules consolidated and refined

---

## [0.5.0] - 2026-04-08

### Added
- Container images published to GHCR (`ghcr.io/matijazezelj/sib-analysis`, `sib-ansible`)
- CI workflow to build and push images on every push to `main` and on version tags
- 35 automated tests for the `analysis/` obfuscator module
- 5 new detection rules: SSH authorized keys modification (T1098.004), shell profile
  modification (T1546.004), at job scheduling (T1053.002), firewall rule tampering
  (T1562.004), network sniffing tool launch (T1040)
- Demo script coverage for all new detection rules (12 MITRE ATT&CK categories)

### Fixed
- GitHub Actions Node.js 20 deprecation warnings (upgraded `actions/checkout` to v6)
- `sigma2sib` field modifier parsing (`Image|endswith` was treated as a single field name)
- Operator precedence bug in Firewall Rules Modified detection rule
- `analysis/` Docker image missing `templates/` directory (caused `TemplateNotFound` crash)
- All semgrep security findings in `analysis/api.py` (NaN injection, SSTI, HTTP transport)

### Changed
- Sigma converter README documents wildcard selector and nested logic limitations
- CI `lint` job added (shellcheck + ruff)

---

## [0.4.0] - 2026-02-10

### Added
- Fleet deployment via Ansible (Dockerized, no local Ansible install needed)
- mTLS support for encrypted fleet communication
- `make backup` / `make restore` for storage volumes and configuration
- AI-powered alert analysis with obfuscation (Anthropic, OpenAI, Ollama)
- 65 detection rules mapped across all 12 MITRE ATT&CK tactics
- Grafana data link integration for one-click alert analysis
- `make doctor` target for diagnosing common issues
- `make demo` with realistic multi-category security event generation

### Fixed
- Fleet dashboard host filter
- mTLS certificate distribution via Ansible
- 30+ Makefile target bugs and documentation issues

---

## [0.3.0] - 2025-12-01

### Added
- Sigma rule converter (`sigma/sigma2sib.py`) with MITRE tag preservation
- Threat intelligence IP blocklist feeds (`threatintel/`)
- Custom Grafana dashboards: Security Overview, Events Explorer, MITRE ATT&CK matrix
- VictoriaLogs + VictoriaMetrics stack (10x less RAM than Loki/Prometheus)
- Remote collector support (Vector/vmagent for vm stack, Alloy for grafana stack)

### Changed
- Default storage stack switched from `grafana` to `vm`
- All sensitive API keys moved to `.env` with Docker Secrets `_FILE` pattern support

---

## [0.2.0] - 2025-10-01

### Added
- Dual storage stack support (`STACK=vm` / `STACK=grafana`)
- Falcosidekick alert routing with webhook and Slack output
- `make test-alert` and `make test-rules` targets
- Onboarding docs: minimal install, FAQ, hardening guide, troubleshooting

---

## [0.1.0] - 2025-08-01

### Added
- Initial release: one-command security monitoring stack
- Falco eBPF syscall detection
- Grafana visualization
- Docker Compose orchestration via Makefile
- CI pipeline with Docker Compose validation
