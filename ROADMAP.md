# Roadmap

This is a living roadmap. Priorities may shift based on feedback and community contributions.

## Recently shipped
- CI pipeline with shellcheck, Python linting, and Docker Compose validation
- Onboarding docs: minimal install, FAQ, hardening guide, troubleshooting
- 65 detection rules mapped across all 12 MITRE ATT&CK tactics
- Fleet deployment via Ansible (Dockerized, no local install needed)
- AI-powered alert analysis with obfuscation (Anthropic, OpenAI, Ollama)
- mTLS support for encrypted fleet communication
- Built-in backup/restore for storage volumes and config
- Container images published to GHCR (`ghcr.io/matijazezelj/sib-analysis`, `sib-ansible`)

## Next
- Add upgrade notes and versioned releases
- Rule packs for common environments (cloud, K8s, web servers)

## 3–6 months
- Dashboards for compliance views (e.g., CIS focus)
- Better alert enrichment (GeoIP, asset tags)
- Lightweight installer script for fresh hosts

## 6–12 months
- Multi-tenant mode for MSP or shared environments
- Built-in alert correlation rules
- Pluggable rule marketplace
- Expanded integrations (SOAR/webhooks)

## How you can help
- Testing on different distros/kernel versions
- Writing or tuning detection rules
- Creating dashboards and docs
- Reporting bugs and UX issues
