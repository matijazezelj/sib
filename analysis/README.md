# SIB Alert Analysis (AI-Powered)

> ⚠️ **BETA**: This feature is in active development. APIs and configuration may change.

> **Optional Feature**: AI-powered analysis of security alerts to identify attack vectors and suggest mitigations.

## Overview

When enabled, SIB can analyze security alerts using a Large Language Model (LLM) to provide:

- **Attack Vector Identification** - What technique is being used (mapped to MITRE ATT&CK)
- **Risk Assessment** - Severity and potential impact
- **Mitigation Strategies** - Concrete steps to remediate
- **Context** - Why this matters and what to look for next

## Web API & Grafana Integration

The Analysis module includes a web API that integrates with Grafana dashboards via data links.

### Installation

```bash
# Install the API service
make install-analysis

# Manage the service
make start-analysis
make stop-analysis
make logs-analysis
```

### Grafana Integration

Once installed, the **Events Explorer** dashboard shows a "🤖 Analyze with AI" link when you click on a log entry. Other dashboards do not have it.

Set your API key in `.env` first. For the link to work from another machine, see [Quick Start](../docs/ai-analysis.md#quick-start).

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API home page |
| `/analyze` | GET | HTML result page |
| `/api/analyze` | POST | JSON API for programmatic access |
| `/health` | GET | Health check endpoint |
| `/api/health/all` | GET | Health of Falcosidekick, storage, Grafana and the API itself, as JSON |
| `/history` | GET | List past analyses |
| `/history/<id>` | GET | View a specific cached analysis |
| `/api/history` | GET | List past analyses as JSON (`?limit=50`) |

### Configuration

Provider, models, API keys, the API token and the bind address are set in `.env`; run `make install-analysis` after changing them. The full list is in [AI Analysis: Configuration](../docs/ai-analysis.md#configuration).

The obfuscation level is set in `config.yaml` (see [Obfuscation Levels](#obfuscation-levels)); run `make restart-analysis` after editing it.

> **Docker Secrets:** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and `ANALYSIS_API_TOKEN` can be loaded from a file by setting the matching `_FILE` variable in `.env`. `./secrets` is mounted read-only at `/app/secrets`, so use e.g. `ANTHROPIC_API_KEY_FILE=/app/secrets/anthropic_api_key`. See [secrets/README.md](../secrets/README.md).

## Privacy & Security

### What Gets Sent to the LLM

With the default `standard` level:

| Data Type | Example | Replaced With |
|-----------|---------|---------------|
| IP addresses | `192.0.2.10` | `[IP-INTERNAL-1]` or `[IP-EXTERNAL-1]` |
| User names (`user=`, `uid=`, `User `) | `user=jsmith` | `user=[USER-1]` |
| Container IDs (12+ hex characters) | `a1b2c3d4e5f6` | `[CONTAINER-1]` |
| Secrets in known formats | `AKIA...` | `[REDACTED-AWS-KEY]` |
| E-mail addresses | `user@example.com` | `[EMAIL-1]` |

Everything else is sent as is: rule name, priority, command lines and arguments, file paths, host names. `root` and common service accounts are kept. The `paranoid` level also replaces dotted host names and file names.

### Obfuscation Levels

Configure in `config.yaml`:

```yaml
analysis:
  obfuscation_level: standard  # minimal, standard, paranoid
```

| Level | Description |
|-------|-------------|
| `minimal` | Only secrets in known formats |
| `standard` | Also IPs, e-mails, container IDs and user names (default) |
| `paranoid` | Also dotted host names, file names and secret-like strings |

No level replaces single-label host names (`web-01`) or user names inside file paths. Check what would be sent with the dry run below.

## Storage Backend

The analyzer picks the storage backend from the `STACK` variable. With `STACK=vm` (default) it reads and stores alerts in VictoriaLogs, with `STACK=grafana` in Loki.

## LLM Providers

### Option 1: Local (Ollama) - Fully Local, Best for Privacy

No data leaves your network. Anthropic is the default provider, so select Ollama in `.env`. Requires ~8GB RAM for good models.

```bash
LLM_PROVIDER=ollama
OLLAMA_URL=http://192.0.2.10:11434   # an address the container can reach
OLLAMA_MODEL=qwen2.5:14b
```

On Linux Docker Engine the default `host.docker.internal` URL does not resolve; see [Ollama Setup](../docs/ai-analysis.md#ollama-setup-fully-local).

### Option 2: OpenAI API

Better quality, data sent to OpenAI (obfuscated). In `.env`:

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=your-api-key
OPENAI_MODEL=gpt-4o   # default
```

### Option 3: Anthropic API (default)

```yaml
analysis:
  provider: anthropic
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    tiers:                                   # cheap first, escalate failures
      - {model: claude-haiku-5-5, effort: medium}
      - {model: claude-haiku-5-5, effort: high}
      - {model: claude-sonnet-5-5, effort: medium}
```

Alert triage is high-volume structured extraction with an answer that can be
checked, so each alert starts on Claude Haiku 5.5. The analyzer validates the
JSON it gets back (MITRE technique ID, severity, summary, mitigations). Only an
answer that fails that check, is refused, or is cut off goes to the next tier:
the same model one effort level up first, then the next model up at a lower
effort. Server-side refusal fallbacks are turned on for tiers above Haiku.

The CLI prints the tiers tried and the estimated cost; with `--json` each result
has an `llm` block with tokens as well. To pin one model, delete `tiers` from
`config.yaml` and set `ANTHROPIC_MODEL` (and optionally `ANTHROPIC_EFFORT`) in
`.env`, then run `make install-analysis` and `make restart-analysis`. While
`tiers` is present, `ANTHROPIC_MODEL` has no effect.

## Usage

### Via Grafana (Recommended)

1. Open **Events Explorer** dashboard
2. Click any event row to select it
3. Click **🤖 Analyze with AI** in the bottom panel
4. View the analysis with attack vectors, MITRE mapping, and mitigations

### Via API

All endpoints except `/health` require the token from `ANALYSIS_API_TOKEN` in `.env`,
passed either as an `Authorization: Bearer` header or a `token=` query parameter.
Run these from the repository root.

```bash
TOKEN=$(grep '^ANALYSIS_API_TOKEN=' .env | cut -d= -f2)

# Analyze a specific event
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/analyze?rule=Read%20sensitive%20file&output=user%3Droot%20file%3D/etc/shadow"

# Dry run - see obfuscated data without calling the LLM (CLI only)
docker exec sib-analysis python analyzer.py --dry-run --limit 1

# JSON API - note the alert text goes in "alert", not "output"
curl -X POST http://localhost:5000/api/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rule": "Read sensitive file", "alert": "user=root file=/etc/shadow"}'
```

### Caching

Results from `GET /analyze` (the Grafana link) are cached to avoid repeated LLM calls for the same event. The JSON API and CLI are not cached. The cache is stored in `/app/cache` (persisted via Docker volume).

- Cache entries expire after `ANALYSIS_CACHE_TTL` seconds (default: 24 hours)
- Cache keys are normalized: timestamps, numeric IDs, IPs, and container IDs are stripped so similar events share a cache key
- A `dedup_count` field tracks how many times the same alert was requested

## AIB Integration (Asset Context)

When [Assets in a Box (AIB)](../docs/aib-integration.md) is configured, alerts are enriched with asset metadata, blast radius, and pre-existing audit findings *before* reaching the LLM. This lets the model reason about real-world impact rather than just the raw event.

Set `AIB_BASE_URL` in your `.env` to enable it — see **[docs/aib-integration.md](../docs/aib-integration.md)** for the full setup guide, data flow, and example output.

## How It Works

Analysis runs on demand, from the Grafana link, the API or the CLI.

1. **Alert received** → rule name and alert text
2. **Obfuscation** → Sensitive data replaced with tokens
3. **AIB Enrichment** *(optional)* → Asset metadata, blast radius, and audit findings fetched, then obfuscated the same way
4. **LLM Analysis** → Security-focused prompt analyzes the alert (with asset context if available)
5. **Storage** → The result can be stored in VictoriaLogs or Loki with `source=analysis` (the Grafana link does this by default; the API needs `store: true`, the CLI `--store`)

## Example Output

**Original Alert:**
```
Read sensitive file untrusted: user=jsmith file=/etc/shadow
process=cat container=a1b2c3d4e5f6 image=nginx:latest
```

**Obfuscated (sent to LLM):**
```
Read sensitive file untrusted: user=[USER-1] file=/etc/shadow
process=cat container=[CONTAINER-1] image=nginx:latest
```

The model answers with JSON; see the [API response](../docs/ai-analysis.md#json-api).

## Example Analysis Output

Examples in the format the CLI prints:

### Critical Alert - Defense Evasion

```
======================================================================
🔍 SECURITY ALERT ANALYSIS
======================================================================

🎯 Attack Vector:
   The alert indicates a potentially malicious attempt to delete a 
   significant number of files within the /var/lib/dpkg/tmp.ci directory 
   using the rm -rf command with root privileges. This directory is 
   associated with package management, making a wholesale deletion highly 
   suspicious, potentially aiming to disrupt system functionality or hide 
   malicious activity.

📊 MITRE ATT&CK:
   Tactic: Defense Evasion
   Technique: T1070.001 - Indicator Removal on Host

⚠️  Risk Assessment:
   Severity: 🔴 Critical
   Confidence: High
   Impact: System instability, package management failure, potential data 
   loss, and masking of further malicious actions.

🛡️  Mitigations:
   Immediate:
     • Isolate the affected host immediately from the network
     • Take a forensic image of the affected host's filesystem
   Short-term:
     • Restore /var/lib/dpkg/tmp.ci from a known good backup
     • Implement stricter access controls for the root user
   Long-term:
     • Implement file integrity monitoring (FIM) on critical directories
     • Strengthen container security practices
     • Improve logging and monitoring capabilities

🤔 False Positive Assessment:
   Likelihood: Low
   Common legitimate causes:
     • Automated cleanup scripts (unlikely to use rm -rf)
     • Package management operations during updates

📝 Summary:
   A critical alert indicating a potentially malicious attempt to delete 
   files within the package management temporary directory. This action 
   strongly suggests a deliberate effort to disrupt system functionality 
   or cover tracks, requiring immediate isolation and forensic investigation.

======================================================================
```

### Error Alert - Persistence Attempt

```
======================================================================
🔍 SECURITY ALERT ANALYSIS
======================================================================

🎯 Attack Vector:
   An attacker is attempting to modify system configuration files, 
   specifically the dynamic linker cache, likely to inject malicious 
   code or redirect program execution to a compromised library.

📊 MITRE ATT&CK:
   Tactic: Persistence
   Technique: T1547.001 - Boot or Logon Autostart Execution

⚠️  Risk Assessment:
   Severity: 🔴 Critical
   Confidence: High
   Impact: Complete system compromise, ability to execute arbitrary code 
   with root privileges, potential for lateral movement and data exfiltration.

🛡️  Mitigations:
   Immediate:
     • Isolate the affected system from the network
     • Quarantine /etc/ld.so.cache~ and restore from backup
   Short-term:
     • Rebuild the affected system from a clean image
     • Review and strengthen dpkg configuration
   Long-term:
     • Implement file integrity monitoring (FIM)
     • Implement Mandatory Access Control (SELinux or AppArmor)
     • Regularly audit system configuration scripts

🤔 False Positive Assessment:
   Likelihood: Low
   Common legitimate causes:
     • Legitimate package upgrade process modifying the linker cache
     • Misconfigured post-installation script

📝 Summary:
   A critical security alert indicates an attempt to modify the system's 
   dynamic linker cache, suggesting a potential compromise. Immediate 
   investigation and remediation required to prevent malicious code execution.

======================================================================
```

### Warning Alert - Discovery Activity

```
======================================================================
🔍 SECURITY ALERT ANALYSIS
======================================================================

🎯 Attack Vector:
   An attacker has successfully gained execution and is attempting to 
   enumerate user accounts by reading the /etc/passwd file. This could 
   be a precursor to credential harvesting or privilege escalation.

📊 MITRE ATT&CK:
   Tactic: Discovery
   Technique: T1082 - System Information Discovery

⚠️  Risk Assessment:
   Severity: 🟡 Medium
   Confidence: Medium
   Impact: Compromise of user accounts and potential system takeover. 
   Information disclosure of user credentials.

🛡️  Mitigations:
   Immediate:
     • Isolate the affected host from the network
     • Kill the suspicious process if acting maliciously
   Short-term:
     • Review and restrict file access permissions on /etc/passwd
     • Audit SSH configuration for unusual settings
   Long-term:
     • Employ a SIEM system to centrally collect and analyze logs
     • Implement runtime security tooling with robust alerting
     • Consider hardened SSH configuration with key-based auth only

🤔 False Positive Assessment:
   Likelihood: Low
   Common legitimate causes:
     • Legitimate system maintenance tasks
     • Debugging by system administrators

📝 Summary:
   A security alert indicates a process accessed the sensitive /etc/passwd 
   file. While this could be legitimate, it's a potential indicator of 
   compromise for user enumeration. Immediate investigation recommended.

======================================================================
```
