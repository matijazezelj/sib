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

Once installed, all log panels show a "🤖 Analyze with AI" link when you click on a log entry:

- **Security Overview** - Critical Events, Recent Events panels
- **Events Explorer** - All log entries
- **MITRE ATT&CK** - Critical & Error Events, MITRE-Tagged Events

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | GET | Web interface with beautiful HTML results |
| `/api/analyze` | POST | JSON API for programmatic access |
| `/health` | GET | Health check endpoint |

### Environment Variables

Configure in `analysis/compose.yaml`:

```yaml
environment:
  - OLLAMA_HOST=http://192.168.101.226:11434  # Your Ollama server
  - OLLAMA_MODEL=qwen2.5:14b                    # Model to use
  - LOKI_URL=http://loki:3100                   # Loki for storing results
  - OBFUSCATION_LEVEL=standard                  # minimal, standard, paranoid
```

## Privacy & Security

### What Gets Sent to the LLM

**NEVER sent (obfuscated before analysis):**
| Data Type | Example | Replaced With |
|-----------|---------|---------------|
| IP Addresses | `192.168.1.100` | `[INTERNAL-IP-1]` or `[EXTERNAL-IP-1]` |
| Hostnames | `prod-web-01.acme.com` | `[HOST-1]` |
| Usernames | `jsmith` | `[USER-1]` |
| File Paths | `/home/jsmith/secrets.txt` | `/home/[USER-1]/[FILE-1].txt` |
| Container IDs | `a1b2c3d4e5f6` | `[CONTAINER-1]` |
| Process IDs | `12345` | `[PID-1]` |
| Secrets/Keys | `AKIA...` | `[REDACTED-SECRET]` |
| Email Addresses | `user@company.com` | `[EMAIL-1]` |

**Sent (structural information only):**
- Alert rule name (e.g., "Read sensitive file untrusted")
- Alert priority (Critical, Error, Warning, Notice)
- Command structure (binary names, flags - not arguments with sensitive data)
- Syscall types (open, execve, connect, etc.)
- Network ports (preserved for analysis)
- File extensions and types
- Container image names (public images only)

### Obfuscation Levels

Configure in `config.yaml`:

```yaml
analysis:
  enabled: true
  obfuscation_level: standard  # minimal, standard, paranoid
```

| Level | Description |
|-------|-------------|
| `minimal` | Only secrets and credentials obfuscated |
| `standard` | IPs, hostnames, users, paths obfuscated (recommended) |
| `paranoid` | Everything except alert type and priority obfuscated |

## LLM Providers

### Option 1: Local (Ollama) - Recommended for Privacy

No data leaves your network. Requires ~8GB RAM for good models.

```yaml
analysis:
  provider: ollama
  ollama:
    url: http://localhost:11434
    model: llama3.1:8b  # or mistral, mixtral
```

### Option 2: OpenAI API

Better quality, data sent to OpenAI (obfuscated).

```yaml
analysis:
  provider: openai
  openai:
    api_key: ${OPENAI_API_KEY}
    model: gpt-4o-mini
```

### Option 3: Anthropic API

```yaml
analysis:
  provider: anthropic
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    model: claude-3-haiku-20240307
```

## Usage

### Via Grafana (Recommended)

1. Open **Events Explorer** dashboard
2. Click any event row to select it
3. Click **🤖 Analyze with AI** in the bottom panel
4. View the analysis with attack vectors, MITRE mapping, and mitigations

### Via API

```bash
# Analyze a specific event
curl "http://localhost:5000/analyze?rule=Read%20sensitive%20file&output=user%3Droot%20file%3D/etc/shadow"

# Dry run - see obfuscated data without calling LLM
curl "http://localhost:5000/analyze?rule=Test&output=test&dry_run=true"

# JSON API
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"rule": "Read sensitive file", "output": "user=root file=/etc/shadow"}'
```

### Caching

Analysis results are cached to avoid repeated LLM calls for the same event. Cache is stored in `/app/cache` (persisted via Docker volume).

## How It Works

1. **Alert Ingested** → Falco detects suspicious activity
2. **Obfuscation** → Sensitive data replaced with tokens
3. **LLM Analysis** → Security-focused prompt analyzes the alert
4. **Enrichment** → Response parsed and attached to alert
5. **Storage** → Enriched alert stored in Loki with analysis labels

## Example Output

**Original Alert:**
```
Read sensitive file untrusted: user=jsmith file=/etc/shadow 
process=cat container=a1b2c3d4 image=nginx:latest
```

**Obfuscated (sent to LLM):**
```
Read sensitive file untrusted: user=[USER-1] file=/etc/shadow 
process=cat container=[CONTAINER-1] image=nginx:latest
```

**LLM Analysis:**
```json
{
  "attack_vector": "Credential Access - /etc/shadow contains password hashes",
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique": "T1003.008 - /etc/passwd and /etc/shadow"
  },
  "risk_level": "High",
  "impact": "Attacker may extract password hashes for offline cracking",
  "mitigations": [
    "Investigate why nginx container needs to read /etc/shadow",
    "Review container security context - should not have CAP_DAC_READ_SEARCH",
    "Consider using read-only root filesystem",
    "Implement runtime protection to block sensitive file access"
  ],
  "next_steps": [
    "Check for other suspicious activity from this container",
    "Review container image for vulnerabilities",
    "Verify this is not a legitimate debugging session"
  ]
}
```

## Example Analysis Output

Here are real examples from analyzing alerts via the API:

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
