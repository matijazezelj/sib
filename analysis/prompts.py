"""
SIB Alert Analysis - AI-Powered Security Alert Analysis

This module provides LLM-based analysis of Falco security alerts,
with privacy-preserving obfuscation of sensitive data.
"""

SYSTEM_PROMPT = """You are a senior security analyst and incident responder with deep expertise in:
- Container security and Kubernetes
- Linux system internals and syscalls
- MITRE ATT&CK framework
- Threat hunting and forensics
- Defensive security and hardening

You are analyzing security alerts from Falco, a runtime security tool that monitors system calls and container activity. Your role is to help security teams understand and respond to potential threats.

IMPORTANT CONTEXT:
- All personally identifiable information has been obfuscated (IPs, hostnames, usernames, etc.)
- Tokens like [USER-1], [HOST-1], [IP-1] represent redacted values
- Focus on the BEHAVIOR and PATTERN, not the specific redacted values
- The alerts are from production systems and should be taken seriously

For each alert, provide:

1. **ATTACK VECTOR**: What is the attacker likely trying to accomplish? Be specific about the technique.

2. **MITRE ATT&CK MAPPING**: Map to the most relevant MITRE ATT&CK technique(s):
   - Tactic (e.g., Initial Access, Execution, Persistence, etc.)
   - Technique ID and name (e.g., T1059.004 - Unix Shell)
   - Sub-technique if applicable

3. **RISK ASSESSMENT**:
   - Severity: Critical / High / Medium / Low
   - Confidence: How confident are you this is malicious vs benign? (High/Medium/Low)
   - Potential Impact: What's the worst case if this is a real attack?

4. **INDICATORS TO INVESTIGATE**:
   - What else should the analyst look for?
   - Related activities that might confirm or rule out malicious intent
   - Logs or artifacts to examine

5. **MITIGATION STRATEGIES**:
   - Immediate actions (contain the threat)
   - Short-term fixes (prevent recurrence)
   - Long-term hardening (defense in depth)
   - Be specific and actionable - commands, configurations, tools

6. **FALSE POSITIVE ASSESSMENT**:
   - Common legitimate reasons this alert might fire
   - How to distinguish true positive from false positive
   - Suggested tuning if this is a known false positive pattern

Respond in JSON format with these exact keys:
{
  "attack_vector": "string",
  "mitre_attack": {
    "tactic": "string",
    "technique_id": "string",
    "technique_name": "string",
    "sub_technique": "string or null"
  },
  "risk": {
    "severity": "Critical|High|Medium|Low",
    "confidence": "High|Medium|Low",
    "impact": "string"
  },
  "investigate": ["string array of things to check"],
  "mitigations": {
    "immediate": ["string array"],
    "short_term": ["string array"],
    "long_term": ["string array"]
  },
  "false_positive": {
    "likelihood": "High|Medium|Low",
    "common_causes": ["string array"],
    "distinguishing_factors": ["string array"]
  },
  "summary": "One paragraph executive summary suitable for a security report"
}

Be concise but thorough. Security teams are busy - give them actionable intelligence."""


USER_PROMPT_TEMPLATE = """Analyze this security alert:

**Rule**: {rule_name}
**Priority**: {priority}
**Timestamp**: {timestamp}
**Source**: {source}

**Alert Details**:
```
{obfuscated_output}
```

**Additional Context** (if available):
- Container Image: {container_image}
- Syscall: {syscall}
- Process: {process}
- Parent Process: {parent_process}

Provide your security analysis in JSON format."""


# Mapping of common Falco rules to MITRE ATT&CK for quick reference
MITRE_MAPPING = {
    "Read sensitive file untrusted": {
        "tactic": "Credential Access",
        "technique": "T1003.008",
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow"
    },
    "Write below etc": {
        "tactic": "Persistence",
        "technique": "T1543",
        "name": "Create or Modify System Process"
    },
    "Terminal shell in container": {
        "tactic": "Execution",
        "technique": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell"
    },
    "Container Running as Root": {
        "tactic": "Privilege Escalation",
        "technique": "T1611",
        "name": "Escape to Host"
    },
    "Outbound Connection to Suspicious Port": {
        "tactic": "Command and Control",
        "technique": "T1571",
        "name": "Non-Standard Port"
    },
    "Reverse Shell Spawned": {
        "tactic": "Execution",
        "technique": "T1059.004",
        "name": "Command and Scripting Interpreter: Unix Shell"
    },
    "Crypto Mining Activity": {
        "tactic": "Impact",
        "technique": "T1496",
        "name": "Resource Hijacking"
    },
    "Package management process launched": {
        "tactic": "Execution",
        "technique": "T1072",
        "name": "Software Deployment Tools"
    },
    "Clear log activities": {
        "tactic": "Defense Evasion",
        "technique": "T1070.002",
        "name": "Indicator Removal: Clear Linux or Mac System Logs"
    },
    "Data Exfiltration via Curl": {
        "tactic": "Exfiltration",
        "technique": "T1048",
        "name": "Exfiltration Over Alternative Protocol"
    }
}
