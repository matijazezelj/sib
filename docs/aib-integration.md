---
layout: default
title: AIB Integration - SIEM in a Box
---

# AIB Integration — Asset-Enriched Alert Analysis

[← Back to Home](index.md)

> **Optional Feature**: Requires [Assets in a Box (AIB)](https://github.com/matijazezelj/aib) running and accessible from the SIB analysis container.

## What Is AIB?

Assets in a Box (AIB) is a graph-based asset inventory. It models your infrastructure as a graph of nodes (Kubernetes pods, VMs, hosts, services) with relationships between them — ownership, network adjacency, dependency chains.

Each node carries:
- **Metadata** — environment, team, owner, criticality, service name
- **Blast radius** — which downstream assets are reachable if this node is compromised
- **Audit findings** — pre-existing security findings from previous scans

## What the Integration Does

Without AIB, SIB analyzes Falco alerts purely from the event payload — process name, syscall, file path, priority. The LLM has no idea *what* the affected asset is, who owns it, or what it connects to.

With AIB, before the alert reaches the LLM:

1. **Asset lookup** — SIB takes the container name and namespace (for Kubernetes) or the hostname from the alert and looks up the AIB node
2. **Blast radius fetch** — how many downstream assets are reachable if this node is compromised
3. **Audit findings fetch** — any pre-existing findings on this asset (misconfigurations, CVEs, compliance gaps)
4. **Prompt injection** — all of this is appended to the LLM prompt as structured context

The result: the LLM can reason about *actual impact*, not just the raw event. A `Read sensitive file` alert on an internet-facing payment service that has 12 downstream dependencies hits differently than the same alert on an internal dev sandbox.

## Data Flow

```
Alert
    │
    ▼
AlertAnalyzer.analyze_alert()
    │
    ├─► Obfuscator (alert text)
    │
    ├─► AIBClient.enrich_alert()
    │       │
    │       ├─ k8s:pod:<ns>/<name>
    │       │   fallback: k8s:node:<hostname>
    │       │             vm:host:<hostname>
    │       │             GET /api/v1/graph/nodes/resolve?hostname=
    │       │
    │       ├─ GET /api/v1/graph/nodes/{node_id}         → asset metadata
    │       ├─ GET /api/v1/impact/{node_id}              → blast radius
    │       └─ GET /api/v1/graph/analysis/audit?node_id= → audit findings (first 5)
    │
    ├─► LLM prompt (alert + AIB context, obfuscated with the same tokens)
    │
    └─► Analysis result (with aib_context field)
```

## Node ID Format

AIB uses a `source:type:identifier` format for node IDs. SIB tries these in order:

| Asset type | Node ID format | Alert fields used |
|------------|---------------|-------------------|
| Kubernetes pod | `k8s:pod:<namespace>/<pod-name>` | `container.name` (used as the pod name) + `kubernetes.namespace.name` (else `default`) |
| Kubernetes node | `k8s:node:<hostname>` | `host.hostname` or `hostname` |
| VM / bare-metal host | `vm:host:<hostname>` | same |
| Any other source (`ansible:vm:`, `tf:vm:`, …) | whatever AIB's resolve endpoint returns | same |

The pod lookup is skipped if the container name is empty, `host`, or `<NA>`.

The Grafana link and the JSON API pass only the hostname, so they get host lookups only. The pod lookup needs a `container.name` field (or a `container_name` label) in the alert, so it can only happen when the CLI analyzes stored alerts.

## Configuration

### 1. Set environment variables

In your `.env` file:

```bash
AIB_BASE_URL=http://aib:8080       # AIB API endpoint (Docker service name or IP)
AIB_API_TOKEN=your-aib-api-token   # Optional — omit if AIB has no auth
```

The URL must be reachable from the `sib-analysis` container, which is on `sib-network`.

### 2. Check `config.yaml`

The shipped `analysis/config.yaml` already has the `aib` block:

```yaml
aib:
  url: ${AIB_BASE_URL:-}       # leave empty to disable
  api_token: ${AIB_API_TOKEN:-}
  cache_ttl: 300               # seconds
```

### 3. Recreate the analysis service

```bash
make install-analysis
```

`make restart-analysis` does not pick up `.env` changes.

### Disabling AIB

Leave `AIB_BASE_URL` empty (or unset). The integration is fully opt-in — if the URL is not configured, no enrichment is attempted and no errors are raised.

## Graceful Degradation

AIB enrichment is best-effort at every step:

- **AIB URL not set** → enrichment skipped, alert analyzed normally
- **AIB unreachable** → request errors are ignored, analysis proceeds without asset context
- **Node not found in AIB (404)** → `node` is null, analysis proceeds without asset context
- **Partial data** (node found, blast radius unavailable) → whatever is available is included

The LLM prompt is constructed only from the fields that are actually populated. A missing blast radius or missing audit findings simply means that section is omitted from the prompt.

## Example Enriched Analysis

Given a Falco alert:
```
Read sensitive file untrusted: user=appuser file=/etc/shadow
container=payment-api namespace=production host=k8s-node-3
```

For a stored alert with these fields, the AIB bridge resolves `k8s:pod:production/payment-api` and adds this to the prompt. E-mail addresses and IPs in it are obfuscated; asset IDs, pod names and team names are sent as they are at the `standard` level.

```
**Asset Context (AIB graph):**
- Asset ID: `k8s:pod:production/payment-api`
- Environment: production
- Team: payments
- Criticality: critical
- Owner: [EMAIL-1]
- Blast radius: 8 downstream assets
  - k8s:pod:production/fraud-detection
  - k8s:pod:production/billing-service
  - k8s:pod:production/audit-logger
- Pre-existing audit findings (2):
  - Container running as root (CIS 5.4.1)
  - Privileged port binding enabled
```

The LLM now answers with awareness of criticality and blast radius:

```
Risk Assessment: CRITICAL
The affected service (payment-api) is classified as critical infrastructure
in the payments team. Compromise of this pod provides a foothold into 8
downstream services including fraud detection and billing. Combined with
the pre-existing finding that this container runs as root, the attacker
likely already has unrestricted access to the container filesystem.

Immediate actions:
1. Isolate payment-api pod — network policy to deny egress immediately
2. The audit finding "container running as root" amplifies this alert's
   severity — /etc/shadow is accessible without privilege escalation
3. Notify payments-eng team lead — this is a production critical-path service
```

Compare to the same alert without AIB enrichment, where the LLM would give generic advice with no knowledge of production impact.

## API Response

The `/api/analyze` JSON response includes an `aib_context` field with what AIB returned, not obfuscated:

```json
{
  "success": true,
  "analysis": { "...": "..." },
  "obfuscation_mapping": { "...": "..." },
  "aib_context": {
    "node_id": "k8s:node:web-01",
    "node": {
      "id": "k8s:node:web-01",
      "metadata": {
        "environment": "production",
        "team": "payments",
        "criticality": "critical"
      }
    },
    "blast_radius": { "affected_nodes": 8, "nodes": [] },
    "audit_findings": [
      { "title": "Container running as root", "severity": "high" }
    ]
  }
}
```

`aib_context` is `{}` when AIB is not configured. When the asset isn't found, `node` is null.

## Caching

AIB responses are cached in memory for `cache_ttl` seconds (default: 300) within one analyzer instance. A CLI run reuses them across its alerts. The API creates a new analyzer for each request, so it asks AIB again every time.

The analysis page cache (24 hours by default) stores `aib_context` with the result, so a cached page shows the asset state from the time of the analysis. See [Cache Deduplication](ai-analysis.md#cache-deduplication).

---

[← Back to Home](index.md) | [AI Analysis](ai-analysis.md)
