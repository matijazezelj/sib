"""
AIB (Assets in a Box) bridge for SIB alert enrichment.

Fetches asset metadata, blast radius, and audit findings from the AIB graph API
to enrich Falco security alerts before LLM analysis.

Asset node ID format: source:type:identifier
  - k8s:pod:namespace/name
  - k8s:node:nodename
  - vm:host:hostname
  - ansible:vm:hostname
  - tf:vm:hostname
"""

import logging
import time
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)


class AIBClient:
    """Client for the AIB REST API with TTL caching."""

    def __init__(self, base_url: str, api_token: str | None = None,
                 ttl: int = 300, timeout: int = 5):
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.ttl = ttl
        self.timeout = timeout
        self._cache: dict = {}

    def _headers(self) -> dict:
        h = {'Accept': 'application/json'}
        if self.api_token:
            h['Authorization'] = f'Bearer {self.api_token}'
        return h

    def _get(self, path: str) -> dict | None:
        """Cached GET. Returns None on any error (including 404)."""
        now = time.monotonic()
        if path in self._cache:
            ts, data = self._cache[path]
            if now - ts < self.ttl:
                return data

        try:
            r = requests.get(
                f"{self.base_url}{path}",
                headers=self._headers(),
                timeout=self.timeout,
            )
            if r.status_code == 404:
                self._cache[path] = (now, None)
                return None
            r.raise_for_status()
            data = r.json()
            self._cache[path] = (now, data)
            return data
        except Exception as e:
            logger.debug("AIB request failed %s: %s", path, e)
            return None

    def get_node(self, node_id: str) -> dict | None:
        return self._get(f"/api/v1/graph/nodes/{node_id}")

    def get_blast_radius(self, node_id: str) -> dict | None:
        return self._get(f"/api/v1/impact/{node_id}")

    def get_audit_findings(self, node_id: str) -> list:
        data = self._get(f"/api/v1/graph/analysis/audit?node_id={quote(node_id, safe='')}")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get('findings') or data.get('results') or []
        return []

    def resolve_node(self, hostname: str) -> dict | None:
        """Find a node by hostname, regardless of IaC source prefix.

        Calls GET /api/v1/graph/nodes/resolve?hostname=<hostname>, which
        matches any node whose ID ends with :<hostname> — covering
        k8s:node:, ansible:vm:, tf:vm:, etc.
        """
        return self._get(f"/api/v1/graph/nodes/resolve?hostname={quote(hostname, safe='')}")

    def enrich_alert(self, alert: dict) -> dict:
        """
        Derive AIB context from Falco alert fields.

        Tries k8s pod lookup first (container.name + namespace), then VM/host
        lookup (host.hostname). Falls back to the /resolve endpoint which
        matches any source prefix (ansible:vm:, tf:vm:, k8s:node:, etc.).
        All lookups are best-effort — returns an empty context dict if the
        asset isn't in AIB or AIB is unreachable.

        Returns:
            {
                'node_id':        str | None,
                'node':           dict | None,   # raw AIB node metadata
                'blast_radius':   dict | None,
                'audit_findings': list,          # capped at 5 entries
            }
        """
        output_fields = alert.get('output_fields', {})
        labels = alert.get('_labels', {})

        container_name = (
            output_fields.get('container.name')
            or labels.get('container_name', '')
        )
        namespace = (
            output_fields.get('kubernetes.namespace.name')
            or labels.get('namespace', 'default')
        )
        hostname = (
            output_fields.get('host.hostname')
            or output_fields.get('hostname')
            or labels.get('hostname', '')
        )

        node = None
        node_id = None

        if container_name and container_name not in ('', 'host', '<NA>'):
            node_id = f"k8s:pod:{namespace}/{container_name}"
            node = self.get_node(node_id)

        if node is None and hostname:
            # Try well-known exact-prefix formats first
            for candidate in (f"k8s:node:{hostname}", f"vm:host:{hostname}"):
                node = self.get_node(candidate)
                if node:
                    node_id = candidate
                    break

            # Fallback: resolve endpoint matches ansible:vm:, tf:vm:, etc.
            if node is None:
                resolved = self.resolve_node(hostname)
                if resolved:
                    node = resolved
                    node_id = resolved.get('id', f"unknown:vm:{hostname}")

        blast_radius = None
        audit_findings: list = []

        if node_id:
            blast_radius = self.get_blast_radius(node_id)
            audit_findings = self.get_audit_findings(node_id)[:5]

        return {
            'node_id': node_id,
            'node': node,
            'blast_radius': blast_radius,
            'audit_findings': audit_findings,
        }


def format_aib_context(ctx: dict) -> str:
    """
    Render AIB enrichment context as a prompt section.

    Returns an empty string if no useful context is available so the
    caller can safely concatenate without branching.
    """
    if not ctx or not ctx.get('node'):
        return ''

    node = ctx['node']
    node_id = ctx.get('node_id', 'unknown')

    lines = ['\n\n**Asset Context (AIB graph):**']
    lines.append(f'- Asset ID: `{node_id}`')

    # Surface any structured metadata the AIB node carries.
    # AIB may store Kubernetes labels as "label:key" — strip the prefix.
    raw_meta = node.get('metadata') or node.get('properties') or node.get('labels') or {}
    meta = {k.removeprefix('label:'): v for k, v in raw_meta.items()}
    for key in ('environment', 'team', 'criticality', 'owner', 'service'):
        val = meta.get(key)
        if val:
            lines.append(f'- {key.title()}: {val}')

    # Blast radius.
    # AIB returns: affected_nodes (int count) + nodes (flat list, added in feat/sib-integration)
    # Older AIB: impact_tree (keyed map). Handle all three.
    br = ctx.get('blast_radius')
    if br:
        node_list = br.get('nodes') or list(br.get('impact_tree', {}).values())
        count = br.get('affected_nodes', len(node_list))
        if count or node_list:
            lines.append(f'- Blast radius: {count} downstream assets')
            for n in node_list[:3]:
                nid = n.get('node_id') or n.get('id') or str(n)
                lines.append(f'  - {nid}')

    # Pre-existing audit findings.
    findings = ctx.get('audit_findings') or []
    if findings:
        lines.append(f'- Pre-existing audit findings ({len(findings)}):')
        for f in findings:
            if isinstance(f, dict):
                title = (f.get('title') or f.get('description')
                         or f.get('finding') or f.get('message') or str(f))
            else:
                title = str(f)
            lines.append(f'  - {title}')

    return '\n'.join(lines)
