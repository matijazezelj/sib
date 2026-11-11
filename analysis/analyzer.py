"""
SIB Alert Analyzer - LLM-powered security alert analysis

Fetches alerts from VictoriaLogs or Loki, obfuscates sensitive data, and uses LLM
to provide attack vector analysis and mitigation strategies.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta
from typing import ClassVar

import requests
import yaml
from obfuscator import ObfuscationLevel, Obfuscator, obfuscate_alert
from prompts import MITRE_MAPPING, SYSTEM_PROMPT, USER_PROMPT_TEMPLATE


class LogClient:
    """Base class for log storage clients."""

    def query_range(self, query: str, start: datetime, end: datetime, limit: int = 100) -> list[dict]:
        raise NotImplementedError

    def push(self, labels: dict[str, str], log_line: str, timestamp: datetime | None = None) -> bool:
        raise NotImplementedError


class LokiClient(LogClient):
    """Client for querying alerts from Loki."""
    
    def __init__(self, url: str = "http://localhost:3100"):
        self.url = url.rstrip('/')
    
    def query_range(self, query: str, start: datetime, end: datetime, limit: int = 100) -> list[dict]:
        """Query Loki for logs in a time range."""
        params = {
            'query': query,
            'start': int(start.timestamp() * 1e9),
            'end': int(end.timestamp() * 1e9),
            'limit': limit,
        }
        
        response = requests.get(f"{self.url}/loki/api/v1/query_range", params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        alerts = []
        
        for stream in data.get('data', {}).get('result', []):
            labels = stream.get('stream', {})
            for value in stream.get('values', []):
                timestamp_ns, log_line = value
                try:
                    alert = json.loads(log_line)
                except json.JSONDecodeError:
                    alert = {'output': log_line}
                
                alert['_labels'] = labels
                alert['_timestamp'] = datetime.fromtimestamp(int(timestamp_ns) / 1e9)
                alerts.append(alert)
        
        return alerts
    
    def push(self, labels: dict[str, str], log_line: str, timestamp: datetime | None = None) -> bool:
        """Push a log entry to Loki."""
        if timestamp is None:
            timestamp = datetime.now()
        
        # Loki push API expects nanosecond timestamps as strings
        ts_ns = str(int(timestamp.timestamp() * 1e9))
        
        payload = {
            "streams": [
                {
                    "stream": labels,
                    "values": [[ts_ns, log_line]]
                }
            ]
        }
        
        try:
            response = requests.post(
                f"{self.url}/loki/api/v1/push",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Failed to push to Loki: {e}", file=sys.stderr)
            return False


class VictoriaLogsClient(LogClient):
    """Client for querying alerts from VictoriaLogs."""

    def __init__(self, url: str = "http://localhost:9428"):
        self.url = url.rstrip('/')

    def query_range(self, query: str, start: datetime, end: datetime, limit: int = 100) -> list[dict]:
        """Query VictoriaLogs for logs in a time range using LogsQL."""
        params = {
            'query': query,
            'start': start.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'end': end.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'limit': limit,
        }

        response = requests.get(f"{self.url}/select/logsql/query", params=params, timeout=30)
        response.raise_for_status()

        alerts = []
        for line in response.text.strip().split('\n'):
            if not line:
                continue
            try:
                entry = json.loads(line)
                msg = entry.get('_msg', '')
                try:
                    alert = json.loads(msg)
                except (json.JSONDecodeError, TypeError):
                    alert = {'output': msg}

                # Non-underscore fields are labels
                labels = {k: v for k, v in entry.items() if not k.startswith('_')}
                alert['_labels'] = labels

                ts = entry.get('_time', '')
                try:
                    alert['_timestamp'] = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    alert['_timestamp'] = datetime.now()

                alerts.append(alert)
            except json.JSONDecodeError:
                continue

        return alerts

    def push(self, labels: dict[str, str], log_line: str, timestamp: datetime | None = None) -> bool:
        """Push a log entry to VictoriaLogs via JSON line protocol."""
        if timestamp is None:
            timestamp = datetime.now()

        entry = {
            '_msg': log_line,
            '_time': timestamp.isoformat(),
        }
        entry.update(labels)

        try:
            response = requests.post(
                f"{self.url}/insert/jsonline",
                data=json.dumps(entry) + '\n',
                headers={"Content-Type": "application/stream+x-ndjson"},
                timeout=30
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Failed to push to VictoriaLogs: {e}", file=sys.stderr)
            return False


class LLMProvider:
    """Base class for LLM providers."""
    
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        raise NotImplementedError


class OllamaProvider(LLMProvider):
    """Local Ollama LLM provider."""
    
    def __init__(self, url: str = "http://localhost:11434", model: str = "llama3.1:8b"):
        self.url = url.rstrip('/')
        self.model = model
    
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        response = requests.post(
            f"{self.url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": False,
                "format": "json"
            },
            timeout=120
        )
        response.raise_for_status()
        
        content = response.json().get('message', {}).get('content', '{}')
        return json.loads(content)


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""
    
    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        self.api_key = api_key
        self.model = model
    
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "response_format": {"type": "json_object"}
            },
            timeout=60
        )
        response.raise_for_status()
        
        content = response.json()['choices'][0]['message']['content']
        return json.loads(content)


class AnalysisRejected(Exception):
    """A model answered, but the answer can't be used (bad JSON, refusal, cut off)."""


_SEVERITIES = {'critical', 'high', 'medium', 'low'}


def validate_analysis(analysis: object) -> None:
    """Cheap check that an LLM answer is a usable alert analysis.

    Raises AnalysisRejected naming the first problem. This is the "test" that
    decides whether a cheaper tier's answer is kept or the alert is escalated.
    """
    if not isinstance(analysis, dict):
        raise AnalysisRejected("answer is not a JSON object")
    for key in ('attack_vector', 'summary'):
        if not isinstance(analysis.get(key), str) or not analysis[key].strip():
            raise AnalysisRejected(f"missing '{key}'")
    mitre = analysis.get('mitre_attack')
    if not isinstance(mitre, dict) or not re.fullmatch(r'T\d{4}(\.\d{3})?', str(mitre.get('technique_id', ''))):
        raise AnalysisRejected("missing or malformed mitre_attack.technique_id")
    risk = analysis.get('risk')
    if not isinstance(risk, dict) or str(risk.get('severity', '')).lower() not in _SEVERITIES:
        raise AnalysisRejected("missing or invalid risk.severity")
    if not isinstance(analysis.get('mitigations'), dict):
        raise AnalysisRejected("missing 'mitigations'")


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider with a cheap-first escalation ladder.

    Alert triage is high-volume structured extraction, so it starts on the
    smallest model and only escalates the alerts whose answer fails
    validate_analysis(): first the same model one effort level up, then the
    next model up at a lower effort. Each tier is {"model", "effort"}.
    """

    API_URL = "https://api.anthropic.com/v1/messages"

    DEFAULT_TIERS: ClassVar[list[dict]] = [
        {"model": "claude-haiku-5-5", "effort": "medium"},
        {"model": "claude-haiku-5-5", "effort": "high"},
        {"model": "claude-sonnet-5-5", "effort": "medium"},
    ]

    # USD per million tokens: (input, output, cache read). Haiku 5.5 prices are
    # for prompts up to 100K tokens, which alert prompts stay well under.
    PRICES: ClassVar[dict[str, tuple[float, float, float]]] = {
        "claude-haiku-5-5": (0.10, 0.50, 0.01),
        "claude-sonnet-5-5": (2.00, 10.00, 0.10),
        "claude-opus-5-5": (4.00, 20.00, 0.20),
        "claude-fable-5-2": (8.00, 40.00, 0.20),
    }

    def __init__(self, api_key: str, model: str = "", effort: str = "medium",
                 tiers: list[dict] | None = None):
        self.api_key = api_key
        if tiers:
            self.tiers = [{"model": t["model"], "effort": t.get("effort", "medium")} for t in tiers]
        elif model:
            # A pinned model means no ladder: one tier, as before.
            self.tiers = [{"model": model, "effort": effort or "medium"}]
        else:
            self.tiers = [dict(t) for t in self.DEFAULT_TIERS]
        self.model = self.tiers[0]["model"]
        # Per-call record of tiers tried, tokens and estimated cost.
        self.last_run: dict = {}

    def _request(self, tier: dict, system_prompt: str, user_prompt: str) -> dict:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        body = {
            "model": tier["model"],
            "max_tokens": 16000,
            "system": system_prompt,
            "output_config": {"effort": tier["effort"]},
            "messages": [{"role": "user", "content": user_prompt}],
        }
        # Security alerts can trip the cyber safety classifier. Above Haiku,
        # let the API re-run a declined request on a fallback model itself.
        if not tier["model"].startswith("claude-haiku"):
            headers["anthropic-beta"] = "server-side-fallback-2026-07-01"
            body["fallbacks"] = "default"
        response = requests.post(self.API_URL, headers=headers, json=body, timeout=120)
        response.raise_for_status()
        return response.json()

    def _cost(self, model: str, usage: dict) -> float:
        price_in, price_out, price_cache = self.PRICES.get(model, (0.0, 0.0, 0.0))
        return (usage.get('input_tokens', 0) * price_in
                + usage.get('cache_creation_input_tokens', 0) * price_in * 1.25
                + usage.get('cache_read_input_tokens', 0) * price_cache
                + usage.get('output_tokens', 0) * price_out) / 1_000_000

    @staticmethod
    def _parse(data: dict) -> dict:
        stop = data.get('stop_reason')
        if stop == 'refusal':
            category = (data.get('stop_details') or {}).get('category')
            raise AnalysisRejected(f"model declined (category: {category})")
        if stop == 'max_tokens':
            raise AnalysisRejected("answer cut off at max_tokens")
        # Responses can open with thinking blocks: read text blocks by type.
        content = "".join(b.get('text', '') for b in data.get('content', []) if b.get('type') == 'text')
        try:
            analysis = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if not match:
                raise AnalysisRejected("no JSON object in answer") from None
            try:
                analysis = json.loads(match.group())
            except json.JSONDecodeError as e:
                raise AnalysisRejected(f"invalid JSON: {e}") from None
        validate_analysis(analysis)
        return analysis

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        attempts = []
        self.last_run = {'attempts': attempts}
        for tier in self.tiers:
            data = self._request(tier, system_prompt, user_prompt)
            usage = data.get('usage') or {}
            served_by = data.get('model', tier['model'])
            attempt = {
                'model': served_by,
                'effort': tier['effort'],
                'input_tokens': usage.get('input_tokens', 0),
                'output_tokens': usage.get('output_tokens', 0),
                'cost_usd': round(self._cost(served_by, usage), 6),
            }
            attempts.append(attempt)
            try:
                analysis = self._parse(data)
            except AnalysisRejected as e:
                attempt['rejected'] = str(e)
                print(f"{tier['model']} @ {tier['effort']}: {e}; escalating", file=sys.stderr)
                continue
            self.last_run.update(model=served_by, effort=tier['effort'])
            return analysis
        reasons = "; ".join(f"{a['model']}@{a['effort']}: {a['rejected']}" for a in attempts)
        raise AnalysisRejected(f"every tier failed ({reasons})")

    def run_summary(self) -> dict:
        """Tiers tried for the last alert, with total tokens and estimated cost."""
        attempts = self.last_run.get('attempts', [])
        return {
            **self.last_run,
            'total_cost_usd': round(sum(a['cost_usd'] for a in attempts), 6),
            'escalations': max(len(attempts) - 1, 0),
        }


class AlertAnalyzer:
    """Main analyzer class that coordinates obfuscation and LLM analysis."""

    def __init__(self, config: dict):
        self.config = config
        self.backend = config.get('storage', {}).get('backend', 'loki')
        if self.backend in ('victorialogs', 'vm'):
            vl_url = config.get('victorialogs', {}).get('url', 'http://localhost:9428')
            self.log_client = VictoriaLogsClient(vl_url)
            self.backend = 'victorialogs'
        else:
            self.log_client = LokiClient(config.get('loki', {}).get('url', 'http://localhost:3100'))
            self.backend = 'loki'
        self.obfuscation_level = config.get('analysis', {}).get('obfuscation_level', 'standard')
        self.provider = self._create_provider()
        self.aib_client = self._create_aib_client()
    
    def _create_aib_client(self):
        """Create AIB client if configured. Returns None if AIB is not set up."""
        aib_cfg = self.config.get('aib', {})
        base_url = aib_cfg.get('url') or os.environ.get('AIB_BASE_URL', '')
        if not base_url:
            return None
        try:
            from aib_bridge import AIBClient
            api_token = aib_cfg.get('api_token') or os.environ.get('AIB_API_TOKEN')
            ttl = int(aib_cfg.get('cache_ttl', 300))
            return AIBClient(base_url, api_token=api_token, ttl=ttl)
        except ImportError:
            print("aib_bridge not found — AIB enrichment disabled", file=sys.stderr)
            return None

    def _create_provider(self) -> LLMProvider:
        """Create the configured LLM provider."""
        analysis_config = self.config.get('analysis', {})
        provider_name = analysis_config.get('provider', 'ollama')
        
        if provider_name == 'ollama':
            ollama_config = analysis_config.get('ollama', {})
            return OllamaProvider(
                url=ollama_config.get('url', 'http://localhost:11434'),
                model=ollama_config.get('model', 'llama3.1:8b')
            )
        elif provider_name == 'openai':
            openai_config = analysis_config.get('openai', {})
            api_key = os.path.expandvars(openai_config.get('api_key', ''))
            return OpenAIProvider(
                api_key=api_key,
                model=openai_config.get('model', 'gpt-4o-mini')
            )
        elif provider_name == 'anthropic':
            anthropic_config = analysis_config.get('anthropic', {})
            api_key = os.path.expandvars(anthropic_config.get('api_key', ''))
            return AnthropicProvider(
                api_key=api_key,
                model=anthropic_config.get('model') or '',
                effort=anthropic_config.get('effort') or 'medium',
                tiers=anthropic_config.get('tiers') or None,
            )
        else:
            raise ValueError(f"Unknown provider: {provider_name}")
    
    def fetch_alerts(self, priority: str | None = None, 
                     last: str = "1h", limit: int = 10) -> list[dict]:
        """Fetch alerts from the configured log storage backend."""
        # Parse time duration
        duration_map = {'m': 'minutes', 'h': 'hours', 'd': 'days'}
        unit = last[-1]
        if unit not in duration_map:
            raise ValueError(f"Invalid time unit '{unit}'. Use 'm' (minutes), 'h' (hours), or 'd' (days).")
        value = int(last[:-1])
        delta = timedelta(**{duration_map[unit]: value})
        
        end = datetime.now()
        start = end - delta
        
        # Build query based on backend
        if self.backend == 'victorialogs':
            query = 'source:syscall'
            if priority:
                query += f' AND priority:{priority}'
        else:
            if priority:
                query = f'{{source="syscall", priority="{priority}"}}'
            else:
                query = '{source="syscall"}'
        
        return self.log_client.query_range(query, start, end, limit)
    
    def analyze_alert(self, alert: dict, dry_run: bool = False) -> dict:
        """Analyze a single alert."""
        # One obfuscator for the whole prompt: the alert body and every
        # enrichment appended below must resolve the same value to the same
        # token, and nothing may reach the model unobfuscated.
        obfuscator = Obfuscator(ObfuscationLevel(self.obfuscation_level))
        obfuscated, _ = obfuscate_alert(
            alert, self.obfuscation_level, obfuscator=obfuscator
        )

        # Enrich with AIB asset context (graceful — alert still analyzed without it)
        aib_context: dict = {}
        if self.aib_client:
            try:
                from aib_bridge import format_aib_context
                aib_context = self.aib_client.enrich_alert(alert)
            except Exception as e:
                print(f"AIB enrichment skipped: {e}", file=sys.stderr)

        # Build the prompt
        labels = alert.get('_labels', {})
        user_prompt = USER_PROMPT_TEMPLATE.format(
            rule_name=labels.get('rule', alert.get('rule', 'Unknown')),
            priority=labels.get('priority', alert.get('priority', 'Unknown')),
            timestamp=alert.get('_timestamp', 'Unknown'),
            source=labels.get('source', 'syscall'),
            obfuscated_output=obfuscated.get('output') or obfuscator.obfuscate(str(obfuscated)),
            container_image=obfuscated.get('output_fields', {}).get('container.image.repository', 'N/A'),
            syscall=obfuscated.get('output_fields', {}).get('syscall.type', 'N/A'),
            process=obfuscated.get('output_fields', {}).get('proc.name', 'N/A'),
            parent_process=obfuscated.get('output_fields', {}).get('proc.pname', 'N/A'),
        )

        # Append AIB context to prompt if available
        if aib_context:
            from aib_bridge import format_aib_context
            aib_section = format_aib_context(aib_context)
            if aib_section:
                user_prompt += obfuscator.obfuscate(aib_section)

        if dry_run:
            return {
                'obfuscated_prompt': user_prompt,
                'obfuscation_mapping': obfuscator.get_mapping(),
                'aib_context': aib_context,
                'note': 'Dry run - no LLM call made'
            }

        # Get quick MITRE mapping if available
        rule_name = labels.get('rule', alert.get('rule', ''))
        quick_mitre = MITRE_MAPPING.get(rule_name, None)

        # Call LLM
        try:
            analysis = self.provider.analyze(SYSTEM_PROMPT, user_prompt)
        except Exception as e:
            analysis = {
                'error': str(e),
                'fallback_mitre': quick_mitre
            }

        result = {
            'original_alert': alert,
            'obfuscated_alert': obfuscated,
            'obfuscation_mapping': obfuscator.get_mapping(),
            'aib_context': aib_context,
            'analysis': analysis
        }
        if hasattr(self.provider, 'run_summary'):
            result['llm'] = self.provider.run_summary()
        return result
    
    def store_analysis(self, result: dict) -> bool:
        """Store analysis result in Loki."""
        analysis = result.get('analysis', {})
        original = result.get('original_alert', {})
        labels = original.get('_labels', {})
        
        # Build labels for the enriched alert
        mitre = analysis.get('mitre_attack', {})
        risk = analysis.get('risk', {})
        fp = analysis.get('false_positive', {})
        
        enriched_labels = {
            'source': 'analysis',
            'type': 'enriched',
            'original_rule': labels.get('rule', 'unknown'),
            'original_priority': labels.get('priority', 'unknown'),
            'hostname': labels.get('hostname', 'unknown'),
            'severity': risk.get('severity', 'unknown').lower(),
            'mitre_tactic': mitre.get('tactic', 'unknown').replace(' ', '_'),
            'mitre_technique': mitre.get('technique_id', 'unknown'),
            'false_positive': str(fp.get('likelihood', 'unknown')).lower(),
        }
        
        # Build the enriched log entry
        enriched_entry = {
            'timestamp': original.get('_timestamp', datetime.now()).isoformat() if isinstance(original.get('_timestamp'), datetime) else str(original.get('_timestamp', '')),
            'original_output': original.get('output', ''),
            'rule': labels.get('rule', ''),
            'priority': labels.get('priority', ''),
            'hostname': labels.get('hostname', ''),
            'attack_vector': analysis.get('attack_vector', ''),
            'mitre_attack': mitre,
            'risk': risk,
            'mitigations': analysis.get('mitigations', {}),
            'false_positive': analysis.get('false_positive', {}),
            'summary': analysis.get('summary', ''),
            'investigate': analysis.get('investigate', []),
        }
        
        return self.log_client.push(
            enriched_labels,
            json.dumps(enriched_entry),
            original.get('_timestamp')
        )
    
    def analyze_batch(self, alerts: list[dict], dry_run: bool = False, store: bool = False) -> list[dict]:
        """Analyze multiple alerts."""
        results = []
        backend_name = 'VictoriaLogs' if self.backend == 'victorialogs' else 'Loki'
        for i, alert in enumerate(alerts):
            print(f"Analyzing alert {i+1}/{len(alerts)}...", file=sys.stderr)
            result = self.analyze_alert(alert, dry_run)
            results.append(result)
            
            # Store in log backend if requested
            if store and not dry_run and 'error' not in result.get('analysis', {}):
                if self.store_analysis(result):
                    print(f"  ✓ Stored analysis in {backend_name}", file=sys.stderr)
                else:
                    print("  ✗ Failed to store analysis", file=sys.stderr)
        
        return results


def read_secret(env_var: str) -> str | None:
    """Read a secret from env var or Docker secret file.

    Supports the Docker Secrets convention: if {ENV_VAR}_FILE is set,
    read the secret from that file path instead of the env var directly.
    This allows secure secret injection without embedding values in env vars.
    """
    file_path = os.environ.get(f"{env_var}_FILE")
    if file_path:
        try:
            with open(file_path) as f:
                return f.read().strip()
        except OSError:
            pass
    return os.environ.get(env_var)


# Environment variable names that should support Docker Secrets (_FILE suffix)
_SECRET_VARS = {'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GRAFANA_ADMIN_PASSWORD'}


def expand_env_vars(obj):
    """Recursively expand environment variables in config values.

    Supports Docker Secrets: for known secret variables, checks for
    a {VAR}_FILE env pointing to a file containing the secret value.
    """
    if isinstance(obj, dict):
        return {k: expand_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        # Handle ${VAR:-default} and ${VAR} patterns
        def replace_var(match):
            var_name = match.group(1)
            default = match.group(3) if match.group(3) else ''
            # Use Docker Secrets-aware lookup for secret vars
            if var_name in _SECRET_VARS:
                value = read_secret(var_name)
                return value if value is not None else default
            return os.environ.get(var_name, default)
        # Pattern matches ${VAR} or ${VAR:-default}
        return re.sub(r'\$\{([^}:]+)(:-([^}]*))?\}', replace_var, obj)
    return obj


def load_config(config_path: str | None = None) -> dict:
    """Load configuration from file with environment variable expansion."""
    config = None
    
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            config = yaml.safe_load(f)
    else:
        # Try default locations
        default_paths = [
            'config.yaml',
            os.path.expanduser('~/.config/sib/analysis.yaml'),
            '/etc/sib/analysis.yaml'
        ]
        
        for path in default_paths:
            if os.path.exists(path):
                with open(path) as f:
                    config = yaml.safe_load(f)
                    break
    
    if config:
        return expand_env_vars(config)
    
    # Return minimal default config
    return {
        'analysis': {
            'enabled': True,
            'obfuscation_level': 'standard',
            'provider': 'ollama',
            'ollama': {
                'url': 'http://localhost:11434',
                'model': 'llama3.1:8b'
            }
        },
        'storage': {
            'backend': os.environ.get('STACK', 'loki'),
        },
        'loki': {
            'url': 'http://localhost:3100'
        },
        'victorialogs': {
            'url': 'http://localhost:9428'
        }
    }


def print_analysis(result: dict, verbose: bool = False):
    """Pretty print analysis results."""
    # A dry run has no 'analysis' key — show the obfuscated prompt instead, which
    # is the whole point of the mode.
    if 'obfuscated_prompt' in result:
        print("\n" + "="*70)
        print("🔐 DRY RUN - EXACTLY WHAT WOULD BE SENT TO THE LLM")
        print("="*70)
        print(result['obfuscated_prompt'])
        mapping = result.get('obfuscation_mapping', {})
        if any(v for v in mapping.values()):
            print("\n" + "-"*70)
            print("Obfuscation mapping (stays local, never sent):")
            print(json.dumps(mapping, indent=2))
        print("\n" + "="*70)
        return

    analysis = result.get('analysis', {})

    if 'error' in analysis:
        print(f"\n❌ Analysis Error: {analysis['error']}")
        if analysis.get('fallback_mitre'):
            print(f"   Fallback MITRE: {analysis['fallback_mitre']}")
        return
    
    print("\n" + "="*70)
    print("🔍 SECURITY ALERT ANALYSIS")
    print("="*70)
    
    # Attack Vector
    print("\n🎯 Attack Vector:")
    print(f"   {analysis.get('attack_vector', 'N/A')}")
    
    # MITRE ATT&CK
    mitre = analysis.get('mitre_attack', {})
    print("\n📊 MITRE ATT&CK:")
    print(f"   Tactic: {mitre.get('tactic', 'N/A')}")
    print(f"   Technique: {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}")
    if mitre.get('sub_technique'):
        print(f"   Sub-technique: {mitre.get('sub_technique')}")
    
    # Risk Assessment
    risk = analysis.get('risk', {})
    severity_colors = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
    print("\n⚠️  Risk Assessment:")
    print(f"   Severity: {severity_colors.get(risk.get('severity', ''), '⚪')} {risk.get('severity', 'N/A')}")
    print(f"   Confidence: {risk.get('confidence', 'N/A')}")
    print(f"   Impact: {risk.get('impact', 'N/A')}")
    
    # Mitigations
    mitigations = analysis.get('mitigations', {})
    print("\n🛡️  Mitigations:")
    if mitigations.get('immediate'):
        print("   Immediate:")
        for m in mitigations['immediate']:
            print(f"     • {m}")
    if mitigations.get('short_term'):
        print("   Short-term:")
        for m in mitigations['short_term']:
            print(f"     • {m}")
    if mitigations.get('long_term'):
        print("   Long-term:")
        for m in mitigations['long_term']:
            print(f"     • {m}")
    
    # False Positive
    fp = analysis.get('false_positive', {})
    print("\n🤔 False Positive Assessment:")
    print(f"   Likelihood: {fp.get('likelihood', 'N/A')}")
    if fp.get('common_causes'):
        print("   Common legitimate causes:")
        for cause in fp['common_causes'][:3]:
            print(f"     • {cause}")
    
    # Summary
    print("\n📝 Summary:")
    print(f"   {analysis.get('summary', 'N/A')}")
    
    llm = result.get('llm')
    if llm and llm.get('attempts'):
        tiers = " → ".join(f"{a['model']}@{a['effort']}" for a in llm['attempts'])
        print(f"\n💰 Model: {tiers}  (~${llm.get('total_cost_usd', 0):.4f})")

    if verbose:
        print("\n🔐 Obfuscation Mapping:")
        print(json.dumps(result.get('obfuscation_mapping', {}), indent=2))

    print("\n" + "="*70)


def main():
    parser = argparse.ArgumentParser(
        description='SIB Alert Analyzer - AI-powered security alert analysis'
    )
    parser.add_argument('--config', '-c', help='Path to config file')
    parser.add_argument('--priority', '-p', choices=['Critical', 'Error', 'Warning', 'Notice'],
                        help='Filter by priority')
    parser.add_argument('--last', '-l', default='1h',
                        help='Time range (e.g., 15m, 1h, 24h, 7d)')
    parser.add_argument('--limit', '-n', type=int, default=5,
                        help='Maximum number of alerts to analyze')
    parser.add_argument('--dry-run', '-d', action='store_true',
                        help='Show obfuscated data without calling LLM')
    parser.add_argument('--store', '-s', action='store_true',
                        help='Store analysis results in Loki for Grafana dashboards')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed output including obfuscation mapping')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output raw JSON instead of formatted text')
    parser.add_argument('--loki-url', help='Override Loki URL')
    parser.add_argument('--victorialogs-url', help='Override VictoriaLogs URL')
    parser.add_argument('--backend', '-b', choices=['loki', 'vm', 'victorialogs'],
                        help='Storage backend (default: auto-detect from STACK env)')
    
    args = parser.parse_args()
    
    # Load config
    config = load_config(args.config)
    
    # Override with CLI args
    if args.backend:
        config.setdefault('storage', {})['backend'] = args.backend
    if args.loki_url:
        config.setdefault('loki', {})['url'] = args.loki_url
        config.setdefault('storage', {})['backend'] = 'loki'
    if args.victorialogs_url:
        config.setdefault('victorialogs', {})['url'] = args.victorialogs_url
        config.setdefault('storage', {})['backend'] = 'victorialogs'
    
    # Check if analysis is enabled
    if not config.get('analysis', {}).get('enabled', True):
        print("Analysis is disabled in config. Set analysis.enabled: true to enable.")
        sys.exit(1)
    
    # Create analyzer
    analyzer = AlertAnalyzer(config)
    
    # Fetch alerts
    print(f"Fetching alerts from last {args.last}...", file=sys.stderr)
    alerts = analyzer.fetch_alerts(priority=args.priority, last=args.last, limit=args.limit)
    
    if not alerts:
        print("No alerts found matching criteria.")
        sys.exit(0)
    
    print(f"Found {len(alerts)} alerts. Analyzing...", file=sys.stderr)
    
    # Analyze
    results = analyzer.analyze_batch(alerts, dry_run=args.dry_run, store=args.store)
    
    # Output
    if args.json:
        # JSON output - convert datetime to string
        def json_serial(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        print(json.dumps(results, indent=2, default=json_serial))
    else:
        for result in results:
            print_analysis(result, verbose=args.verbose)


if __name__ == '__main__':
    main()
