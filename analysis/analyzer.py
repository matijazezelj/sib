"""
SIB Alert Analyzer - LLM-powered security alert analysis

Fetches alerts from Loki, obfuscates sensitive data, and uses LLM
to provide attack vector analysis and mitigation strategies.
"""

import json
import os
import re
import sys
import argparse
import requests
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

import yaml

from obfuscator import obfuscate_alert, ObfuscationLevel
from prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE, MITRE_MAPPING


class LogClient:
    """Base class for log storage clients."""

    def query_range(self, query: str, start: datetime, end: datetime, limit: int = 100) -> List[dict]:
        raise NotImplementedError

    def push(self, labels: Dict[str, str], log_line: str, timestamp: Optional[datetime] = None) -> bool:
        raise NotImplementedError


class LokiClient(LogClient):
    """Client for querying alerts from Loki."""
    
    def __init__(self, url: str = "http://localhost:3100"):
        self.url = url.rstrip('/')
    
    def query_range(self, query: str, start: datetime, end: datetime, limit: int = 100) -> List[dict]:
        """Query Loki for logs in a time range."""
        params = {
            'query': query,
            'start': int(start.timestamp() * 1e9),
            'end': int(end.timestamp() * 1e9),
            'limit': limit,
        }
        
        response = requests.get(f"{self.url}/loki/api/v1/query_range", params=params)
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
    
    def push(self, labels: Dict[str, str], log_line: str, timestamp: Optional[datetime] = None) -> bool:
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
                headers={"Content-Type": "application/json"}
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

    def query_range(self, query: str, start: datetime, end: datetime, limit: int = 100) -> List[dict]:
        """Query VictoriaLogs for logs in a time range using LogsQL."""
        params = {
            'query': query,
            'start': start.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'end': end.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'limit': limit,
        }

        response = requests.get(f"{self.url}/select/logsql/query", params=params)
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

    def push(self, labels: Dict[str, str], log_line: str, timestamp: Optional[datetime] = None) -> bool:
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
                headers={"Content-Type": "application/stream+x-ndjson"}
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


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider."""
    
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model
    
    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": self.model,
                "max_tokens": 4096,
                "system": system_prompt,
                "messages": [
                    {"role": "user", "content": user_prompt}
                ]
            },
            timeout=60
        )
        response.raise_for_status()
        
        content = response.json()['content'][0]['text']
        # Extract JSON from response
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                return json.loads(match.group())
            raise


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
        # Backward compatibility alias
        self.loki = self.log_client
        self.obfuscation_level = config.get('analysis', {}).get('obfuscation_level', 'standard')
        self.provider = self._create_provider()
    
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
                model=anthropic_config.get('model', 'claude-3-haiku-20240307')
            )
        else:
            raise ValueError(f"Unknown provider: {provider_name}")
    
    def fetch_alerts(self, priority: Optional[str] = None, 
                     last: str = "1h", limit: int = 10) -> List[dict]:
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
        # Obfuscate the alert
        obfuscated, mapping = obfuscate_alert(alert, self.obfuscation_level)
        
        # Build the prompt
        labels = alert.get('_labels', {})
        user_prompt = USER_PROMPT_TEMPLATE.format(
            rule_name=labels.get('rule', alert.get('rule', 'Unknown')),
            priority=labels.get('priority', alert.get('priority', 'Unknown')),
            timestamp=alert.get('_timestamp', 'Unknown'),
            source=labels.get('source', 'syscall'),
            obfuscated_output=obfuscated.get('output', str(obfuscated)),
            container_image=obfuscated.get('output_fields', {}).get('container.image.repository', 'N/A'),
            syscall=obfuscated.get('output_fields', {}).get('syscall.type', 'N/A'),
            process=obfuscated.get('output_fields', {}).get('proc.name', 'N/A'),
            parent_process=obfuscated.get('output_fields', {}).get('proc.pname', 'N/A'),
        )
        
        if dry_run:
            return {
                'obfuscated_prompt': user_prompt,
                'obfuscation_mapping': mapping,
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
        
        return {
            'original_alert': alert,
            'obfuscated_alert': obfuscated,
            'obfuscation_mapping': mapping,
            'analysis': analysis
        }
    
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
    
    def analyze_batch(self, alerts: List[dict], dry_run: bool = False, store: bool = False) -> List[dict]:
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
                    print(f"  ✗ Failed to store analysis", file=sys.stderr)
        
        return results


def read_secret(env_var: str) -> Optional[str]:
    """Read a secret from env var or Docker secret file.

    Supports the Docker Secrets convention: if {ENV_VAR}_FILE is set,
    read the secret from that file path instead of the env var directly.
    This allows secure secret injection without embedding values in env vars.
    """
    file_path = os.environ.get(f"{env_var}_FILE")
    if file_path:
        try:
            with open(file_path, 'r') as f:
                return f.read().strip()
        except OSError:
            pass
    return os.environ.get(env_var)


# Environment variable names that should support Docker Secrets (_FILE suffix)
_SECRET_VARS = {'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'OLLAMA_API_KEY', 'GRAFANA_ADMIN_PASSWORD'}


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


def load_config(config_path: Optional[str] = None) -> dict:
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
    analysis = result.get('analysis', {})
    
    if 'error' in analysis:
        print(f"\n❌ Analysis Error: {analysis['error']}")
        if 'fallback_mitre' in analysis and analysis['fallback_mitre']:
            print(f"   Fallback MITRE: {analysis['fallback_mitre']}")
        return
    
    print("\n" + "="*70)
    print("🔍 SECURITY ALERT ANALYSIS")
    print("="*70)
    
    # Attack Vector
    print(f"\n🎯 Attack Vector:")
    print(f"   {analysis.get('attack_vector', 'N/A')}")
    
    # MITRE ATT&CK
    mitre = analysis.get('mitre_attack', {})
    print(f"\n📊 MITRE ATT&CK:")
    print(f"   Tactic: {mitre.get('tactic', 'N/A')}")
    print(f"   Technique: {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}")
    if mitre.get('sub_technique'):
        print(f"   Sub-technique: {mitre.get('sub_technique')}")
    
    # Risk Assessment
    risk = analysis.get('risk', {})
    severity_colors = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
    print(f"\n⚠️  Risk Assessment:")
    print(f"   Severity: {severity_colors.get(risk.get('severity', ''), '⚪')} {risk.get('severity', 'N/A')}")
    print(f"   Confidence: {risk.get('confidence', 'N/A')}")
    print(f"   Impact: {risk.get('impact', 'N/A')}")
    
    # Mitigations
    mitigations = analysis.get('mitigations', {})
    print(f"\n🛡️  Mitigations:")
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
    print(f"\n🤔 False Positive Assessment:")
    print(f"   Likelihood: {fp.get('likelihood', 'N/A')}")
    if fp.get('common_causes'):
        print("   Common legitimate causes:")
        for cause in fp['common_causes'][:3]:
            print(f"     • {cause}")
    
    # Summary
    print(f"\n📝 Summary:")
    print(f"   {analysis.get('summary', 'N/A')}")
    
    if verbose:
        print(f"\n🔐 Obfuscation Mapping:")
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
