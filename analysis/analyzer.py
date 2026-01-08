"""
SIB Alert Analyzer - LLM-powered security alert analysis

Fetches alerts from Loki, obfuscates sensitive data, and uses LLM
to provide attack vector analysis and mitigation strategies.
"""

import json
import os
import sys
import argparse
import requests
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

import yaml

from obfuscator import obfuscate_alert, ObfuscationLevel
from prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE, MITRE_MAPPING


class LokiClient:
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
    
    def __init__(self, api_key: str, model: str = "claude-3-haiku-20240307"):
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
            import re
            match = re.search(r'\{.*\}', content, re.DOTALL)
            if match:
                return json.loads(match.group())
            raise


class AlertAnalyzer:
    """Main analyzer class that coordinates obfuscation and LLM analysis."""
    
    def __init__(self, config: dict):
        self.config = config
        self.loki = LokiClient(config.get('loki', {}).get('url', 'http://localhost:3100'))
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
        """Fetch alerts from Loki."""
        # Parse time duration
        duration_map = {'m': 'minutes', 'h': 'hours', 'd': 'days'}
        unit = last[-1]
        value = int(last[:-1])
        delta = timedelta(**{duration_map[unit]: value})
        
        end = datetime.now()
        start = end - delta
        
        # Build query
        if priority:
            query = f'{{source="syscall", priority="{priority}"}}'
        else:
            query = '{source="syscall"}'
        
        return self.loki.query_range(query, start, end, limit)
    
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
    
    def analyze_batch(self, alerts: List[dict], dry_run: bool = False) -> List[dict]:
        """Analyze multiple alerts."""
        results = []
        for i, alert in enumerate(alerts):
            print(f"Analyzing alert {i+1}/{len(alerts)}...", file=sys.stderr)
            result = self.analyze_alert(alert, dry_run)
            results.append(result)
        return results


def load_config(config_path: Optional[str] = None) -> dict:
    """Load configuration from file."""
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            return yaml.safe_load(f)
    
    # Try default locations
    default_paths = [
        'config.yaml',
        os.path.expanduser('~/.config/sib/analysis.yaml'),
        '/etc/sib/analysis.yaml'
    ]
    
    for path in default_paths:
        if os.path.exists(path):
            with open(path) as f:
                return yaml.safe_load(f)
    
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
        'loki': {
            'url': 'http://localhost:3100'
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
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed output including obfuscation mapping')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output raw JSON instead of formatted text')
    parser.add_argument('--loki-url', help='Override Loki URL')
    
    args = parser.parse_args()
    
    # Load config
    config = load_config(args.config)
    
    # Override with CLI args
    if args.loki_url:
        config.setdefault('loki', {})['url'] = args.loki_url
    
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
    results = analyzer.analyze_batch(alerts, dry_run=args.dry_run)
    
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
