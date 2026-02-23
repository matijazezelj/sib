#!/usr/bin/env python3
"""
SIB Analysis API - REST API for AI-powered alert analysis

Provides endpoints for Grafana to trigger alert analysis via data links.
"""

import os
import re
import sys
import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from markupsafe import escape

from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import AlertAnalyzer, load_config
from obfuscator import Obfuscator, ObfuscationLevel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Allow Grafana to call API

# Load config once at startup
config = load_config()

# Analysis cache directory
CACHE_DIR = Path(os.environ.get('ANALYSIS_CACHE_DIR', '/app/cache'))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Cache TTL in seconds (default 24h). Entries older than this are re-analyzed.
CACHE_TTL = int(os.environ.get('ANALYSIS_CACHE_TTL', 86400))

# HTML template for analysis results page
ANALYSIS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIB Alert Analysis</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #111217;
            color: #d8d9da;
            padding: 20px;
            line-height: 1.6;
        }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { color: #ff9830; margin-bottom: 20px; font-size: 1.5em; }
        h2 { color: #73bf69; margin: 20px 0 10px; font-size: 1.2em; }
        .card {
            background: #1f2129;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #3274d9;
        }
        .card.critical { border-left-color: #f2495c; }
        .card.high { border-left-color: #ff9830; }
        .card.medium { border-left-color: #fade2a; }
        .card.low { border-left-color: #73bf69; }
        .original-alert {
            background: #181b1f;
            padding: 15px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin-bottom: 20px;
            border: 1px solid #2c3235;
        }
        .section { margin-bottom: 25px; }
        .label {
            color: #8e8e8e;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }
        .value { font-size: 1em; }
        .mitre-badge {
            display: inline-block;
            background: #3274d9;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            margin-right: 8px;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .severity-critical { background: #f2495c; color: white; }
        .severity-high { background: #ff9830; color: black; }
        .severity-medium { background: #fade2a; color: black; }
        .severity-low { background: #73bf69; color: black; }
        .mitigation-list { list-style: none; padding-left: 0; }
        .mitigation-list li {
            padding: 8px 0;
            border-bottom: 1px solid #2c3235;
        }
        .mitigation-list li:last-child { border-bottom: none; }
        .mitigation-category {
            color: #ff9830;
            font-weight: bold;
            margin-top: 15px;
            margin-bottom: 8px;
        }
        .false-positive {
            background: #2a2d35;
            padding: 15px;
            border-radius: 4px;
        }
        .fp-likelihood {
            font-size: 1.1em;
            font-weight: bold;
        }
        .fp-low { color: #73bf69; }
        .fp-medium { color: #fade2a; }
        .fp-high { color: #f2495c; }
        .investigate-list {
            background: #181b1f;
            padding: 15px;
            border-radius: 4px;
            list-style: decimal;
            padding-left: 35px;
        }
        .investigate-list li { padding: 5px 0; }
        .loading {
            text-align: center;
            padding: 60px;
            color: #8e8e8e;
        }
        .spinner {
            border: 3px solid #2c3235;
            border-top: 3px solid #3274d9;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .error {
            background: #f2495c22;
            border: 1px solid #f2495c;
            padding: 20px;
            border-radius: 8px;
            color: #f2495c;
        }
        .privacy-note {
            background: #73bf6922;
            border: 1px solid #73bf69;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 0.9em;
        }
        .privacy-note strong { color: #73bf69; }
        .obfuscation-map {
            font-family: monospace;
            font-size: 0.85em;
            background: #181b1f;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #2c3235;
            text-align: center;
            color: #6e6e6e;
            font-size: 0.85em;
        }
        .cached-badge {
            display: inline-block;
            background: #3274d9;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            margin-left: 10px;
        }
        .nav-link {
            color: #3274d9;
            text-decoration: none;
            margin-right: 15px;
        }
        .nav { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/" class="nav-link">← API Home</a>
            <a href="/history" class="nav-link">📜 History</a>
        </div>
        <h1>🛡️ SIB Alert Analysis {% if cached %}<span class="cached-badge">📋 Cached</span>{% endif %}</h1>
        
        {% if error %}
        <div class="error">
            <strong>Analysis Error:</strong> {{ error }}
        </div>
        {% else %}
        
        <div class="privacy-note">
            <strong>🔐 Privacy Protected:</strong> Sensitive data was obfuscated before AI analysis. 
            IPs, usernames, hostnames, and secrets are replaced with tokens.
            {% if cached %}<br><em>This is a cached result from {{ timestamp }}.</em>{% endif %}
        </div>
        
        <div class="section">
            <div class="label">Original Alert</div>
            <div class="original-alert">{{ original_output }}</div>
        </div>
        
        {% if obfuscated_output and obfuscated_output != original_output %}
        <div class="section">
            <div class="label">🔒 What Was Sent to AI (Obfuscated)</div>
            <div class="original-alert" style="border-left: 3px solid #73bf69;">{{ obfuscated_output }}</div>
        </div>
        {% endif %}
        
        {% if obfuscation_mapping and show_mapping %}
        <div class="section">
            <div class="label">Obfuscation Mapping</div>
            <div class="obfuscation-map">
                {% for category, mappings in obfuscation_mapping.items() %}
                {% if mappings and category != 'secrets_count' %}
                <div><strong>{{ category }}:</strong> {{ mappings }}</div>
                {% endif %}
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        <div class="card {{ severity_class }}">
            <div class="section">
                <div class="label">Attack Vector</div>
                <div class="value">{{ analysis.attack_vector or 'N/A' }}</div>
            </div>
            
            <div class="section">
                <div class="label">MITRE ATT&CK</div>
                <div class="value">
                    {% if analysis.mitre_attack %}
                    <span class="mitre-badge">{{ analysis.mitre_attack.tactic or 'Unknown' }}</span>
                    <span class="mitre-badge">{{ analysis.mitre_attack.technique_id or 'Unknown' }} - {{ analysis.mitre_attack.technique_name or '' }}</span>
                    {% if analysis.mitre_attack.sub_technique %}
                    <span class="mitre-badge">{{ analysis.mitre_attack.sub_technique }}</span>
                    {% endif %}
                    {% else %}
                    N/A
                    {% endif %}
                </div>
            </div>
            
            <div class="section">
                <div class="label">Risk Assessment</div>
                <div class="value">
                    {% if analysis.risk %}
                    <span class="severity-badge severity-{{ (analysis.risk.severity or 'medium')|lower }}">
                        {{ analysis.risk.severity or 'Unknown' }}
                    </span>
                    <span style="margin-left: 10px;">Confidence: {{ analysis.risk.confidence or 'Unknown' }}</span>
                    <p style="margin-top: 10px; color: #b0b0b0;">{{ analysis.risk.impact or '' }}</p>
                    {% else %}
                    N/A
                    {% endif %}
                </div>
            </div>
        </div>
        
        <h2>🛡️ Mitigations</h2>
        <div class="card">
            {% if analysis.mitigations %}
                {% if analysis.mitigations.immediate %}
                <div class="mitigation-category">⚡ Immediate Actions</div>
                <ul class="mitigation-list">
                    {% for item in analysis.mitigations.immediate %}
                    <li>{{ item }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                
                {% if analysis.mitigations.short_term %}
                <div class="mitigation-category">📅 Short-term</div>
                <ul class="mitigation-list">
                    {% for item in analysis.mitigations.short_term %}
                    <li>{{ item }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                
                {% if analysis.mitigations.long_term %}
                <div class="mitigation-category">🎯 Long-term</div>
                <ul class="mitigation-list">
                    {% for item in analysis.mitigations.long_term %}
                    <li>{{ item }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            {% else %}
            <p>No mitigation recommendations available.</p>
            {% endif %}
        </div>
        
        <h2>🤔 False Positive Assessment</h2>
        <div class="false-positive">
            {% if analysis.false_positive %}
            <p class="fp-likelihood fp-{{ (analysis.false_positive.likelihood or 'medium')|lower }}">
                Likelihood: {{ analysis.false_positive.likelihood or 'Unknown' }}
            </p>
            {% if analysis.false_positive.common_causes %}
            <p style="margin-top: 10px;"><strong>Common legitimate causes:</strong></p>
            <ul style="margin-top: 5px; padding-left: 20px;">
                {% for cause in analysis.false_positive.common_causes %}
                <li>{{ cause }}</li>
                {% endfor %}
            </ul>
            {% endif %}
            {% else %}
            <p>No false positive assessment available.</p>
            {% endif %}
        </div>
        
        {% if analysis.investigate %}
        <h2>🔍 Investigation Steps</h2>
        <ol class="investigate-list">
            {% for step in analysis.investigate %}
            <li>{{ step }}</li>
            {% endfor %}
        </ol>
        {% endif %}
        
        <h2>📝 Summary</h2>
        <div class="card">
            <p>{{ analysis.summary or 'No summary available.' }}</p>
        </div>
        
        {% if show_mapping and obfuscation_mapping %}
        <h2>🔐 Obfuscation Mapping</h2>
        <div class="card">
            <p style="margin-bottom: 10px; color: #8e8e8e;">
                The following sensitive data was replaced with tokens:
            </p>
            <div class="obfuscation-map">
                <pre>{{ obfuscation_mapping | tojson(indent=2) }}</pre>
            </div>
        </div>
        {% endif %}
        
        {% endif %}
        
        <div class="footer">
            Analyzed by SIB (SIEM in a Box) • {{ timestamp }}
        </div>
    </div>
</body>
</html>
"""

# ==================== Cache Functions ====================

def normalize_output(output: str) -> str:
    """Normalize alert output for consistent cache keys.
    
    Strips timestamps, PIDs, UIDs, and other varying numeric fields
    so that alerts from the same rule with different specifics share a
    cache key. File paths are kept as-is since they carry important context.
    """
    # Normalize whitespace
    normalized = ' '.join(output.split())
    # Remove common timestamp patterns that make each event unique
    # ISO format: 2026-01-09T12:34:56.789Z or with offset +0000
    normalized = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{4})?', '[TIME]', normalized)
    # Unix timestamp: 1234567890 or 1234567890.123
    normalized = re.sub(r'\b\d{10,13}(\.\d+)?\b', '[TIMESTAMP]', normalized)
    # Common date formats
    normalized = re.sub(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', '[TIME]', normalized)
    # Normalize numeric IDs (user_uid=0, user_loginuid=1000, pid=12345, etc.)
    normalized = re.sub(r'(user_uid|user_loginuid|pid|ppid|gid|tid|res)=\d+', r'\1=[ID]', normalized)
    # Normalize container IDs (64-char hex or short hex)
    normalized = re.sub(r'(container_id)=[a-f0-9]{8,64}', r'\1=[CID]', normalized)
    # Normalize IP addresses
    normalized = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?', '[IP]', normalized)
    return normalized


def get_cache_key(output: str, rule: str) -> str:
    """Generate a cache key from alert output and rule."""
    normalized = normalize_output(output)
    content = f"{normalized}:{rule}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def get_cached_analysis(cache_key: str) -> Optional[dict]:
    """Retrieve cached analysis if it exists and hasn't expired.
    
    Returns None if cache entry is missing or older than CACHE_TTL.
    Increments the dedup hit counter on cache hits.
    """
    cache_file = CACHE_DIR / f"{cache_key}.json"
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            # Check TTL
            cached_time = data.get('timestamp', '')
            if cached_time:
                try:
                    cached_dt = datetime.fromisoformat(cached_time)
                    age = (datetime.now() - cached_dt).total_seconds()
                    if age > CACHE_TTL:
                        logger.info(f"Cache expired for {cache_key} (age={age:.0f}s, ttl={CACHE_TTL}s)")
                        return None
                except (ValueError, TypeError):
                    pass
            # Increment hit counter
            data['dedup_count'] = data.get('dedup_count', 1) + 1
            data['last_seen'] = datetime.now().isoformat()
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return data
        except Exception as e:
            logger.warning(f"Failed to read cache: {e}")
    return None


def save_to_cache(cache_key: str, result: dict, original_output: str, rule: str, priority: str, hostname: str):
    """Save analysis result to cache with dedup tracking."""
    cache_file = CACHE_DIR / f"{cache_key}.json"
    cache_data = {
        'cache_key': cache_key,
        'timestamp': datetime.now().isoformat(),
        'original_output': original_output,
        'rule': rule,
        'priority': priority,
        'hostname': hostname,
        'analysis': result.get('analysis', {}),
        'obfuscated_output': result.get('obfuscated_alert', {}).get('output', '') if isinstance(result.get('obfuscated_alert'), dict) else '',
        'obfuscation_mapping': result.get('obfuscation_mapping', {}),
        'dedup_count': 1,
        'last_seen': datetime.now().isoformat(),
    }
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2, default=str)
        logger.info(f"Cached analysis: {cache_key}")
    except Exception as e:
        logger.warning(f"Failed to save cache: {e}")


def list_cached_analyses(limit: int = 50) -> list:
    """List all cached analyses, most recent first."""
    cache_files = sorted(CACHE_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    results = []
    for cache_file in cache_files[:limit]:
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                results.append({
                    'cache_key': data.get('cache_key', cache_file.stem),
                    'timestamp': data.get('timestamp'),
                    'rule': data.get('rule'),
                    'priority': data.get('priority'),
                    'hostname': data.get('hostname'),
                    'severity': data.get('analysis', {}).get('risk', {}).get('severity', 'unknown'),
                    'dedup_count': data.get('dedup_count', 1),
                    'last_seen': data.get('last_seen'),
                })
        except Exception:
            pass
    return results


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'sib-analysis-api'})


@app.route('/api/health/all', methods=['GET'])
def health_all():
    """Aggregate health check for all SIB services.

    Returns structured JSON with the status of every SIB component.
    Uses Docker-internal hostnames (sib-*) by default; override with
    query params if running outside Docker.
    """
    timeout = float(request.args.get('timeout', 3))
    results = {}

    checks = {
        'falcosidekick': {
            'url': os.environ.get('SIDEKICK_HEALTH_URL', 'http://sib-sidekick:2801/healthz'),
        },
        'grafana': {
            'url': os.environ.get('GRAFANA_HEALTH_URL', 'http://sib-grafana:3000/api/health'),
        },
    }

    # Stack-aware storage checks
    stack = os.environ.get('STACK', config.get('storage', {}).get('backend', 'loki'))
    if stack in ('vm', 'victorialogs'):
        checks['victorialogs'] = {
            'url': os.environ.get('VICTORIALOGS_HEALTH_URL', 'http://sib-victorialogs:9428/health'),
        }
        checks['victoriametrics'] = {
            'url': os.environ.get('VICTORIAMETRICS_HEALTH_URL', 'http://sib-victoriametrics:8428/health'),
        }
    else:
        checks['loki'] = {
            'url': os.environ.get('LOKI_HEALTH_URL', 'http://sib-loki:3100/ready'),
        }
        checks['prometheus'] = {
            'url': os.environ.get('PROMETHEUS_HEALTH_URL', 'http://sib-prometheus:9090/-/ready'),
        }

    import requests as http_client
    for name, check in checks.items():
        try:
            r = http_client.get(check['url'], timeout=timeout)
            results[name] = {
                'status': 'healthy' if r.ok else 'unhealthy',
                'code': r.status_code,
            }
        except http_client.ConnectionError:
            results[name] = {'status': 'unreachable'}
        except http_client.Timeout:
            results[name] = {'status': 'timeout'}
        except Exception as e:
            results[name] = {'status': 'error', 'detail': str(e)}

    # Self (analysis API) is healthy if we're serving this request
    results['analysis'] = {'status': 'healthy'}

    # Determine overall status
    statuses = [s['status'] for s in results.values()]
    if all(s == 'healthy' for s in statuses):
        overall = 'healthy'
    elif any(s == 'healthy' for s in statuses):
        overall = 'degraded'
    else:
        overall = 'unhealthy'

    return jsonify({
        'status': overall,
        'stack': stack,
        'services': results,
        'checked_at': datetime.now().isoformat(),
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_api():
    """
    API endpoint for analyzing an alert.
    
    Request body:
        {
            "alert": "alert output text",
            "rule": "rule name",
            "priority": "Critical",
            "hostname": "host",
            "store": true/false
        }
    
    Returns JSON analysis result.
    """
    try:
        data = request.get_json()
        if not data or 'alert' not in data:
            return jsonify({'error': 'Missing alert data'}), 400
        
        # Build alert object
        alert = {
            'output': data.get('alert'),
            '_labels': {
                'rule': data.get('rule', 'Unknown'),
                'priority': data.get('priority', 'Unknown'),
                'hostname': data.get('hostname', 'Unknown'),
            },
            '_timestamp': datetime.now()
        }
        
        # Analyze
        analyzer = AlertAnalyzer(config)
        result = analyzer.analyze_alert(alert, dry_run=False)
        
        # Optionally store in log backend
        if data.get('store', False):
            analyzer.store_analysis(result)
        
        return jsonify({
            'success': True,
            'analysis': result.get('analysis', {}),
            'obfuscation_mapping': result.get('obfuscation_mapping', {})
        })
        
    except Exception as e:
        logger.exception("Analysis failed")
        return jsonify({'error': str(e)}), 500


@app.route('/analyze', methods=['GET'])
def analyze_page():
    """
    Web page for analyzing an alert (called from Grafana data link).
    
    Query params:
        - output: URL-encoded alert output
        - rule: rule name
        - priority: alert priority
        - hostname: source hostname
        - store: whether to store result (default: true)
    """
    try:
        output = request.args.get('output', '')
        rule = request.args.get('rule', 'Unknown')
        priority = request.args.get('priority', 'Unknown')
        hostname = request.args.get('hostname', 'Unknown')
        store = request.args.get('store', 'true').lower() == 'true'
        show_mapping = request.args.get('show_mapping', 'false').lower() == 'true'
        
        if not output:
            return render_template_string(ANALYSIS_TEMPLATE, 
                error="No alert output provided. Use ?output=... parameter.",
                analysis={},
                original_output='',
                obfuscated_output='',
                severity_class='',
                obfuscation_mapping={},
                show_mapping=False,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                cached=False
            )
        
        # Check cache first
        cache_key = get_cache_key(output, rule)
        cached_result = get_cached_analysis(cache_key)
        
        if cached_result:
            # Return cached analysis
            analysis = cached_result.get('analysis', {})
            risk = analysis.get('risk', {})
            severity = (risk.get('severity') or 'medium').lower()
            severity_class = severity if severity in ['critical', 'high', 'medium', 'low'] else 'medium'
            
            return render_template_string(ANALYSIS_TEMPLATE,
                error=None,
                analysis=analysis,
                original_output=output,
                obfuscated_output=cached_result.get('obfuscated_output', ''),
                severity_class=severity_class,
                obfuscation_mapping=cached_result.get('obfuscation_mapping', {}),
                show_mapping=show_mapping,
                timestamp=cached_result.get('timestamp', 'cached'),
                cached=True
            )
        
        # Build alert object
        alert = {
            'output': output,
            '_labels': {
                'rule': rule,
                'priority': priority,
                'hostname': hostname,
            },
            '_timestamp': datetime.now()
        }
        
        # Analyze
        analyzer = AlertAnalyzer(config)
        result = analyzer.analyze_alert(alert, dry_run=False)
        
        # Store in log backend if requested
        if store and 'error' not in result.get('analysis', {}):
            try:
                analyzer.store_analysis(result)
            except Exception as e:
                logger.warning(f"Failed to store analysis: {e}")
        
        # Save to cache
        save_to_cache(cache_key, result, output, rule, priority, hostname)
        
        # Determine severity class for styling
        analysis = result.get('analysis', {})
        risk = analysis.get('risk', {})
        severity = (risk.get('severity') or 'medium').lower()
        severity_class = severity if severity in ['critical', 'high', 'medium', 'low'] else 'medium'
        
        # Get obfuscated output
        obfuscated_alert = result.get('obfuscated_alert', {})
        obfuscated_output = obfuscated_alert.get('output', '') if isinstance(obfuscated_alert, dict) else str(obfuscated_alert)
        
        return render_template_string(ANALYSIS_TEMPLATE,
            error=None,
            analysis=analysis,
            original_output=output,
            obfuscated_output=obfuscated_output,
            severity_class=severity_class,
            obfuscation_mapping=result.get('obfuscation_mapping', {}),
            show_mapping=show_mapping,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            cached=False
        )
        
    except Exception as e:
        logger.exception("Analysis page failed")
        return render_template_string(ANALYSIS_TEMPLATE,
            error=str(e),
            analysis={},
            original_output=request.args.get('output', ''),
            obfuscated_output='',
            severity_class='',
            obfuscation_mapping={},
            show_mapping=False,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            cached=False
        )


@app.route('/history', methods=['GET'])
def history_page():
    """List all cached analyses."""
    analyses = list_cached_analyses(limit=100)
    
    rows = ""
    for a in analyses:
        severity = escape(a.get('severity', 'unknown'))
        severity_color = {'critical': '#f2495c', 'high': '#ff9830', 'medium': '#fade2a', 'low': '#73bf69'}.get(str(severity), '#8e8e8e')
        rows += f"""
        <tr onclick="window.location='/history/{escape(a['cache_key'])}'" style="cursor: pointer;">
            <td>{escape(a.get('timestamp', '')[:19])}</td>
            <td>{escape(a.get('rule', ''))}</td>
            <td>{escape(a.get('priority', ''))}</td>
            <td style="color: {severity_color}; font-weight: bold;">{severity}</td>
            <td>{escape(a.get('hostname', ''))}</td>
            <td>{a.get('dedup_count', 1)}</td>
        </tr>"""
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Analysis History - SIB</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; background: #111217; color: #d8d9da; padding: 40px; }}
            h1 {{ color: #ff9830; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #2c3235; }}
            th {{ background: #1f2129; color: #73bf69; }}
            tr:hover {{ background: #1f2129; }}
            a {{ color: #3274d9; text-decoration: none; }}
            .back {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="back"><a href="/">← Back to API</a></div>
        <h1>📜 Analysis History</h1>
        <p>{len(analyses)} cached analyses</p>
        <table>
            <tr><th>Timestamp</th><th>Rule</th><th>Priority</th><th>AI Severity</th><th>Hostname</th><th>Seen</th></tr>
            {rows}
        </table>
    </body>
    </html>
    """


@app.route('/history/<cache_key>', methods=['GET'])
def history_detail(cache_key: str):
    """View a cached analysis."""
    cached = get_cached_analysis(cache_key)
    if not cached:
        return "Analysis not found", 404
    
    analysis = cached.get('analysis', {})
    risk = analysis.get('risk', {})
    severity = (risk.get('severity') or 'medium').lower()
    severity_class = severity if severity in ['critical', 'high', 'medium', 'low'] else 'medium'
    
    return render_template_string(ANALYSIS_TEMPLATE,
        error=None,
        analysis=analysis,
        original_output=cached.get('original_output', ''),
        obfuscated_output=cached.get('obfuscated_output', ''),
        severity_class=severity_class,
        obfuscation_mapping=cached.get('obfuscation_mapping', {}),
        show_mapping=False,
        timestamp=cached.get('timestamp', 'cached'),
        cached=True
    )


@app.route('/api/history', methods=['GET'])
def api_history():
    """API endpoint to list cached analyses."""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(list_cached_analyses(limit=limit))


@app.route('/', methods=['GET'])
def index():
    """Home page with API documentation."""
    cached_count = len(list(CACHE_DIR.glob("*.json")))
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIB Analysis API</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; background: #111217; color: #d8d9da; padding: 40px; }}
            h1 {{ color: #ff9830; }}
            h2 {{ color: #73bf69; margin-top: 30px; }}
            code {{ background: #2a2d35; padding: 2px 8px; border-radius: 4px; }}
            pre {{ background: #1f2129; padding: 20px; border-radius: 8px; overflow-x: auto; }}
            a {{ color: #3274d9; }}
            .stat {{ display: inline-block; background: #1f2129; padding: 15px 25px; border-radius: 8px; margin-right: 15px; }}
            .stat-value {{ font-size: 2em; color: #73bf69; }}
            .stat-label {{ color: #8e8e8e; }}
        </style>
    </head>
    <body>
        <h1>🛡️ SIB Analysis API</h1>
        <p>AI-powered security alert analysis with privacy protection.</p>
        
        <div style="margin: 30px 0;">
            <div class="stat">
                <div class="stat-value">{cached_count}</div>
                <div class="stat-label">Cached Analyses</div>
            </div>
            <a href="/history" style="background: #3274d9; color: white; padding: 15px 25px; border-radius: 8px; text-decoration: none;">📜 View History</a>
        </div>
        
        <h2>Endpoints</h2>
        
        <h3>GET /analyze</h3>
        <p>Analyze an alert and display results in a web page (for Grafana data links).</p>
        <pre>GET /analyze?output=&lt;alert_text&gt;&amp;rule=&lt;rule_name&gt;&amp;priority=&lt;priority&gt;&amp;hostname=&lt;host&gt;</pre>
        
        <h3>GET /history</h3>
        <p>View all cached analyses.</p>
        
        <h3>POST /api/analyze</h3>
        <p>Analyze an alert and return JSON results.</p>
        <pre>{{
    "alert": "alert output text",
    "rule": "rule name",
    "priority": "Critical",
    "hostname": "host",
    "store": true
}}</pre>
        
        <h3>GET /health</h3>
        <p>Health check endpoint.</p>
        
        <h3>GET /api/health/all</h3>
        <p>Aggregate health check for all SIB services. Returns JSON with status of every component.</p>
        
        <h2>Grafana Integration</h2>
        <p>Add a data link to your log panels:</p>
        <pre>http://localhost:5000/analyze?output=${{__value.raw}}&amp;rule=${{__data.fields.rule}}&amp;priority=${{__data.fields.priority}}&amp;hostname=${{__data.fields.hostname}}</pre>
    </body>
    </html>
    """


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='SIB Analysis API')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    print(f"🛡️  SIB Analysis API starting on http://{args.host}:{args.port}")
    print(f"📊 Grafana data link URL: http://localhost:{args.port}/analyze?output={{alert}}")
    
    app.run(host=args.host, port=args.port, debug=args.debug)
