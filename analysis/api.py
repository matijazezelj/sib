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
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from markupsafe import escape

from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import AlertAnalyzer, load_config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Allow Grafana to call API

# Load config once at startup
config = load_config()

# Validate provider API keys at startup
_provider = config.get('analysis', {}).get('provider', 'ollama')
if _provider == 'anthropic':
    _key = config.get('analysis', {}).get('anthropic', {}).get('api_key', '')
    if not _key or _key in ('your-api-key', '${ANTHROPIC_API_KEY}', ''):
        logger.warning("LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set — analysis requests will fail")
elif _provider == 'openai':
    _key = config.get('analysis', {}).get('openai', {}).get('api_key', '')
    if not _key or _key in ('your-api-key', '${OPENAI_API_KEY}', ''):
        logger.warning("LLM_PROVIDER=openai but OPENAI_API_KEY is not set — analysis requests will fail")

# Analysis cache directory
CACHE_DIR = Path(os.environ.get('ANALYSIS_CACHE_DIR', '/app/cache'))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Cache TTL in seconds (default 24h). Entries older than this are re-analyzed.
CACHE_TTL = int(os.environ.get('ANALYSIS_CACHE_TTL', 86400))


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
    try:
        timeout = int(request.args.get('timeout', 3))
    except (ValueError, TypeError):
        timeout = 3
    timeout = max(1, min(timeout, 30))
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
            r = http_client.get(check['url'], timeout=timeout)  # nosemgrep: python.lang.security.audit.insecure-transport.requests.request-with-http.request-with-http
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
            return render_template('analysis.html', 
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
            
            return render_template('analysis.html',
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
        
        return render_template('analysis.html',
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
        return render_template('analysis.html',
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
    
    return render_template('analysis.html',
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
