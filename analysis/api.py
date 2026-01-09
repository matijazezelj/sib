#!/usr/bin/env python3
"""
SIB Analysis API - REST API for AI-powered alert analysis

Provides endpoints for Grafana to trigger alert analysis via data links.
"""

import os
import sys
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

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
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SIB Alert Analysis</h1>
        
        {% if error %}
        <div class="error">
            <strong>Analysis Error:</strong> {{ error }}
        </div>
        {% else %}
        
        <div class="privacy-note">
            <strong>🔐 Privacy Protected:</strong> Sensitive data was obfuscated before AI analysis. 
            IPs, usernames, hostnames, and secrets are replaced with tokens.
        </div>
        
        <div class="section">
            <div class="label">Original Alert</div>
            <div class="original-alert">{{ original_output }}</div>
        </div>
        
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

# Loading page template
LOADING_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analyzing Alert...</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #111217;
            color: #d8d9da;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .loading { text-align: center; }
        .spinner {
            border: 4px solid #2c3235;
            border-top: 4px solid #3274d9;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        h2 { color: #ff9830; margin-bottom: 10px; }
        p { color: #8e8e8e; }
    </style>
</head>
<body>
    <div class="loading">
        <div class="spinner"></div>
        <h2>🔍 Analyzing Alert</h2>
        <p>Obfuscating sensitive data and sending to AI...</p>
        <p style="font-size: 0.9em; margin-top: 20px;">This may take 10-30 seconds</p>
    </div>
    <script>
        // Auto-submit form to trigger analysis
        setTimeout(function() {
            window.location.href = window.location.href.replace('/loading', '/result');
        }, 500);
    </script>
</body>
</html>
"""


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'service': 'sib-analysis-api'})


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
        
        # Optionally store in Loki
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
                severity_class='',
                obfuscation_mapping={},
                show_mapping=False,
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
        
        # Store in Loki if requested
        if store and 'error' not in result.get('analysis', {}):
            try:
                analyzer.store_analysis(result)
            except Exception as e:
                logger.warning(f"Failed to store analysis: {e}")
        
        # Determine severity class for styling
        analysis = result.get('analysis', {})
        risk = analysis.get('risk', {})
        severity = (risk.get('severity') or 'medium').lower()
        severity_class = severity if severity in ['critical', 'high', 'medium', 'low'] else 'medium'
        
        return render_template_string(ANALYSIS_TEMPLATE,
            error=None,
            analysis=analysis,
            original_output=output,
            severity_class=severity_class,
            obfuscation_mapping=result.get('obfuscation_mapping', {}),
            show_mapping=show_mapping,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
    except Exception as e:
        logger.exception("Analysis page failed")
        return render_template_string(ANALYSIS_TEMPLATE,
            error=str(e),
            analysis={},
            original_output=request.args.get('output', ''),
            severity_class='',
            obfuscation_mapping={},
            show_mapping=False,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )


@app.route('/', methods=['GET'])
def index():
    """Home page with API documentation."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIB Analysis API</title>
        <style>
            body { font-family: -apple-system, sans-serif; background: #111217; color: #d8d9da; padding: 40px; }
            h1 { color: #ff9830; }
            h2 { color: #73bf69; margin-top: 30px; }
            code { background: #2a2d35; padding: 2px 8px; border-radius: 4px; }
            pre { background: #1f2129; padding: 20px; border-radius: 8px; overflow-x: auto; }
            a { color: #3274d9; }
        </style>
    </head>
    <body>
        <h1>🛡️ SIB Analysis API</h1>
        <p>AI-powered security alert analysis with privacy protection.</p>
        
        <h2>Endpoints</h2>
        
        <h3>GET /analyze</h3>
        <p>Analyze an alert and display results in a web page (for Grafana data links).</p>
        <pre>GET /analyze?output=&lt;alert_text&gt;&amp;rule=&lt;rule_name&gt;&amp;priority=&lt;priority&gt;&amp;hostname=&lt;host&gt;</pre>
        
        <h3>POST /api/analyze</h3>
        <p>Analyze an alert and return JSON results.</p>
        <pre>{
    "alert": "alert output text",
    "rule": "rule name",
    "priority": "Critical",
    "hostname": "host",
    "store": true
}</pre>
        
        <h3>GET /health</h3>
        <p>Health check endpoint.</p>
        
        <h2>Grafana Integration</h2>
        <p>Add a data link to your log panels:</p>
        <pre>http://localhost:5000/analyze?output=${__value.raw}&amp;rule=${__data.fields.rule}&amp;priority=${__data.fields.priority}&amp;hostname=${__data.fields.hostname}</pre>
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
