#!/usr/bin/env python3
"""
Sigma to Falco/LogQL/LogsQL Converter for SIB

Converts Sigma rules to:
1. Falco rules (for syscall-level detection)
2. LogQL alerts (for log-based detection in Loki - Grafana stack)
3. LogsQL alerts (for log-based detection in VictoriaLogs - VM stack)

Usage:
    ./sigma2sib.py rules/          # Convert all rules in directory
    ./sigma2sib.py rule.yml        # Convert single rule
    ./sigma2sib.py rule.yml -o falco   # Output Falco format
    ./sigma2sib.py rule.yml -o logql   # Output LogQL format (Loki)
    ./sigma2sib.py rule.yml -o logsql  # Output LogsQL format (VictoriaLogs)
"""

import argparse
import sys
import yaml
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# MITRE ATT&CK mapping for tags
MITRE_TACTICS = {
    'initial_access': 'TA0001',
    'execution': 'TA0002',
    'persistence': 'TA0003',
    'privilege_escalation': 'TA0004',
    'defense_evasion': 'TA0005',
    'credential_access': 'TA0006',
    'discovery': 'TA0007',
    'lateral_movement': 'TA0008',
    'collection': 'TA0009',
    'exfiltration': 'TA0010',
    'command_and_control': 'TA0011',
    'impact': 'TA0012',
}

# Sigma to Falco field mapping
SIGMA_TO_FALCO_FIELDS = {
    'CommandLine': 'proc.cmdline',
    'Image': 'proc.exe',
    'ParentImage': 'proc.pname',
    'User': 'user.name',
    'TargetFilename': 'fd.name',
    'SourceIp': 'fd.sip',
    'DestinationIp': 'fd.dip',
    'DestinationPort': 'fd.dport',
    'ProcessName': 'proc.name',
    'CurrentDirectory': 'proc.cwd',
}

# Sigma to LogsQL field mapping (VictoriaLogs)
SIGMA_TO_LOGSQL_FIELDS = {
    'CommandLine': 'proc.cmdline',
    'Image': 'proc.exe',
    'User': 'user.name',
    'ProcessName': 'proc.name',
    'TargetFilename': 'fd.name',
    'SourceIp': 'fd.sip',
    'DestinationIp': 'fd.dip',
}


def load_sigma_rule(path: Path) -> Dict[str, Any]:
    """Load a Sigma rule from YAML file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def sigma_priority_to_falco(level: str) -> str:
    """Convert Sigma level to Falco priority."""
    mapping = {
        'critical': 'CRITICAL',
        'high': 'ERROR',
        'medium': 'WARNING',
        'low': 'NOTICE',
        'informational': 'INFORMATIONAL',
    }
    return mapping.get(level.lower(), 'WARNING')


def extract_mitre_tags(tags: List[str]) -> List[str]:
    """Extract MITRE ATT&CK tags from Sigma tags."""
    mitre_tags = []
    for tag in tags or []:
        tag_lower = tag.lower()
        if tag_lower.startswith('attack.'):
            technique = tag_lower.replace('attack.', '')
            # Check if it's a tactic
            if technique in MITRE_TACTICS:
                mitre_tags.append(f'mitre_{technique}')
            # Check if it's a technique ID
            elif technique.startswith('t'):
                mitre_tags.append(f'mitre_technique_{technique.upper()}')
            else:
                mitre_tags.append(f'mitre_{technique.replace("_", "")}')
    return mitre_tags


def convert_detection_to_falco_condition(detection: Dict[str, Any]) -> str:
    """Convert Sigma detection block to Falco condition."""
    conditions = []
    
    for key, value in detection.items():
        if key == 'condition':
            continue
            
        if isinstance(value, dict):
            # Field conditions
            for field, pattern in value.items():
                falco_field = SIGMA_TO_FALCO_FIELDS.get(field, field.lower())
                
                if isinstance(pattern, list):
                    # Multiple values - OR them
                    sub_conditions = []
                    for p in pattern:
                        sub_conditions.append(f'{falco_field} contains "{p}"')
                    conditions.append(f'({" or ".join(sub_conditions)})')
                elif isinstance(pattern, str):
                    if '*' in pattern:
                        # Wildcard pattern
                        clean_pattern = pattern.replace('*', '')
                        if pattern.startswith('*') and pattern.endswith('*'):
                            conditions.append(f'{falco_field} contains "{clean_pattern}"')
                        elif pattern.startswith('*'):
                            conditions.append(f'{falco_field} endswith "{clean_pattern}"')
                        elif pattern.endswith('*'):
                            conditions.append(f'{falco_field} startswith "{clean_pattern}"')
                    else:
                        conditions.append(f'{falco_field} = "{pattern}"')
                        
        elif isinstance(value, list):
            # List of conditions
            for item in value:
                if isinstance(item, dict):
                    for field, pattern in item.items():
                        falco_field = SIGMA_TO_FALCO_FIELDS.get(field, field.lower())
                        conditions.append(f'{falco_field} contains "{pattern}"')
    
    # Parse the condition logic
    condition_logic = detection.get('condition', ' and '.join(k for k in detection.keys() if k != 'condition'))
    
    # Simple condition parsing
    if 'all of' in condition_logic:
        return ' and '.join(conditions)
    elif '1 of' in condition_logic or 'any of' in condition_logic:
        return ' or '.join(conditions)
    else:
        return ' and '.join(conditions) if conditions else 'evt.type = execve'


def convert_detection_to_logql(detection: Dict[str, Any], logsource: Dict[str, Any]) -> str:
    """Convert Sigma detection block to LogQL query."""
    patterns = []
    
    for key, value in detection.items():
        if key == 'condition':
            continue
            
        if isinstance(value, dict):
            for field, pattern in value.items():
                if isinstance(pattern, list):
                    patterns.extend(pattern)
                elif isinstance(pattern, str):
                    # Remove wildcards for LogQL
                    clean = pattern.replace('*', '')
                    if clean:
                        patterns.append(clean)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for field, pattern in item.items():
                        clean = str(pattern).replace('*', '')
                        if clean:
                            patterns.append(clean)
    
    # Determine log source selector
    category = logsource.get('category', 'process_creation')
    product = logsource.get('product', 'linux')
    
    if product == 'linux' and category == 'process_creation':
        selector = '{source="syscall"}'
    elif product == 'windows':
        selector = '{job="windows"}'
    else:
        selector = '{job=~".+"}'
    
    # Build line filters
    if len(patterns) == 1:
        line_filter = f'|= "{patterns[0]}"'
    elif len(patterns) > 1:
        # Use regex for multiple patterns
        regex_pattern = '|'.join(re.escape(p) for p in patterns[:5])  # Limit to 5
        line_filter = f'|~ "(?i)({regex_pattern})"'
    else:
        line_filter = ''
    
    return f'{selector} {line_filter}'


def sigma_to_falco(sigma: Dict[str, Any], source_file: str = '') -> str:
    """Convert a Sigma rule to Falco rule format."""
    title = sigma.get('title', 'Unknown Rule')
    description = sigma.get('description', title)
    level = sigma.get('level', 'medium')
    tags = sigma.get('tags', [])
    detection = sigma.get('detection', {})
    logsource = sigma.get('logsource', {})
    
    # Convert to Falco format
    rule_name = title.replace(' ', '_').replace('-', '_')
    priority = sigma_priority_to_falco(level)
    mitre_tags = extract_mitre_tags(tags)
    condition = convert_detection_to_falco_condition(detection)
    
    # Build Falco rule
    falco_rule = f'''# Converted from Sigma rule: {source_file}
# Original: {title}
- rule: {title}
  desc: "{description}"
  condition: >
    spawned_process and
    {condition}
  output: >
    Sigma Alert: {title}
    (user=%user.name cmd=%proc.cmdline file=%fd.name)
  priority: {priority}
  tags: [{", ".join(mitre_tags + ["sigma"])}]
'''
    return falco_rule


def sigma_to_logql_alert(sigma: Dict[str, Any], source_file: str = '') -> Dict[str, Any]:
    """Convert a Sigma rule to Loki alerting rule format."""
    title = sigma.get('title', 'Unknown Rule')
    description = sigma.get('description', title)
    level = sigma.get('level', 'medium')
    tags = sigma.get('tags', [])
    detection = sigma.get('detection', {})
    logsource = sigma.get('logsource', {})
    
    mitre_tags = extract_mitre_tags(tags)
    logql_query = convert_detection_to_logql(detection, logsource)
    
    # Build Loki alerting rule
    alert_rule = {
        'name': f'sigma_{title.replace(" ", "_").lower()}',
        'rules': [{
            'alert': title.replace(' ', '_'),
            'expr': f'count_over_time({logql_query} [5m]) > 0',
            'for': '0m',
            'labels': {
                'severity': level,
                'source': 'sigma',
            },
            'annotations': {
                'summary': title,
                'description': description,
                'mitre': ', '.join(mitre_tags),
            }
        }]
    }
    return alert_rule


def convert_detection_to_logsql(detection: Dict[str, Any], logsource: Dict[str, Any]) -> str:
    """Convert Sigma detection block to LogsQL query (VictoriaLogs)."""
    conditions = []
    
    for key, value in detection.items():
        if key == 'condition':
            continue
            
        if isinstance(value, dict):
            for field, pattern in value.items():
                logsql_field = SIGMA_TO_LOGSQL_FIELDS.get(field, field.lower())
                
                if isinstance(pattern, list):
                    # Multiple values - OR them with parentheses
                    sub_conditions = []
                    for p in pattern:
                        clean = str(p).replace('*', '')
                        if clean:
                            sub_conditions.append(f'"{clean}"')
                    if sub_conditions:
                        conditions.append(f'({" OR ".join(sub_conditions)})')
                elif isinstance(pattern, str):
                    # Remove wildcards, LogsQL does substring matching by default
                    clean = pattern.replace('*', '')
                    if clean:
                        conditions.append(f'"{clean}"')
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for field, pattern in item.items():
                        clean = str(pattern).replace('*', '')
                        if clean:
                            conditions.append(f'"{clean}"')
    
    # Determine log source filter
    category = logsource.get('category', 'process_creation')
    product = logsource.get('product', 'linux')
    
    if product == 'linux' and category == 'process_creation':
        source_filter = 'source:syscall'
    elif product == 'windows':
        source_filter = 'source:windows'
    else:
        source_filter = '*'
    
    # Build LogsQL query
    if conditions:
        return f'{source_filter} AND ({" AND ".join(conditions)})'
    else:
        return source_filter


def sigma_to_logsql_alert(sigma: Dict[str, Any], source_file: str = '') -> Dict[str, Any]:
    """Convert a Sigma rule to VictoriaLogs alerting rule format."""
    title = sigma.get('title', 'Unknown Rule')
    description = sigma.get('description', title)
    level = sigma.get('level', 'medium')
    tags = sigma.get('tags', [])
    detection = sigma.get('detection', {})
    logsource = sigma.get('logsource', {})
    
    mitre_tags = extract_mitre_tags(tags)
    logsql_query = convert_detection_to_logsql(detection, logsource)
    
    # Build VictoriaLogs alerting rule (vmalert format)
    alert_rule = {
        'name': f'sigma_{title.replace(" ", "_").lower()}',
        'rules': [{
            'alert': title.replace(' ', '_'),
            'expr': f'{logsql_query} | stats count() as hits',
            'for': '0m',
            'labels': {
                'severity': level,
                'source': 'sigma',
            },
            'annotations': {
                'summary': title,
                'description': description,
                'mitre': ', '.join(mitre_tags),
                'query': logsql_query,
            }
        }]
    }
    return alert_rule


def convert_file(input_path: Path, output_format: str = 'both') -> None:
    """Convert a single Sigma rule file."""
    sigma = load_sigma_rule(input_path)
    
    print(f"\n{'='*60}")
    print(f"Converting: {input_path.name}")
    print(f"Title: {sigma.get('title', 'Unknown')}")
    print(f"{'='*60}")
    
    if output_format in ('falco', 'both', 'all'):
        print("\n--- Falco Rule ---")
        falco_output = sigma_to_falco(sigma, str(input_path))
        print(falco_output)
        
    if output_format in ('logql', 'both', 'all'):
        print("\n--- LogQL Alert Rule (Loki) ---")
        logql_output = sigma_to_logql_alert(sigma, str(input_path))
        print(yaml.dump(logql_output, default_flow_style=False))

    if output_format in ('logsql', 'all'):
        print("\n--- LogsQL Alert Rule (VictoriaLogs) ---")
        logsql_output = sigma_to_logsql_alert(sigma, str(input_path))
        print(yaml.dump(logsql_output, default_flow_style=False))


def convert_directory(input_dir: Path, output_format: str = 'both') -> None:
    """Convert all Sigma rules in a directory."""
    rules_found = list(input_dir.glob('**/*.yml')) + list(input_dir.glob('**/*.yaml'))
    
    if not rules_found:
        print(f"No Sigma rules found in {input_dir}")
        return
    
    print(f"\nFound {len(rules_found)} Sigma rules")
    
    all_falco_rules = []
    all_logql_rules = {'groups': []}
    all_logsql_rules = {'groups': []}
    
    for rule_path in rules_found:
        try:
            sigma = load_sigma_rule(rule_path)
            
            if output_format in ('falco', 'both', 'all'):
                all_falco_rules.append(sigma_to_falco(sigma, str(rule_path)))
                
            if output_format in ('logql', 'both', 'all'):
                logql_alert = sigma_to_logql_alert(sigma, str(rule_path))
                all_logql_rules['groups'].append(logql_alert)

            if output_format in ('logsql', 'all'):
                logsql_alert = sigma_to_logsql_alert(sigma, str(rule_path))
                all_logsql_rules['groups'].append(logsql_alert)
                
            print(f"  ✓ {rule_path.name}")
        except Exception as e:
            print(f"  ✗ {rule_path.name}: {e}")
    
    if output_format in ('falco', 'both', 'all') and all_falco_rules:
        output_file = input_dir / 'converted_falco_rules.yaml'
        with open(output_file, 'w') as f:
            f.write(f"# Sigma rules converted to Falco format\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Source: {input_dir}\n\n")
            f.write('\n'.join(all_falco_rules))
        print(f"\n✓ Falco rules saved to: {output_file}")
    
    if output_format in ('logql', 'both', 'all') and all_logql_rules['groups']:
        output_file = input_dir / 'converted_logql_alerts.yaml'
        with open(output_file, 'w') as f:
            f.write(f"# Sigma rules converted to LogQL alerts (Loki)\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Source: {input_dir}\n\n")
            yaml.dump(all_logql_rules, f, default_flow_style=False)
        print(f"✓ LogQL alerts saved to: {output_file}")

    if output_format in ('logsql', 'all') and all_logsql_rules['groups']:
        output_file = input_dir / 'converted_logsql_alerts.yaml'
        with open(output_file, 'w') as f:
            f.write(f"# Sigma rules converted to LogsQL alerts (VictoriaLogs)\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Source: {input_dir}\n\n")
            yaml.dump(all_logsql_rules, f, default_flow_style=False)
        print(f"✓ LogsQL alerts saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Convert Sigma rules to Falco rules, LogQL alerts (Loki), or LogsQL alerts (VictoriaLogs)'
    )
    parser.add_argument(
        'input',
        type=Path,
        help='Sigma rule file or directory'
    )
    parser.add_argument(
        '-o', '--output',
        choices=['falco', 'logql', 'logsql', 'both', 'all'],
        default='all',
        help='Output format: falco, logql (Loki), logsql (VictoriaLogs), both (falco+logql), all (default: all)'
    )
    
    args = parser.parse_args()
    
    if not args.input.exists():
        print(f"Error: {args.input} does not exist")
        sys.exit(1)
    
    if args.input.is_file():
        convert_file(args.input, args.output)
    elif args.input.is_dir():
        convert_directory(args.input, args.output)
    else:
        print(f"Error: {args.input} is not a file or directory")
        sys.exit(1)


if __name__ == '__main__':
    main()
