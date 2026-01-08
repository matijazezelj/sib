"""
SIB Obfuscator - Privacy-preserving data redaction for security alerts

Replaces sensitive information with consistent tokens while preserving
the structure and relationships needed for security analysis.
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Set
from enum import Enum


class ObfuscationLevel(Enum):
    MINIMAL = "minimal"      # Only secrets/credentials
    STANDARD = "standard"    # IPs, hostnames, users, paths (recommended)
    PARANOID = "paranoid"    # Everything except alert type


@dataclass
class ObfuscationMap:
    """Tracks obfuscated values for consistent replacement and potential de-obfuscation."""
    ips: Dict[str, str] = field(default_factory=dict)
    hostnames: Dict[str, str] = field(default_factory=dict)
    users: Dict[str, str] = field(default_factory=dict)
    containers: Dict[str, str] = field(default_factory=dict)
    paths: Dict[str, str] = field(default_factory=dict)
    pids: Dict[str, str] = field(default_factory=dict)
    emails: Dict[str, str] = field(default_factory=dict)
    secrets: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> dict:
        """Export mapping for potential de-obfuscation."""
        return {
            "ips": self.ips,
            "hostnames": self.hostnames,
            "users": self.users,
            "containers": self.containers,
            "paths": self.paths,
            "pids": self.pids,
            "emails": self.emails,
            "secrets_count": len(self.secrets)
        }


class Obfuscator:
    """Obfuscates sensitive data in security alerts while preserving analytical value."""
    
    # RFC 1918 private IP ranges
    PRIVATE_IP_RANGES = [
        (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
        (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
        (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
        (0x7F000000, 0x7FFFFFFF),  # 127.0.0.0/8 (loopback)
    ]
    
    # Patterns for sensitive data
    PATTERNS = {
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'container_id': r'\b[a-f0-9]{12,64}\b',
        'aws_key': r'\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b',
        'aws_secret': r'\b[A-Za-z0-9/+=]{40}\b',
        'api_key': r'\b(api[_-]?key|apikey|api[_-]?token)[=:]\s*["\']?[\w-]{20,}["\']?\b',
        'jwt': r'\beyJ[A-Za-z0-9-_]*\.eyJ[A-Za-z0-9-_]*\.[A-Za-z0-9-_.+/]*\b',
        'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        'password_field': r'(password|passwd|pwd|secret|token)[=:]\s*["\']?[^\s"\']+["\']?',
    }
    
    # System users that are safe to show
    SYSTEM_USERS = {'root', 'nobody', 'daemon', 'www-data', 'nginx', 'postgres', 'mysql', 'redis'}
    
    # Sensitive files to always flag
    SENSITIVE_PATHS = {
        '/etc/shadow', '/etc/passwd', '/etc/sudoers', '/etc/ssh/',
        '/.ssh/', '/id_rsa', '/id_ed25519', '/.aws/credentials',
        '/.kube/config', '/secrets/', '/vault/', '/.env'
    }
    
    def __init__(self, level: ObfuscationLevel = ObfuscationLevel.STANDARD):
        self.level = level
        self.map = ObfuscationMap()
        self._counters = {
            'ip_internal': 0,
            'ip_external': 0,
            'host': 0,
            'user': 0,
            'container': 0,
            'path': 0,
            'pid': 0,
            'email': 0,
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        try:
            parts = [int(p) for p in ip.split('.')]
            ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            return any(start <= ip_int <= end for start, end in self.PRIVATE_IP_RANGES)
        except (ValueError, IndexError):
            return False
    
    def _get_token(self, category: str, original: str, mapping: Dict[str, str]) -> str:
        """Get or create a consistent token for a value."""
        if original in mapping:
            return mapping[original]
        
        self._counters[category] += 1
        token = f"[{category.upper().replace('_', '-')}-{self._counters[category]}]"
        mapping[original] = token
        return token
    
    def _obfuscate_ips(self, text: str) -> str:
        """Replace IP addresses with tokens, preserving internal/external distinction."""
        def replace_ip(match):
            ip = match.group(0)
            category = 'ip_internal' if self._is_private_ip(ip) else 'ip_external'
            return self._get_token(category, ip, self.map.ips)
        
        text = re.sub(self.PATTERNS['ipv4'], replace_ip, text)
        text = re.sub(self.PATTERNS['ipv6'], 
                      lambda m: self._get_token('ip_external', m.group(0), self.map.ips), text)
        return text
    
    def _obfuscate_secrets(self, text: str) -> str:
        """Redact secrets and credentials - always applied regardless of level."""
        # AWS keys
        text = re.sub(self.PATTERNS['aws_key'], '[REDACTED-AWS-KEY]', text)
        text = re.sub(self.PATTERNS['aws_secret'], '[REDACTED-SECRET]', text)
        
        # API keys and tokens
        text = re.sub(self.PATTERNS['api_key'], r'\1=[REDACTED-API-KEY]', text, flags=re.IGNORECASE)
        
        # JWTs
        text = re.sub(self.PATTERNS['jwt'], '[REDACTED-JWT]', text)
        
        # Private keys
        text = re.sub(self.PATTERNS['private_key'], '[REDACTED-PRIVATE-KEY]', text)
        
        # Password fields
        def redact_password(match):
            self.map.secrets.add(match.group(0))
            return match.group(1) + '=[REDACTED-PASSWORD]'
        text = re.sub(self.PATTERNS['password_field'], redact_password, text, flags=re.IGNORECASE)
        
        return text
    
    def _obfuscate_emails(self, text: str) -> str:
        """Replace email addresses with tokens."""
        def replace_email(match):
            return self._get_token('email', match.group(0), self.map.emails)
        return re.sub(self.PATTERNS['email'], replace_email, text)
    
    def _obfuscate_containers(self, text: str) -> str:
        """Replace container IDs with tokens."""
        def replace_container(match):
            cid = match.group(0)
            # Only obfuscate if it looks like a container ID (hex, 12+ chars)
            if len(cid) >= 12 and all(c in '0123456789abcdef' for c in cid.lower()):
                return self._get_token('container', cid, self.map.containers)
            return cid
        return re.sub(self.PATTERNS['container_id'], replace_container, text)
    
    def _obfuscate_users(self, text: str) -> str:
        """Replace usernames with tokens, preserving system users."""
        # Pattern for user= or similar
        def replace_user(match):
            user = match.group(2)
            if user.lower() in self.SYSTEM_USERS:
                return match.group(0)  # Keep system users visible
            token = self._get_token('user', user, self.map.users)
            return f"{match.group(1)}{token}"
        
        patterns = [
            r'(user=)(\w+)',
            r'(uid=)(\d+)',
            r'(User )(\w+)',
            r'(by user )(\w+)',
        ]
        for pattern in patterns:
            text = re.sub(pattern, replace_user, text, flags=re.IGNORECASE)
        return text
    
    def _obfuscate_paths(self, text: str) -> str:
        """Obfuscate file paths while preserving structure and sensitive indicators."""
        # Keep sensitive path indicators visible
        def replace_path(match):
            path = match.group(0)
            
            # Check if path contains sensitive indicators - keep those visible
            for sensitive in self.SENSITIVE_PATHS:
                if sensitive in path:
                    return path  # Keep sensitive paths visible for analysis
            
            # For other paths, obfuscate the specific parts but keep structure
            parts = path.split('/')
            obfuscated_parts = []
            for part in parts:
                if not part:
                    obfuscated_parts.append('')
                elif part in ('home', 'var', 'tmp', 'etc', 'usr', 'opt', 'root', 'proc', 'sys', 'dev'):
                    obfuscated_parts.append(part)  # Keep common directories
                elif '.' in part:
                    # Keep extension, obfuscate name
                    name, ext = part.rsplit('.', 1)
                    if len(name) > 3:
                        obfuscated_parts.append(f'[FILE].{ext}')
                    else:
                        obfuscated_parts.append(part)
                else:
                    obfuscated_parts.append(part)
            
            return '/'.join(obfuscated_parts)
        
        # Match file paths
        text = re.sub(r'/[\w./-]+', replace_path, text)
        return text
    
    def _obfuscate_hostnames(self, text: str) -> str:
        """Replace hostnames with tokens."""
        # Match FQDN-like patterns
        def replace_hostname(match):
            hostname = match.group(0)
            # Don't obfuscate localhost or simple service names
            if hostname.lower() in ('localhost', 'localhost.localdomain'):
                return hostname
            return self._get_token('host', hostname, self.map.hostnames)
        
        # Match hostnames (word.word.word pattern, at least 2 parts)
        text = re.sub(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+\b', replace_hostname, text)
        return text
    
    def obfuscate(self, text: str) -> str:
        """
        Obfuscate sensitive data in text based on configured level.
        
        Args:
            text: Raw alert text containing potentially sensitive data
            
        Returns:
            Obfuscated text safe for LLM analysis
        """
        if not text:
            return text
        
        # Always obfuscate secrets regardless of level
        result = self._obfuscate_secrets(text)
        
        if self.level == ObfuscationLevel.MINIMAL:
            return result
        
        # Standard level
        result = self._obfuscate_ips(result)
        result = self._obfuscate_emails(result)
        result = self._obfuscate_containers(result)
        result = self._obfuscate_users(result)
        
        if self.level == ObfuscationLevel.PARANOID:
            result = self._obfuscate_paths(result)
            result = self._obfuscate_hostnames(result)
        
        return result
    
    def get_mapping(self) -> dict:
        """Get the obfuscation mapping for potential de-obfuscation."""
        return self.map.to_dict()


def obfuscate_alert(alert: dict, level: str = "standard") -> tuple[dict, dict]:
    """
    Convenience function to obfuscate an alert dictionary.
    
    Args:
        alert: Alert dictionary with 'output', 'rule', etc.
        level: Obfuscation level (minimal, standard, paranoid)
        
    Returns:
        Tuple of (obfuscated_alert, obfuscation_mapping)
    """
    obfuscator = Obfuscator(ObfuscationLevel(level))
    
    obfuscated = alert.copy()
    
    # Obfuscate the main output field
    if 'output' in obfuscated:
        obfuscated['output'] = obfuscator.obfuscate(obfuscated['output'])
    
    # Obfuscate output_fields if present
    if 'output_fields' in obfuscated:
        fields = obfuscated['output_fields'].copy()
        for key, value in fields.items():
            if isinstance(value, str):
                fields[key] = obfuscator.obfuscate(value)
        obfuscated['output_fields'] = fields
    
    return obfuscated, obfuscator.get_mapping()


# Example usage and testing
if __name__ == "__main__":
    test_alert = """
    Read sensitive file untrusted: user=jsmith command=cat /etc/shadow 
    container=a1b2c3d4e5f6 (nginx:latest) connection from 192.168.1.100 
    to external IP 52.94.233.12:443 password=secret123 
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE email=admin@company.com
    host=prod-web-01.acme.com pid=12345
    """
    
    print("=== MINIMAL ===")
    obfuscator = Obfuscator(ObfuscationLevel.MINIMAL)
    print(obfuscator.obfuscate(test_alert))
    
    print("\n=== STANDARD ===")
    obfuscator = Obfuscator(ObfuscationLevel.STANDARD)
    print(obfuscator.obfuscate(test_alert))
    
    print("\n=== PARANOID ===")
    obfuscator = Obfuscator(ObfuscationLevel.PARANOID)
    print(obfuscator.obfuscate(test_alert))
    print("\nMapping:", obfuscator.get_mapping())
