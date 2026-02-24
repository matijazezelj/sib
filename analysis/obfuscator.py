"""
SIB Obfuscator - Privacy-preserving data redaction for security alerts

Replaces sensitive information with consistent tokens while preserving
the structure and relationships needed for security analysis.
"""

import re
import math
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
    
    # Patterns for sensitive data - based on TruffleHog detectors
    # https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors
    PATTERNS = {
        # Network identifiers
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'container_id': r'\b[a-f0-9]{12,64}\b',
        
        # AWS - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
        'aws_access_key': r'\b(A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b',
        'aws_secret_key': r'\b[A-Za-z0-9+/]{40}\b',
        'aws_session_token': r'\b(FwoGZXIvYXdzE|IQoJb3JpZ2lu)[A-Za-z0-9/+=]+\b',
        'aws_mws_key': r'\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        
        # GitHub tokens
        'github_pat': r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b',
        'github_fine_grained': r'\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b',
        'github_oauth': r'\bgho_[A-Za-z0-9]{36}\b',
        'github_app_token': r'\b(ghu|ghs)_[A-Za-z0-9]{36}\b',
        'github_refresh_token': r'\bghr_[A-Za-z0-9]{36,}\b',
        
        # GitLab tokens
        'gitlab_pat': r'\bglpat-[A-Za-z0-9\-_]{20,}\b',
        'gitlab_pipeline': r'\bglptt-[A-Za-z0-9]{40}\b',
        'gitlab_runner': r'\bGR1348941[A-Za-z0-9\-_]{20,}\b',
        
        # Slack
        'slack_bot_token': r'\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b',
        'slack_user_token': r'\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b',
        'slack_app_token': r'\bxapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{64}\b',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}',
        
        # Google
        'google_api_key': r'\bAIza[0-9A-Za-z\-_]{35}\b',
        'google_oauth_id': r'\b[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com\b',
        'google_oauth_secret': r'\bGOCspx-[A-Za-z0-9\-_]{28}\b',
        'gcp_service_account': r'\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b',
        
        # Azure / Microsoft
        'azure_storage_key': r'\b[A-Za-z0-9+/]{86}==\b',
        'azure_client_secret': r'\b[A-Za-z0-9~._-]{34}\b',
        'azure_sas_token': r'\bsig=[A-Za-z0-9%]+&se=[0-9]+&[A-Za-z0-9&=%]+\b',
        
        # Stripe
        'stripe_secret_key': r'\b(sk|rk)_(test|live)_[A-Za-z0-9]{24,}\b',
        'stripe_publishable_key': r'\bpk_(test|live)_[A-Za-z0-9]{24,}\b',
        'stripe_restricted_key': r'\brk_(test|live)_[A-Za-z0-9]{24,}\b',
        
        # Twilio
        'twilio_api_key': r'\bSK[a-f0-9]{32}\b',
        'twilio_account_sid': r'\bAC[a-f0-9]{32}\b',
        'twilio_auth_token': r'\b[a-f0-9]{32}\b',
        
        # SendGrid
        'sendgrid_api_key': r'\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b',
        
        # Mailchimp
        'mailchimp_api_key': r'\b[a-f0-9]{32}-us[0-9]{1,2}\b',
        
        # Mailgun
        'mailgun_api_key': r'\bkey-[A-Za-z0-9]{32}\b',
        
        # NPM
        'npm_token': r'\bnpm_[A-Za-z0-9]{36}\b',
        
        # PyPI
        'pypi_token': r'\bpypi-[A-Za-z0-9\-_]{50,}\b',
        
        # NuGet
        'nuget_api_key': r'\boy2[A-Za-z0-9]{43}\b',
        
        # Heroku
        'heroku_api_key': r'\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b',
        
        # DigitalOcean
        'digitalocean_pat': r'\bdop_v1_[a-f0-9]{64}\b',
        'digitalocean_oauth': r'\bdoo_v1_[a-f0-9]{64}\b',
        'digitalocean_refresh': r'\bdor_v1_[a-f0-9]{64}\b',
        
        # Cloudflare
        'cloudflare_api_key': r'\b[A-Za-z0-9_-]{37}\b',
        'cloudflare_origin_ca': r'\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b',
        
        # Discord
        'discord_bot_token': r'\b(MTA|MTE|MTI|OT|Nj|Nz|OD)[A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b',
        'discord_webhook': r'https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
        
        # Telegram
        'telegram_bot_token': r'\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b',
        
        # Datadog
        'datadog_api_key': r'\b[a-f0-9]{32}\b',
        'datadog_app_key': r'\b[a-f0-9]{40}\b',
        
        # Sentry
        'sentry_dsn': r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+',
        
        # PagerDuty
        'pagerduty_api_key': r'\b[A-Za-z0-9+/]{20}\b',
        
        # Database connection strings
        'postgres_uri': r'postgres(ql)?://[^:]+:[^@]+@[^/]+/\w+',
        'mysql_uri': r'mysql://[^:]+:[^@]+@[^/]+/\w+',
        'mongodb_uri': r'mongodb(\+srv)?://[^:]+:[^@]+@[^/]+',
        'redis_uri': r'redis://[^:]+:[^@]+@[^/]+',
        
        # Generic patterns
        'jwt': r'\beyJ[A-Za-z0-9-_]*\.eyJ[A-Za-z0-9-_]*\.[A-Za-z0-9-_.+/]*\b',
        'private_key': r'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----',
        'private_key_content': r'-----BEGIN[^-]+-----[A-Za-z0-9+/=\s]+-----END[^-]+-----',
        'password_field': r'(password|passwd|pwd|secret_key|auth_key|private_key|encryption_key)[=:]\s*["\']?[^\s"\']{8,}["\']?',
        'basic_auth': r'\bBasic\s+[A-Za-z0-9+/]+=*\b',
        'bearer_token': r'\bBearer\s+[A-Za-z0-9\-_\.]+\b',
        
        # High entropy base64 (potential secrets)
        'base64_secret': r'\b[A-Za-z0-9+/]{40,}={0,2}\b',
        
        # SSH keys
        'ssh_private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'ssh_public_key': r'ssh-(rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/]+[=]{0,2}',
    }
    
    # Secret type labels for redaction messages
    SECRET_LABELS = {
        'aws_access_key': 'AWS-KEY',
        'aws_secret_key': 'AWS-SECRET',
        'aws_session_token': 'AWS-SESSION',
        'aws_mws_key': 'AWS-MWS',
        'github_pat': 'GITHUB-TOKEN',
        'github_fine_grained': 'GITHUB-TOKEN',
        'github_oauth': 'GITHUB-OAUTH',
        'github_app_token': 'GITHUB-APP',
        'github_refresh_token': 'GITHUB-REFRESH',
        'gitlab_pat': 'GITLAB-TOKEN',
        'gitlab_pipeline': 'GITLAB-PIPELINE',
        'gitlab_runner': 'GITLAB-RUNNER',
        'slack_bot_token': 'SLACK-BOT',
        'slack_user_token': 'SLACK-USER',
        'slack_app_token': 'SLACK-APP',
        'slack_webhook': 'SLACK-WEBHOOK',
        'google_api_key': 'GOOGLE-API',
        'google_oauth_id': 'GOOGLE-OAUTH',
        'google_oauth_secret': 'GOOGLE-SECRET',
        'gcp_service_account': 'GCP-SERVICE-ACCOUNT',
        'azure_storage_key': 'AZURE-STORAGE',
        'azure_client_secret': 'AZURE-SECRET',
        'azure_sas_token': 'AZURE-SAS',
        'stripe_secret_key': 'STRIPE-SECRET',
        'stripe_publishable_key': 'STRIPE-KEY',
        'stripe_restricted_key': 'STRIPE-RESTRICTED',
        'twilio_api_key': 'TWILIO-KEY',
        'twilio_account_sid': 'TWILIO-SID',
        'twilio_auth_token': 'TWILIO-AUTH',
        'sendgrid_api_key': 'SENDGRID-KEY',
        'mailchimp_api_key': 'MAILCHIMP-KEY',
        'mailgun_api_key': 'MAILGUN-KEY',
        'npm_token': 'NPM-TOKEN',
        'pypi_token': 'PYPI-TOKEN',
        'nuget_api_key': 'NUGET-KEY',
        'heroku_api_key': 'HEROKU-KEY',
        'digitalocean_pat': 'DO-TOKEN',
        'digitalocean_oauth': 'DO-OAUTH',
        'digitalocean_refresh': 'DO-REFRESH',
        'cloudflare_api_key': 'CLOUDFLARE-KEY',
        'cloudflare_origin_ca': 'CLOUDFLARE-CA',
        'discord_bot_token': 'DISCORD-BOT',
        'discord_webhook': 'DISCORD-WEBHOOK',
        'telegram_bot_token': 'TELEGRAM-BOT',
        'datadog_api_key': 'DATADOG-API',
        'datadog_app_key': 'DATADOG-APP',
        'sentry_dsn': 'SENTRY-DSN',
        'pagerduty_api_key': 'PAGERDUTY-KEY',
        'postgres_uri': 'DB-POSTGRES',
        'mysql_uri': 'DB-MYSQL',
        'mongodb_uri': 'DB-MONGODB',
        'redis_uri': 'DB-REDIS',
        'jwt': 'JWT',
        'private_key': 'PRIVATE-KEY',
        'private_key_content': 'PRIVATE-KEY',
        'password_field': 'PASSWORD',
        'basic_auth': 'BASIC-AUTH',
        'bearer_token': 'BEARER-TOKEN',
        'base64_secret': 'SECRET',
        'ssh_private_key': 'SSH-PRIVATE-KEY',
        'ssh_public_key': 'SSH-PUBLIC-KEY',
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
        """
        Redact secrets and credentials - always applied regardless of level.
        Uses TruffleHog-style pattern matching for comprehensive secret detection.
        """
        # Define secret patterns to check (in order of specificity - most specific first)
        secret_patterns = [
            # Cloud providers - specific patterns first
            'aws_access_key', 'aws_session_token', 'aws_mws_key',
            'gcp_service_account', 'google_api_key', 'google_oauth_id', 'google_oauth_secret',
            'azure_storage_key', 'azure_sas_token',
            
            # Version control
            'github_pat', 'github_fine_grained', 'github_oauth', 'github_app_token', 'github_refresh_token',
            'gitlab_pat', 'gitlab_pipeline', 'gitlab_runner',
            
            # Communication platforms
            'slack_bot_token', 'slack_user_token', 'slack_app_token', 'slack_webhook',
            'discord_bot_token', 'discord_webhook',
            'telegram_bot_token',
            
            # Payment & services
            'stripe_secret_key', 'stripe_publishable_key', 'stripe_restricted_key',
            'twilio_api_key', 'twilio_account_sid',
            
            # Email services
            'sendgrid_api_key', 'mailchimp_api_key', 'mailgun_api_key',
            
            # Package managers
            'npm_token', 'pypi_token', 'nuget_api_key',
            
            # Cloud platforms
            'heroku_api_key',
            'digitalocean_pat', 'digitalocean_oauth', 'digitalocean_refresh',
            'cloudflare_api_key', 'cloudflare_origin_ca',
            
            # Monitoring
            'sentry_dsn',
            'pagerduty_api_key',
            
            # Database connection strings (contain credentials)
            'postgres_uri', 'mysql_uri', 'mongodb_uri', 'redis_uri',
            
            # Auth tokens
            'jwt', 'basic_auth', 'bearer_token',
            
            # Private keys (handle specially)
            'private_key_content', 'private_key', 'ssh_private_key',
            
            # Password fields
            'password_field',
            
            # Note: aws_secret_key, datadog_*, twilio_auth_token, azure_client_secret
            # and base64_secret are too generic (match many false positives)
            # Only use them in paranoid mode
        ]
        
        # Apply each pattern
        for pattern_name in secret_patterns:
            if pattern_name not in self.PATTERNS:
                continue
            pattern = self.PATTERNS[pattern_name]
            label = self.SECRET_LABELS.get(pattern_name, 'SECRET')
            
            def make_replacer(lbl):
                def replacer(match):
                    self.map.secrets.add(match.group(0)[:20] + '...')  # Store truncated for audit
                    return f'[REDACTED-{lbl}]'
                return replacer
            
            try:
                text = re.sub(pattern, make_replacer(label), text, flags=re.IGNORECASE)
            except re.error:
                # Skip invalid patterns
                pass
        
        return text
    
    def _obfuscate_high_entropy(self, text: str) -> str:
        """Detect and redact high-entropy strings that might be secrets (paranoid mode only)."""
        
        def entropy(s):
            """Calculate Shannon entropy of a string."""
            if not s:
                return 0
            prob = [float(s.count(c)) / len(s) for c in set(s)]
            return -sum(p * math.log2(p) for p in prob)
        
        def replace_high_entropy(match):
            s = match.group(0)
            # High entropy threshold - typical secrets have entropy > 4.5
            if len(s) >= 20 and entropy(s) > 4.5:
                self.map.secrets.add(s[:10] + '...')
                return '[REDACTED-HIGH-ENTROPY]'
            return s
        
        # Match potential secrets (base64-like, hex, alphanumeric)
        text = re.sub(r'\b[A-Za-z0-9+/=_-]{20,}\b', replace_high_entropy, text)
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
            result = self._obfuscate_high_entropy(result)
        
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
