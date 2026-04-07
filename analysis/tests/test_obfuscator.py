"""Tests for the SIB obfuscator module."""

import pytest
from obfuscator import Obfuscator, ObfuscationLevel, ObfuscationMap, obfuscate_alert


# ---------------------------------------------------------------------------
# ObfuscationMap
# ---------------------------------------------------------------------------

class TestObfuscationMap:
    def test_to_dict_keys(self):
        m = ObfuscationMap()
        d = m.to_dict()
        assert set(d.keys()) == {"ips", "hostnames", "users", "containers", "paths", "emails", "secrets_count"}

    def test_secrets_count(self):
        m = ObfuscationMap()
        m.secrets.add("secret1")
        m.secrets.add("secret2")
        assert m.to_dict()["secrets_count"] == 2


# ---------------------------------------------------------------------------
# IP obfuscation
# ---------------------------------------------------------------------------

class TestIPObfuscation:
    def test_external_ip_replaced(self):
        o = Obfuscator()
        result = o.obfuscate("Connection from 8.8.8.8 detected")
        assert "8.8.8.8" not in result
        assert "[IP-EXTERNAL-1]" in result

    def test_internal_ip_replaced(self):
        o = Obfuscator()
        result = o.obfuscate("Internal host 192.168.1.100 connected")
        assert "192.168.1.100" not in result
        assert "[IP-INTERNAL-1]" in result

    def test_loopback_is_internal(self):
        o = Obfuscator()
        result = o.obfuscate("localhost 127.0.0.1")
        assert "127.0.0.1" not in result
        assert "IP-INTERNAL" in result

    def test_same_ip_gets_same_token(self):
        o = Obfuscator()
        result = o.obfuscate("from 10.0.0.1 to 10.0.0.1")
        assert result.count("[IP-INTERNAL-1]") == 2

    def test_different_ips_get_different_tokens(self):
        o = Obfuscator()
        result = o.obfuscate("from 10.0.0.1 to 10.0.0.2")
        assert "[IP-INTERNAL-1]" in result
        assert "[IP-INTERNAL-2]" in result

    def test_multiple_external_ips(self):
        o = Obfuscator()
        result = o.obfuscate("SRC=1.2.3.4 DST=5.6.7.8")
        assert "1.2.3.4" not in result
        assert "5.6.7.8" not in result
        assert "[IP-EXTERNAL-1]" in result
        assert "[IP-EXTERNAL-2]" in result


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

class TestSecretRedaction:
    def test_aws_access_key_redacted(self):
        o = Obfuscator()
        result = o.obfuscate("key=AKIAIOSFODNN7EXAMPLE found")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED-AWS-KEY]" in result

    def test_github_pat_redacted(self):
        o = Obfuscator()
        token = "ghp_" + "A" * 36
        result = o.obfuscate(f"token={token}")
        assert token not in result
        assert "REDACTED" in result

    def test_password_field_redacted(self):
        o = Obfuscator()
        result = o.obfuscate("password=supersecret123")
        assert "supersecret123" not in result
        assert "REDACTED" in result

    def test_bearer_token_redacted(self):
        o = Obfuscator()
        result = o.obfuscate("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_secrets_applied_at_minimal_level(self):
        """Secret redaction runs at all levels, including MINIMAL."""
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o.obfuscate("AKIAIOSFODNN7EXAMPLE leaked in log")
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_secret_count_tracked(self):
        o = Obfuscator()
        o.obfuscate("password=supersecret123 and password=supersecret123")
        # Same value twice — set deduplicates to 1
        assert o.map.to_dict()["secrets_count"] >= 1


# ---------------------------------------------------------------------------
# Email obfuscation
# ---------------------------------------------------------------------------

class TestEmailObfuscation:
    def test_email_replaced(self):
        o = Obfuscator()
        result = o.obfuscate("user admin@company.com logged in")
        assert "admin@company.com" not in result
        assert "[EMAIL-1]" in result

    def test_same_email_consistent_token(self):
        o = Obfuscator()
        result = o.obfuscate("admin@acme.com and admin@acme.com")
        assert result.count("[EMAIL-1]") == 2

    def test_different_emails_different_tokens(self):
        o = Obfuscator()
        result = o.obfuscate("a@b.com and c@d.com")
        assert "[EMAIL-1]" in result
        assert "[EMAIL-2]" in result


# ---------------------------------------------------------------------------
# Container ID obfuscation
# ---------------------------------------------------------------------------

class TestContainerObfuscation:
    def test_container_id_replaced(self):
        o = Obfuscator()
        result = o.obfuscate("container=a1b2c3d4e5f6 running")
        assert "a1b2c3d4e5f6" not in result
        assert "[CONTAINER-1]" in result

    def test_short_hex_not_replaced(self):
        o = Obfuscator()
        # 11 chars — below 12-char threshold
        result = o.obfuscate("id=a1b2c3d4e5f")
        assert "a1b2c3d4e5f" in result


# ---------------------------------------------------------------------------
# User obfuscation
# ---------------------------------------------------------------------------

class TestUserObfuscation:
    def test_user_field_replaced(self):
        o = Obfuscator()
        result = o.obfuscate("user=jsmith executed command")
        assert "jsmith" not in result
        assert "[USER-1]" in result

    def test_system_user_preserved(self):
        o = Obfuscator()
        result = o.obfuscate("user=root executed command")
        assert "root" in result

    def test_system_user_nginx_preserved(self):
        o = Obfuscator()
        result = o.obfuscate("user=nginx started")
        assert "nginx" in result


# ---------------------------------------------------------------------------
# Obfuscation levels
# ---------------------------------------------------------------------------

class TestObfuscationLevels:
    def test_minimal_does_not_replace_ips(self):
        o = Obfuscator(ObfuscationLevel.MINIMAL)
        result = o.obfuscate("from 192.168.1.1")
        assert "192.168.1.1" in result

    def test_standard_replaces_ips(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate("from 192.168.1.1")
        assert "192.168.1.1" not in result

    def test_paranoid_replaces_hostnames(self):
        o = Obfuscator(ObfuscationLevel.PARANOID)
        result = o.obfuscate("host prod-web-01.acme.com reported")
        assert "prod-web-01.acme.com" not in result

    def test_standard_keeps_hostnames(self):
        o = Obfuscator(ObfuscationLevel.STANDARD)
        result = o.obfuscate("host prod-web-01.acme.com reported")
        # Standard level doesn't touch hostnames
        assert "prod-web-01.acme.com" in result


# ---------------------------------------------------------------------------
# Empty / edge inputs
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self):
        o = Obfuscator()
        assert o.obfuscate("") == ""

    def test_none_passthrough(self):
        o = Obfuscator()
        # obfuscate() returns input unchanged for falsy values
        assert o.obfuscate(None) is None  # type: ignore[arg-type]

    def test_no_sensitive_data_unchanged(self):
        o = Obfuscator()
        text = "Falco rule triggered: write below root dir"
        result = o.obfuscate(text)
        assert result == text

    def test_get_mapping_structure(self):
        o = Obfuscator()
        o.obfuscate("from 8.8.8.8 user=bob")
        mapping = o.get_mapping()
        assert "ips" in mapping
        assert "8.8.8.8" in mapping["ips"]


# ---------------------------------------------------------------------------
# obfuscate_alert convenience function
# ---------------------------------------------------------------------------

class TestObfuscateAlert:
    def test_output_field_obfuscated(self):
        alert = {"output": "user=attacker read /etc/shadow from 10.0.0.1", "rule": "Read sensitive file"}
        obfuscated, mapping = obfuscate_alert(alert)
        assert "attacker" not in obfuscated["output"]
        assert "10.0.0.1" not in obfuscated["output"]
        assert obfuscated["rule"] == "Read sensitive file"

    def test_output_fields_obfuscated(self):
        alert = {
            "output": "alert",
            "output_fields": {
                "proc.name": "bash",
                "fd.rip": "8.8.8.8",
                "user.name": "jdoe",
            }
        }
        obfuscated, _ = obfuscate_alert(alert)
        assert "8.8.8.8" not in obfuscated["output_fields"]["fd.rip"]
        # Non-sensitive field unchanged
        assert obfuscated["output_fields"]["proc.name"] == "bash"

    def test_original_alert_not_mutated(self):
        alert = {"output": "from 8.8.8.8", "rule": "test"}
        original_output = alert["output"]
        obfuscate_alert(alert)
        assert alert["output"] == original_output

    def test_returns_mapping(self):
        alert = {"output": "from 8.8.8.8"}
        _, mapping = obfuscate_alert(alert)
        assert isinstance(mapping, dict)
        assert "8.8.8.8" in mapping.get("ips", {})

    def test_invalid_level_raises(self):
        alert = {"output": "test"}
        with pytest.raises(ValueError):
            obfuscate_alert(alert, level="nonexistent")
