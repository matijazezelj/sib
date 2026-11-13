"""Regression tests for scripts/generate-grafana-alerting.sh.

The generator runs in a temporary copy of the repo layout with no Ansible
inventory, so no Docker is needed. Each test checks the provisioning files it
writes, above all who owns Grafana's organisation-wide notification policy.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
SLACK = "https://hooks.slack.com/services/T000/B000/XXXX"
HEARTBEAT = "https://uptime.example.com/api/push/abc"


@pytest.fixture
def sib(tmp_path):
    """A minimal SIB tree: the generator plus the alerting templates."""
    (tmp_path / "scripts").mkdir()
    shutil.copy(REPO / "scripts/generate-grafana-alerting.sh", tmp_path / "scripts")
    alerting = tmp_path / "grafana/provisioning/alerting"
    shutil.copytree(REPO / "grafana/provisioning/alerting/templates", alerting / "templates")
    (tmp_path / "detection/config").mkdir(parents=True)
    return tmp_path


def run(root, check=True, **env):
    """Run the generator with only PATH and the given settings in its environment."""
    full_env = {"PATH": os.environ["PATH"], **{k: v for k, v in env.items() if v is not None}}
    return subprocess.run(
        ["bash", str(root / "scripts/generate-grafana-alerting.sh")],
        env=full_env, capture_output=True, text=True, check=check)


def load(root, name):
    path = root / "grafana/provisioning/alerting" / name
    return yaml.safe_load(path.read_text()) if path.exists() else None


def notifications(root):
    return load(root, "notifications.yml") or {}


def contact_uids(doc):
    return sorted(r["uid"] for cp in doc.get("contactPoints", []) for r in cp["receivers"])


def deleted_contacts(doc):
    return sorted(c["uid"] for c in doc.get("deleteContactPoints", []))


def all_rules(root):
    rules = []
    for name in ("alert-rules.yml", "heartbeat.yml", "falco-liveness.yml"):
        doc = load(root, name)
        for group in (doc or {}).get("groups", []):
            rules.extend(group["rules"])
    return rules


# --- unmanaged: never takes ownership ------------------------------------------

@pytest.mark.parametrize("webhook,heartbeat", [(None, None), (SLACK, None), (None, HEARTBEAT), (SLACK, HEARTBEAT)])
def test_unmanaged_never_writes_policies(sib, webhook, heartbeat):
    for _ in range(3):  # repeated runs stay unmanaged
        run(sib, GRAFANA_MANAGE_NOTIFICATION_POLICY="false",
            GRAFANA_ALERT_WEBHOOK_URL=webhook, GRAFANA_HEARTBEAT_URL=heartbeat)
        doc = notifications(sib)
        assert "policies" not in doc
        assert "resetPolicies" not in doc
        assert "deleteContactPoints" not in doc


def test_unmanaged_with_slack_still_provisions_contact_points(sib):
    run(sib, GRAFANA_MANAGE_NOTIFICATION_POLICY="false",
        GRAFANA_ALERT_WEBHOOK_URL=SLACK, GRAFANA_HEARTBEAT_URL=HEARTBEAT)
    assert contact_uids(notifications(sib)) == ["sib-alerts", "sib-heartbeat"]


def test_switching_to_unmanaged_does_not_reset_a_managed_policy(sib):
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=SLACK)
    assert "policies" in notifications(sib)
    run(sib, GRAFANA_MANAGE_NOTIFICATION_POLICY="false")
    doc = notifications(sib)
    assert "resetPolicies" not in doc and "deleteContactPoints" not in doc and "policies" not in doc


def test_unmanaged_url_is_not_written_to_disk(sib):
    run(sib, GRAFANA_MANAGE_NOTIFICATION_POLICY="false", GRAFANA_ALERT_WEBHOOK_URL=SLACK)
    text = (sib / "grafana/provisioning/alerting/notifications.yml").read_text()
    assert SLACK not in text and "$GRAFANA_ALERT_WEBHOOK_URL" in text


# --- managed (default) ---------------------------------------------------------

def test_fresh_unconfigured_leaves_policy_alone(sib):
    for _ in range(2):
        run(sib)
        doc = notifications(sib)
        assert "policies" not in doc and "resetPolicies" not in doc and "deleteContactPoints" not in doc


def test_managed_webhook_owns_policy(sib):
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=SLACK)
    policy = notifications(sib)["policies"][0]
    assert policy["receiver"] == "sib-alerts"
    assert {tuple(r["object_matchers"][0]) for r in policy["routes"]} == {
        ("severity", "=", "critical"), ("severity", "=", "warning")}


def test_managed_heartbeat_route_is_scoped_by_alertname(sib):
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=SLACK, GRAFANA_HEARTBEAT_URL=HEARTBEAT)
    routes = notifications(sib)["policies"][0]["routes"]
    hb = [r for r in routes if r["receiver"] == "sib-heartbeat"]
    assert hb == [r for r in routes if r["object_matchers"] == [["alertname", "=", "SIB heartbeat"]]]
    assert hb[0]["repeat_interval"] == "5m"


def test_managed_enabled_then_disabled_hands_policy_back_once(sib):
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=SLACK, GRAFANA_HEARTBEAT_URL=HEARTBEAT)
    run(sib)
    doc = notifications(sib)
    assert doc["resetPolicies"] == [1]
    assert deleted_contacts(doc) == ["sib-alerts", "sib-alerts-telegram", "sib-heartbeat"]
    run(sib)  # next run: nothing left to hand back
    doc = notifications(sib)
    assert "resetPolicies" not in doc and "deleteContactPoints" not in doc


def test_managed_removing_heartbeat_keeps_policy_and_deletes_only_heartbeat(sib):
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=SLACK, GRAFANA_HEARTBEAT_URL=HEARTBEAT)
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=SLACK)
    doc = notifications(sib)
    assert "policies" in doc and "resetPolicies" not in doc
    assert deleted_contacts(doc) == ["sib-alerts-telegram", "sib-heartbeat"]


@pytest.mark.parametrize("manage", ["true", "false"])
def test_repeated_runs_are_identical(sib, manage):
    files = {}
    for i in range(2):
        run(sib, GRAFANA_MANAGE_NOTIFICATION_POLICY=manage,
            GRAFANA_ALERT_WEBHOOK_URL=SLACK, GRAFANA_HEARTBEAT_URL=HEARTBEAT)
        files[i] = {p.name: p.read_text() for p in (sib / "grafana/provisioning/alerting").glob("*.yml")}
    assert files[0] == files[1]


# --- rules ---------------------------------------------------------------------

@pytest.mark.parametrize("stack,logs_default", [("vm", "victorialogs"), ("grafana", "loki")])
def test_datasource_uids_are_configurable(sib, stack, logs_default):
    (sib / "detection/config/falco.yaml").touch()  # local Falco -> liveness rule
    run(sib, STACK=stack, GRAFANA_HEARTBEAT_URL=HEARTBEAT,
        GRAFANA_METRICS_DS_UID="sib-victoriametrics", GRAFANA_LOGS_DS_UID="shared-logs")
    uids = set()
    for rule in all_rules(sib):
        for q in rule["data"]:
            uids.add(q["datasourceUid"])
            uids.add(q["model"]["datasource"]["uid"])
    assert uids == {"__expr__", "sib-victoriametrics", "shared-logs"}


@pytest.mark.parametrize("stack,logs_default", [("vm", "victorialogs"), ("grafana", "loki")])
def test_default_datasource_uids(sib, stack, logs_default):
    run(sib, STACK=stack)
    uids = {q["datasourceUid"] for r in all_rules(sib) for q in r["data"]}
    assert uids == {"__expr__", "prometheus", logs_default}


def test_sib_rules_carry_source_sib_and_heartbeat_does_not(sib):
    (sib / "detection/config/falco.yaml").touch()
    run(sib, GRAFANA_HEARTBEAT_URL=HEARTBEAT)
    for rule in all_rules(sib):
        if rule["uid"] == "sib-heartbeat":
            assert rule["labels"]["source"] != "sib"
        else:
            assert rule["labels"]["source"] == "sib", rule["uid"]


def test_sidekick_output_errors_match_old_and_new_metric_names(sib):
    run(sib)
    rule = next(r for r in all_rules(sib) if r["uid"] == "sib-sidekick-output-errors")
    expr = rule["data"][0]["model"]["expr"]
    assert "falcosidekick_outputs{" in expr
    assert "falcosecurity_falcosidekick_outputs_total{" in expr


@pytest.mark.parametrize("env", [
    {"GRAFANA_MANAGE_NOTIFICATION_POLICY": "maybe"},
    {"GRAFANA_METRICS_DS_UID": "bad uid"},
    {"GRAFANA_LOGS_DS_UID": "x/y"},
    {"GRAFANA_ALERT_WEBHOOK_TYPE": "teams"},
])
def test_invalid_settings_are_rejected(sib, env):
    assert run(sib, check=False, **env).returncode != 0


# --- Telegram ------------------------------------------------------------------

TG = {"GRAFANA_ALERT_TELEGRAM_BOT_TOKEN": "123456:secret-token", "GRAFANA_ALERT_TELEGRAM_CHAT_ID": "-1001234567890"}


def receivers(doc, name):
    return next(cp["receivers"] for cp in doc.get("contactPoints", []) if cp["name"] == name)


@pytest.mark.parametrize("webhook", [None, SLACK])
def test_telegram_is_an_integration_on_sib_alerts(sib, webhook):
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=webhook, **TG)
    doc = notifications(sib)
    recv = receivers(doc, "sib-alerts")
    tg = next(r for r in recv if r["type"] == "telegram")
    assert tg["uid"] == "sib-alerts-telegram"
    assert tg["settings"] == {"bottoken": "$GRAFANA_ALERT_TELEGRAM_BOT_TOKEN",
                              "chatid": "-1001234567890"}
    assert len(recv) == (2 if webhook else 1)
    assert doc["policies"][0]["receiver"] == "sib-alerts"


def test_telegram_chat_id_is_a_literal_string(sib):
    """Grafana re-types substituted values, so a $VAR chat ID like -100... would
    become a number and fail validation (seen on Grafana 11.4)."""
    run(sib, **TG)
    raw = (sib / "grafana/provisioning/alerting/notifications.yml").read_text()
    assert 'chatid: "-1001234567890"' in raw
    assert "$GRAFANA_ALERT_TELEGRAM_CHAT_ID" not in raw


def test_telegram_token_is_not_written_to_disk(sib):
    run(sib, **TG)
    text = (sib / "grafana/provisioning/alerting/notifications.yml").read_text()
    assert "secret-token" not in text


def test_removing_telegram_deletes_only_its_integration(sib):
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=SLACK, **TG)
    run(sib, GRAFANA_ALERT_WEBHOOK_URL=SLACK)
    doc = notifications(sib)
    assert "policies" in doc and "resetPolicies" not in doc
    assert deleted_contacts(doc) == ["sib-alerts-telegram", "sib-heartbeat"]


def test_unmanaged_telegram_never_owns_policy(sib):
    for _ in range(2):
        run(sib, GRAFANA_MANAGE_NOTIFICATION_POLICY="false", **TG)
        doc = notifications(sib)
        assert "policies" not in doc and "resetPolicies" not in doc and "deleteContactPoints" not in doc
        assert receivers(doc, "sib-alerts")[0]["type"] == "telegram"


@pytest.mark.parametrize("env", [
    {"GRAFANA_ALERT_TELEGRAM_BOT_TOKEN": "123:abc"},
    {"GRAFANA_ALERT_TELEGRAM_CHAT_ID": "-100123"},
    {"GRAFANA_ALERT_TELEGRAM_BOT_TOKEN": "123:abc", "GRAFANA_ALERT_TELEGRAM_CHAT_ID": "not a chat"},
])
def test_incomplete_or_invalid_telegram_is_rejected(sib, env):
    assert run(sib, check=False, **env).returncode != 0
