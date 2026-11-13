"""Tests for the Telegram output in scripts/generate-sidekick-config.sh."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
OLD = "# previous config\n"


@pytest.fixture
def sib(tmp_path):
    (tmp_path / "scripts").mkdir()
    shutil.copy(REPO / "scripts/generate-sidekick-config.sh", tmp_path / "scripts")
    (tmp_path / "alerting/config").mkdir(parents=True)
    (tmp_path / "alerting/config/config.yaml").write_text(OLD)
    return tmp_path


def run(root, **env):
    return subprocess.run(
        ["bash", str(root / "scripts/generate-sidekick-config.sh")],
        env={"PATH": os.environ["PATH"], **env}, capture_output=True, text=True)


def config(root):
    return (root / "alerting/config/config.yaml").read_text()


def test_complete_telegram_config(sib):
    r = run(sib, TELEGRAM_TOKEN="123456:abc", TELEGRAM_CHAT_ID="-1001234567890",
            TELEGRAM_MINIMUM_PRIORITY="warning")
    assert r.returncode == 0, r.stderr
    assert yaml.safe_load(config(sib))["telegram"] == {
        "token": "123456:abc", "chatid": "-1001234567890", "minimumpriority": "warning"}


def test_no_telegram_settings_means_no_output(sib):
    assert run(sib).returncode == 0
    assert "telegram" not in yaml.safe_load(config(sib))


@pytest.mark.parametrize("env", [
    {"TELEGRAM_TOKEN": "123456:abc"},
    {"TELEGRAM_CHAT_ID": "-1001234567890"},
    {"TELEGRAM_TOKEN": "123456:abc", "TELEGRAM_CHAT_ID": "my chat"},
])
def test_incomplete_or_invalid_telegram_fails_and_keeps_old_config(sib, env):
    r = run(sib, **env)
    assert r.returncode != 0
    assert "Telegram" in r.stderr
    assert config(sib) == OLD
