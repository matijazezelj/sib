"""Tests for the Anthropic provider's cheap-first escalation ladder.

No network: requests.post is replaced with a fake that answers per model/effort.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyzer
from analyzer import AnalysisRejected, AnthropicProvider, validate_analysis

GOOD = {
    "attack_vector": "Shell spawned in a container",
    "mitre_attack": {"tactic": "Execution", "technique_id": "T1059.004",
                     "technique_name": "Unix Shell", "sub_technique": None},
    "risk": {"severity": "High", "confidence": "Medium", "impact": "x"},
    "investigate": ["check parent"],
    "mitigations": {"immediate": ["a"], "short_term": [], "long_term": []},
    "false_positive": {"likelihood": "Low", "common_causes": [], "distinguishing_factors": []},
    "summary": "Someone opened a shell.",
}


def _message(text=None, stop="end_turn", model="claude-haiku-5-5", details=None):
    content = [{"type": "thinking", "thinking": "", "signature": "sig"}]
    if text is not None:
        content.append({"type": "text", "text": text})
    return {"model": model, "stop_reason": stop, "stop_details": details, "content": content,
            "usage": {"input_tokens": 1000, "output_tokens": 500}}


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


@pytest.fixture
def fake_api(monkeypatch):
    """Map (model, effort) -> response dict; record each request body and headers."""
    answers, calls = {}, []

    def post(url, headers, json, timeout):
        calls.append({"headers": headers, "body": json})
        return FakeResponse(answers[(json["model"], json["output_config"]["effort"])])

    monkeypatch.setattr(analyzer.requests, "post", post)
    return answers, calls


def test_first_tier_good_answer_is_kept(fake_api):
    answers, calls = fake_api
    answers[("claude-haiku-5-5", "medium")] = _message(json.dumps(GOOD))
    p = AnthropicProvider("k")
    assert p.analyze("sys", "user") == GOOD
    assert len(calls) == 1
    summary = p.run_summary()
    assert summary["escalations"] == 0
    assert summary["total_cost_usd"] == pytest.approx((1000 * 0.10 + 500 * 0.50) / 1e6)
    # Haiku has no server-side fallback, and no sampling params are sent.
    assert "fallbacks" not in calls[0]["body"] and "anthropic-beta" not in calls[0]["headers"]
    assert "temperature" not in calls[0]["body"]


def test_bad_json_escalates_effort_then_model(fake_api):
    answers, calls = fake_api
    answers[("claude-haiku-5-5", "medium")] = _message("not json")
    answers[("claude-haiku-5-5", "high")] = _message(json.dumps({**GOOD, "risk": {"severity": "Huge"}}))
    answers[("claude-sonnet-5-5", "medium")] = _message(json.dumps(GOOD), model="claude-sonnet-5-5")
    p = AnthropicProvider("k")
    assert p.analyze("sys", "user") == GOOD
    assert [(c["body"]["model"], c["body"]["output_config"]["effort"]) for c in calls] == [
        ("claude-haiku-5-5", "medium"), ("claude-haiku-5-5", "high"), ("claude-sonnet-5-5", "medium")]
    assert calls[2]["body"]["fallbacks"] == "default"
    assert calls[2]["headers"]["anthropic-beta"] == "server-side-fallback-2026-07-01"
    s = p.run_summary()
    assert s["escalations"] == 2 and s["model"] == "claude-sonnet-5-5"
    assert "risk.severity" in s["attempts"][1]["rejected"]


def test_refusal_and_truncation_escalate(fake_api):
    answers, _ = fake_api
    answers[("claude-haiku-5-5", "medium")] = _message(stop="refusal", details={"category": "cyber"})
    answers[("claude-haiku-5-5", "high")] = _message('{"attack', stop="max_tokens")
    answers[("claude-sonnet-5-5", "medium")] = _message(json.dumps(GOOD), model="claude-sonnet-5-5")
    p = AnthropicProvider("k")
    assert p.analyze("sys", "user") == GOOD
    rejected = [a["rejected"] for a in p.run_summary()["attempts"][:2]]
    assert "cyber" in rejected[0] and "max_tokens" in rejected[1]


def test_all_tiers_fail_raises(fake_api):
    answers, _ = fake_api
    for key in [("claude-haiku-5-5", "medium"), ("claude-haiku-5-5", "high"), ("claude-sonnet-5-5", "medium")]:
        answers[key] = _message("nope")
    with pytest.raises(AnalysisRejected, match="every tier failed"):
        AnthropicProvider("k").analyze("sys", "user")


def test_json_wrapped_in_prose_is_accepted(fake_api):
    answers, _ = fake_api
    answers[("claude-haiku-5-5", "medium")] = _message("Here you go:\n" + json.dumps(GOOD) + "\nDone.")
    assert AnthropicProvider("k").analyze("sys", "user") == GOOD


def test_pinned_model_is_a_single_tier():
    p = AnthropicProvider("k", model="claude-opus-5-5", effort="high")
    assert p.tiers == [{"model": "claude-opus-5-5", "effort": "high"}]


def test_custom_tiers_win_over_model():
    p = AnthropicProvider("k", model="claude-opus-5-5", tiers=[{"model": "claude-sonnet-5-5"}])
    assert p.tiers == [{"model": "claude-sonnet-5-5", "effort": "medium"}]


def test_config_wiring(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MODEL", "")
    cfg = analyzer.expand_env_vars({"analysis": {"provider": "anthropic", "anthropic": {
        "api_key": "k", "model": "${ANTHROPIC_MODEL:-}", "effort": "${ANTHROPIC_EFFORT:-medium}"}}})
    a = analyzer.AlertAnalyzer.__new__(analyzer.AlertAnalyzer)
    a.config = cfg
    assert a._create_provider().tiers == AnthropicProvider.DEFAULT_TIERS


@pytest.mark.parametrize("bad", [
    [], {**GOOD, "summary": ""},
    {**GOOD, "mitre_attack": {"technique_id": "1059"}},
    {k: v for k, v in GOOD.items() if k != "mitigations"},
])
def test_validate_rejects(bad):
    with pytest.raises(AnalysisRejected):
        validate_analysis(bad)
