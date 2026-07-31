"""Tests for the Analysis API token guard.

The API triggers billed LLM calls, so an unauthenticated endpoint is a way to
drain someone's provider budget. These tests pin that behaviour down.
"""

import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TOKEN = "test-token-123"

# Endpoints that must never be reachable without a token, as (method, path).
GUARDED = [
    ("get", "/"),
    ("get", "/analyze?output=x"),
    ("get", "/history"),
    ("get", "/history/deadbeef"),
    ("get", "/api/history"),
    ("get", "/api/health/all"),
    ("post", "/api/analyze"),
]


def _load_api(monkeypatch, tmp_path, token):
    """Import a fresh api module with the given token, since it is read at import."""
    if token is None:
        monkeypatch.delenv("ANALYSIS_API_TOKEN", raising=False)
    else:
        monkeypatch.setenv("ANALYSIS_API_TOKEN", token)
    monkeypatch.setenv("ANALYSIS_CACHE_DIR", str(tmp_path))
    if "api" in sys.modules:
        del sys.modules["api"]
    return importlib.import_module("api")


@pytest.fixture
def client(monkeypatch, tmp_path):
    api = _load_api(monkeypatch, tmp_path, TOKEN)
    return api.app.test_client()


@pytest.mark.parametrize(("method", "path"), GUARDED)
def test_rejects_missing_token(client, method, path):
    assert getattr(client, method)(path).status_code == 401


@pytest.mark.parametrize(("method", "path"), GUARDED)
def test_rejects_wrong_token(client, method, path):
    sep = "&" if "?" in path else "?"
    resp = getattr(client, method)(f"{path}{sep}token=wrong")
    assert resp.status_code == 401


def test_health_stays_open(client):
    """Docker healthcheck and 'make health' poll this without credentials."""
    assert client.get("/health").status_code == 200


def test_accepts_query_token(client):
    """Grafana data links open a browser tab and cannot set headers."""
    assert client.get(f"/?token={TOKEN}").status_code == 200


def test_accepts_bearer_header(client):
    resp = client.get("/", headers={"Authorization": f"Bearer {TOKEN}"})
    assert resp.status_code == 200


@pytest.mark.parametrize("placeholder", ["CHANGE_ME", "change_me", "CHANGE_ME_TO_SECURE_TOKEN"])
def test_refuses_public_placeholder_tokens(monkeypatch, tmp_path, placeholder):
    """A documented placeholder must never become a working credential."""
    with pytest.raises(RuntimeError, match="public placeholder"):
        _load_api(monkeypatch, tmp_path, placeholder)


def test_json_401_has_error_body(client):
    resp = client.post("/api/analyze", json={"alert": "x"})
    assert resp.get_json()["error"] == "Missing or invalid API token"


def test_token_propagates_to_page_links(client):
    """A 401 on every in-page link would make the UI unusable behind auth."""
    body = client.get(f"/?token={TOKEN}").get_data(as_text=True)
    assert f"/history?token={TOKEN}" in body


def test_no_token_configured_leaves_api_open(monkeypatch, tmp_path):
    """Backwards compatibility: existing installs keep working, with a warning."""
    api = _load_api(monkeypatch, tmp_path, None)
    client = api.app.test_client()
    assert client.get("/").status_code == 200
    assert api.token_qs() == ""
