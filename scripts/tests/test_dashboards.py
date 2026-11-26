"""Checks for the provisioned Grafana dashboards (no Grafana needed).

Every dashboard: valid JSON, a unique uid, and only its stack's datasource
(only the active stack's folder is provisioned, so a Loki panel in the
VictoriaLogs set would render broken). The Coding Agents (HIB) pair: the two
stacks at parity, every query filtered by the hostname variable, and tables
that work with the VictoriaLogs plugin's one-frame-per-series results.
"""

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DASH = REPO / "grafana/provisioning/dashboards"
STACKS = {"victorialogs": "victoriametrics-logs-datasource", "loki": "loki"}
VL_CA = DASH / "victorialogs/coding-agents-victorialogs.json"
LOKI_CA = DASH / "loki/coding-agents.json"


def load(path):
    return json.loads(path.read_text())


def dashboards():
    return sorted(p for folder in STACKS for p in (DASH / folder).glob("*.json"))


def datasources(node):
    """Every datasource type referenced anywhere in a dashboard."""
    if isinstance(node, dict):
        ds = node.get("datasource")
        if isinstance(ds, dict) and ds.get("type") and not str(ds.get("uid", "")).startswith("$"):
            yield ds["type"]
        for v in node.values():
            yield from datasources(v)
    elif isinstance(node, list):
        for v in node:
            yield from datasources(v)


def targets(d):
    return [(p, t) for p in d["panels"] for t in p.get("targets", [])]


@pytest.mark.parametrize("path", dashboards(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_dashboard_uses_only_its_stack(path):
    d = load(path)
    allowed = {STACKS[path.parent.name], "datasource", "__expr__", "prometheus", "victoriametrics-metrics-datasource"}
    if path.parent.name == "victorialogs":
        allowed.discard("loki")
    found = set(datasources(d))
    assert found <= allowed, f"{path.name}: {found - allowed}"
    assert STACKS[path.parent.name] in found or path.name.startswith("fleet-overview"), f"{path.name} has no logs panels"


def test_dashboard_uids_unique():
    uids = [load(p)["uid"] for p in dashboards()]
    assert len(uids) == len(set(uids)), uids


@pytest.mark.parametrize("path", [VL_CA, LOKI_CA], ids=["victorialogs", "loki"])
def test_coding_agents_conventions(path):
    d = load(path)
    assert "sib" in d["tags"] and "hib" in d["tags"]
    assert d["title"].startswith("Coding Agents (HIB")
    assert [v["name"] for v in d["templating"]["list"]] == ["hostname"]
    ids = [p["id"] for p in d["panels"]]
    assert len(ids) == len(set(ids))
    for p, t in targets(d):
        assert "$hostname" in t["expr"], f"{p['title']}: query ignores the hostname filter"
        if path is LOKI_CA:
            assert 'hostname=~"$hostname"' in t["expr"], p["title"]


def test_coding_agents_parity():
    vl, loki = load(VL_CA), load(LOKI_CA)
    shape = lambda d: [(p["title"], p["type"], p["gridPos"]) for p in d["panels"]]  # noqa: E731
    assert shape(vl) == shape(loki)
    # The same sources on both sides: HIB events and Falco's coding agent rules.
    for a, b in zip(vl["panels"], loki["panels"]):
        va = " ".join(t["expr"] for t in a["targets"])
        lb = " ".join(t["expr"] for t in b["targets"])
        assert ("source:hib" in va) == ('source="hib"' in lb), a["title"]
        assert ("source:syscall" in va) == ('source="syscall"' in lb), a["title"]


def test_coding_agents_vl_tables_take_per_series_frames():
    # victoriametrics-logs-datasource returns one frame per `stats by` series,
    # with the by-fields in labels: a table needs them as columns, then merged
    # into one frame, or it shows one series behind a frame selector (#66).
    for p in load(VL_CA)["panels"]:
        if p["type"] != "table":
            continue
        ids = [t["id"] for t in p.get("transformations", [])]
        assert ids[:2] == ["labelsToFields", "merge"], p["title"]
        assert p["transformations"][0]["options"] == {"mode": "columns", "valueLabel": "__name__"}


def test_coding_agents_query_types():
    vl, loki = load(VL_CA), load(LOKI_CA)
    want = {"stat": "stats", "table": "stats", "timeseries": "statsRange", "logs": "instant"}
    for p, t in targets(vl):
        assert t["queryType"] == want[p["type"]], p["title"]
        if p["type"] in ("stat", "table", "timeseries"):
            assert re.search(r"\|\s*stats\b", t["expr"]), p["title"]
    for p, t in targets(loki):
        if p["type"] == "table":
            assert t.get("format") == "table" and t.get("queryType") == "instant", p["title"]
            renamed = next(x for x in p["transformations"] if x["id"] == "organize")["options"]["renameByName"]
            assert f"Value #{t['refId']}" in renamed, f"{p['title']}: Loki names table values 'Value #<refId>'"
        if p["type"] in ("stat", "table"):
            assert "[$__range]" in t["expr"] or "[15m]" in t["expr"], p["title"]
        if p["type"] == "timeseries":
            assert "[$__interval]" in t["expr"], p["title"]
