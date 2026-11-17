#!/usr/bin/env python3
"""SIB end-to-end test helpers (stdlib only), driven by scripts/e2e/run.sh.

  e2e.py replay <dir> <host>          write recorded HIB events for a simulated host
  e2e.py session <port> <token file> <script dir> <workspace>
                                      run one scripted agent turn on a HIB daemon
  e2e.py check <stack> <e2e dir>      verify storage, then Grafana's alert states

Hosts:
  e2e-hib      a real HIB daemon (run.sh): heartbeats, auth failures, a scripted
               agent session, clean stops, a refused hash key
  e2e-replay   recorded events: protected.reverted, a denial burst,
               sandbox.unavailable, heartbeats that stopped 20 minutes ago
  e2e-stopped  recorded events: heartbeats then a clean daemon.stop, long enough
               ago that the liveness rule compares them
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

HOSTS = ["e2e-hib", "e2e-replay", "e2e-stopped"]

# Expected state per HIB rule and host: True = firing, False = silent.
# e2e-hib's sandbox row is filled in from its own daemon.start line.
EXPECT = {
    "sib-hib-critical":            {"e2e-hib": True,  "e2e-replay": True,  "e2e-stopped": False},
    "sib-hib-auth-failures":       {"e2e-hib": True,  "e2e-replay": False, "e2e-stopped": False},
    "sib-hib-denials":             {"e2e-hib": True,  "e2e-replay": True,  "e2e-stopped": False},
    "sib-hib-sandbox-unavailable": {"e2e-hib": None,  "e2e-replay": True,  "e2e-stopped": False},
    "sib-hib-not-running":         {"e2e-hib": False, "e2e-replay": True,  "e2e-stopped": False},
    "sib-hib-events-key-refused":  {"e2e-hib": True,  "e2e-replay": False, "e2e-stopped": False},
    "sib-hib-test-mode":           {"e2e-hib": True,  "e2e-replay": False, "e2e-stopped": False},
}
# For rules grouped by event: the events each must fire for, per host.
EXPECT_EVENTS = {
    ("sib-hib-critical", "e2e-hib"): {"protected.reverted", "home.changed"},
}
# Every rule must fire for at least one host: Grafana's VictoriaLogs plugin
# reports a failing query as "no data" with the rule healthy, so a rule that is
# only ever expected to stay silent could hide a broken query.
assert all(any(v) for v in EXPECT.values())

# Which events prove each rule's input reached storage, per host.
NEEDS = {
    "e2e-hib": ["daemon.start", "daemon.alive", "auth.failure", "daemon.stop", "events.key_refused",
                "session.start", "tool.permission", "sandbox.network", "protected.reverted", "home.changed"],
    "e2e-replay": ["daemon.alive", "protected.reverted", "tool.permission", "sandbox.unavailable"],
    "e2e-stopped": ["daemon.alive", "daemon.stop"],
}


def ts(minutes_ago):
    t = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def event(minutes_ago, name, severity, mode="daemon", **extra):
    # Same shape as HIB 0.1.0's lines (docs/hib-events-spec.md, schema 1).
    return {"ts": ts(minutes_ago), "schema": 1, "source": "hib", "host": "replay",
            "hib_version": "0.1.0", "event": name, "severity": severity, "mode": mode, **extra}


def replay_events(host):
    if host == "e2e-replay":
        evs = [event(41, "daemon.start", "info", bind="127.0.0.1", port=7777, sandbox="available")]
        evs += [event(m, "daemon.alive", "info", uptime_sec=(41 - m) * 60) for m in range(40, 19, -5)]
        # The rest is "now": the alert windows are 10-60 minutes.
        evs.append(event(0, "sandbox.unavailable", "warning", reason="bwrap not found"))
        evs.append(event(0, "protected.reverted", "critical", mode="workspace", session_id="s_e2e",
                         workspace="/home/e2e/app", account="claude@e2e",
                         changes=[{"path": ".git/hooks/pre-commit", "change": "added"}], failed=[]))
        # A second apart, like real ones: Loki keeps only one of several lines
        # that are identical down to the timestamp.
        evs += [event(i / 60, "tool.permission", "warning", mode="workspace", session_id="s_e2e",
                      tool="Bash", decision="deny", decided_by="policy", command="curl")
                for i in range(6, 0, -1)]
        return evs
    if host == "e2e-stopped":
        evs = [event(45, "daemon.start", "info", bind="127.0.0.1", port=7777, sandbox="available")]
        evs += [event(m, "daemon.alive", "info", uptime_sec=(45 - m) * 60) for m in range(40, 24, -5)]
        evs.append(event(22, "daemon.stop", "info", signal="SIGTERM"))
        return evs
    raise SystemExit(f"no replay for {host}")


def cmd_replay(directory, host):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, "events.jsonl")
    with open(path, "a") as f:
        for e in replay_events(host):
            f.write(json.dumps(e, separators=(",", ":")) + "\n")
    os.chmod(path, 0o600)


# --- a scripted agent turn on a real HIB daemon --------------------------------

# Steps for HIB's scripted test agent (HIB 0.2.0+, [testing] script_dir). Every
# command and the network request are denied: six denials make the burst alert
# fire. The two writes go past HIB's permission prompt, like a swapped symlink.
SCRIPT = [
    {"say": "SIB end-to-end test"},
    {"edit": "notes.md", "content": "e2e\n"},
    *[{"command": f"cat data-{i}.csv"} for i in range(6)],
    {"network": "exfil.example.com"},
    {"fetch": "https://example.com/e2e"},
    {"write": ".git/hooks/pre-commit", "content": "#!/bin/sh\necho e2e\n"},
    {"write": "~/.bashrc", "content": "# e2e\n"},
]


def cmd_session(port, token_file, script_dir, root):
    token = open(token_file).read().strip()
    base = f"http://127.0.0.1:{port}"

    def call(path, body=None, timeout=15):
        req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode())
        req.add_header("Authorization", f"Bearer {token}")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        return urllib.request.urlopen(req, timeout=timeout)

    with open(os.path.join(script_dir, "e2e.json"), "w") as f:
        json.dump(SCRIPT, f)
    root = json.load(call("/hib/workspaces", {"root": root}))["root"]
    q = "?root=" + urllib.parse.quote(root)
    started = json.load(call("/ws/turn" + q, {"model": "script/replay", "text": "hib-script:e2e"}))
    if "sessionId" not in started:
        raise SystemExit(f"HIB refused the turn: {started}")
    sid = started["sessionId"]
    answered = {}
    with call(f"/ws/sessions/{sid}/stream" + q, timeout=60) as stream:
        for raw in stream:
            line = raw.decode().rstrip("\n")
            if not line.startswith("data: "):
                continue
            e = json.loads(line[6:])
            if e.get("type") == "error":
                raise SystemExit(f"scripted turn failed: {e.get('message')}")
            if e.get("type") == "permission":
                name = e["call"]["name"]
                choice = "deny" if name in ("Bash", "SandboxNetworkAccess") else "allow"
                call("/ws/permission" + q, {"sessionId": sid, "id": e["id"], "choice": choice}).read()
                answered[name] = answered.get(name, 0) + 1
            if e.get("type") == "turn_end":
                break
    want = {"Write": 1, "Bash": 6, "SandboxNetworkAccess": 1, "WebFetch": 1}
    if answered != want:
        raise SystemExit(f"scripted turn asked {answered}, expected {want}")
    print(f"  scripted session {sid}: {sum(answered.values())} prompts answered")


# --- checks ------------------------------------------------------------------

def http_json(url, data=None, auth=None):
    req = urllib.request.Request(url, data=data)
    if auth:
        import base64
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read() or b"null")


def stored_count(stack, port, host, ev):
    if stack == "vm":
        q = f'_time:24h source:hib hostname:"{host}" event:"{ev}" | stats count() as n'
        url = f"http://127.0.0.1:{port}/select/logsql/query"
        body = urllib.request.urlopen(url, urllib.parse.urlencode({"query": q}).encode(), timeout=15).read()
        rows = [json.loads(line) for line in body.splitlines() if line.strip()]
        return int(rows[0]["n"]) if rows else 0
    q = f'sum(count_over_time({{source="hib", hostname="{host}", event="{ev}"}}[24h]))'
    r = http_json(f"http://127.0.0.1:{port}/loki/api/v1/query?" + urllib.parse.urlencode({"query": q}))
    res = r["data"]["result"]
    return int(float(res[0]["value"][1])) if res else 0


def file_events(d, host):
    path = os.path.join(d, "hosts", host, "events.jsonl")
    if not os.path.exists(path):
        return []
    return [json.loads(line) for line in open(path) if line.strip()]


def rfc3339(s):
    # Grafana: 2026-11-16T20:31:00.123456789Z or with an offset
    import re
    s = re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00"))  # fromisoformat takes microseconds
    return datetime.fromisoformat(s).timestamp()


def cmd_check(stack, d):
    logs_port = os.environ["E2E_LOGS_PORT"]
    gport = os.environ["E2E_GRAFANA_PORT"]
    auth = "admin:" + os.environ["E2E_GRAFANA_PASSWORD"]
    hib_real = os.environ.get("E2E_HIB", "1") == "1"
    failures = []

    # Layer 1: the events are in the files.
    print("== 1. events written")
    hosts = HOSTS if hib_real else HOSTS[1:]
    for host in hosts:
        names = {e["event"] for e in file_events(d, host)}
        missing = [n for n in NEEDS[host] if n not in names]
        print(f"  {host:12} {len(file_events(d, host)):3} lines" + (f"  MISSING {missing}" if missing else ""))
        if missing:
            failures.append(f"{host}: not written: {missing}")
    if hib_real:
        starts = [e for e in file_events(d, "e2e-hib") if e["event"] == "daemon.start"]
        if not any(e.get("script_driver") is True for e in starts):
            failures.append("e2e-hib: no daemon.start with script_driver true (HIB older than 0.2.0?)")
        home = [e for e in file_events(d, "e2e-hib") if e["event"] == "home.changed"]
        if home and not any(c.get("path") == "~/.bashrc" for e in home for c in e.get("changes", [])):
            failures.append(f"e2e-hib: home.changed doesn't name ~/.bashrc: {home}")
    if failures:
        return finish(failures)

    expect = {k: dict(v) for k, v in EXPECT.items()}
    if hib_real:
        start = [e for e in file_events(d, "e2e-hib") if e["event"] == "daemon.start"][0]
        expect["sib-hib-sandbox-unavailable"]["e2e-hib"] = start.get("sandbox") == "unavailable"
    else:
        for v in expect.values():
            v.pop("e2e-hib")

    # Layer 2: the collectors shipped them to storage under the right hostname.
    print("== 2. events in storage")
    deadline = time.time() + 120
    pending = {(h, ev) for h in hosts for ev in NEEDS[h]}
    while pending and time.time() < deadline:
        for h, ev in sorted(pending):
            try:
                if stored_count(stack, logs_port, h, ev) > 0:
                    pending.discard((h, ev))
            except Exception:
                pass
        if pending:
            time.sleep(3)
    for h in hosts:
        miss = sorted(ev for hh, ev in pending if hh == h)
        print(f"  {h:12} " + ("all events stored" if not miss else f"MISSING {miss}"))
    if pending:
        return finish([f"not in storage: {sorted(pending)}"])
    data_at = time.time()

    # Layer 3: Grafana evaluated each HIB rule after the data landed.
    print("== 3. Grafana alert states")
    titles = rule_titles(stack)
    deadline = time.time() + 240
    rules = {}
    while time.time() < deadline:
        rules = grafana_rules(gport, auth, titles)
        ready = [u for u in expect if u in rules and rules[u]["health"] == "ok"
                 and rules[u]["evaluated"] > data_at + 1]
        if len(ready) == len(expect):
            break
        time.sleep(5)
    for uid, per_host in expect.items():
        r = rules.get(uid)
        if r is None:
            failures.append(f"{uid}: rule not found in Grafana")
            print(f"  {uid:30} NOT FOUND")
            continue
        if r["health"] != "ok":
            failures.append(f"{uid}: health={r['health']} {r['error']}")
            print(f"  {uid:30} UNHEALTHY {r['health']}: {r['error']}")
            continue
        if r["evaluated"] <= data_at + 1:
            failures.append(f"{uid}: not evaluated since the data arrived")
            print(f"  {uid:30} NOT EVALUATED since the data arrived")
            continue
        for host, want in per_host.items():
            got = host in r["firing"]
            src = "real HIB" if host == "e2e-hib" else "recorded"
            ok = got == want
            want_events = EXPECT_EVENTS.get((uid, host))
            if ok and got and want_events:
                fired = r["events"].get(host, set())
                if not want_events <= fired:
                    ok = False
                    failures.append(f"{uid} on {host}: fires for {sorted(fired)}, expected {sorted(want_events)}")
            print(f"  {'PASS' if ok else 'FAIL'} {uid:30} {host:12} {'fires' if got else 'silent':6}"
                  f" (expected {'fires' if want else 'silent'}; {src} events"
                  + (f": {', '.join(sorted(want_events))}" if want_events else "") + ")")
            if got != want:
                why = " (the query returned no data: broken query, or nothing matched)" if r["nodata"] else ""
                failures.append(f"{uid} on {host}: {'fires' if got else 'silent'}, expected the opposite{why}")
    return finish(failures)


def rule_titles(stack):
    """uid -> title, from the generated provisioning (the rules API reports titles)."""
    import re
    path = os.path.join(os.environ["E2E_DIR"], "grafana", "alerting", "alert-rules.yml")
    text = open(path).read()
    return dict(re.findall(r"- uid: (sib-hib-[\w-]+)\n\s+title: (.+)", text))


def grafana_rules(port, auth, titles):
    by_title = {t.strip(): u for u, t in titles.items()}
    out = {}
    try:
        r = http_json(f"http://127.0.0.1:{port}/api/prometheus/grafana/api/v1/rules", auth=auth)
    except Exception:
        return out
    for g in r["data"]["groups"]:
        for rule in g["rules"]:
            uid = by_title.get(rule["name"])
            if not uid:
                continue
            alerts = rule.get("alerts") or []
            live = [a for a in alerts if a.get("state", "").lower() in ("alerting", "firing")]
            firing = {a["labels"].get("hostname") for a in live}
            events = {}
            for a in live:
                if "event" in a["labels"]:
                    events.setdefault(a["labels"].get("hostname"), set()).add(a["labels"]["event"])
            nodata = any("nodata" in a.get("state", "").lower().replace(" ", "") for a in alerts)
            last = rule.get("lastEvaluation") or "1970-01-01T00:00:00Z"
            out[uid] = {"health": rule.get("health"), "error": rule.get("lastError", ""),
                        "evaluated": 0 if last.startswith("0001") else rfc3339(last), "firing": firing,
                        "events": events,
                        "nodata": nodata}
    return out


def finish(failures):
    if failures:
        print("FAIL")
        for f in failures:
            print("  - " + f)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "replay":
        cmd_replay(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 6 and sys.argv[1] == "session":
        cmd_session(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == "check":
        sys.exit(cmd_check(sys.argv[2], sys.argv[3]))
    else:
        sys.exit(__doc__)
