---
layout: default
title: HIB Security Event Log - SIEM in a Box
---

# HIB security event log (contract between HIB and SIB)

[HIB](https://github.com/matijazezelj/hib) writes security-relevant events as JSON
lines; SIB's collectors ship them to VictoriaLogs/Loki and Grafana alerts on them.
This page is the contract both sides implement against. Schema version: **1**.

## File

- Directory: `[events] dir` in `config.toml`, default `$HIB_HOME/events/`
  (`~/.hib/events/`). Only event files live there, so a log collector can mount
  this directory alone, never the token, vault key or database next to it.
- Current file: `events.jsonl`. Rotation by size (`[events] max_mb`, default
  20): rename to `events.jsonl.1` (shift older up to `[events] keep`, default
  5) and start a new file. Append-only, one JSON object per line, `\n`
  terminated, flushed per event.
- `[events] enabled` (default `true`). Directory mode 0700, files 0600 (the
  collector reads as root inside its container).

## Common fields (every event)

| Field | Type | Notes |
|-------|------|-------|
| `ts` | string | RFC 3339 UTC with milliseconds, e.g. `2026-11-13T10:15:02.123Z` |
| `schema` | int | `1` |
| `source` | string | always `"hib"` |
| `host` | string | machine hostname |
| `hib_version` | string | |
| `event` | string | one of the types below |
| `severity` | string | `info`, `warning` or `critical` (fixed per event type, see below) |
| `mode` | string | `router`, `workspace` or `daemon` |
| `session_id` | string? | workspace/agent session, when there is one |
| `run_id` | string? | router/engine run, when there is one |
| `workspace` | string? | workspace root path (absolute) |
| `account` | string? | `<provider>@<account>` |
| `model` | string? | |
| `route` | string? | |

Optional fields are omitted, not `null`.

## Never in the log

No prompt text, model output, tool output, file contents, diffs, tokens,
vault values or placeholders' originals. Any field below that can carry
user-controlled text (`command`, `url`, `reasons`) is passed through HIB's
redactor at `minimal` level or stricter before logging and truncated to 300
characters (`…` appended). Paths inside a workspace are logged relative to
`workspace`.

## Event types

| `event` | `severity` | When | Extra fields |
|---------|-----------|------|--------------|
| `daemon.start` | info | daemon listening | `bind`, `port`, `sandbox` (`available` / `unavailable`) |
| `daemon.stop` | info | clean shutdown | |
| `auth.failure` | warning | request rejected: bad/missing token, Host or Origin mismatch | `reason` (`token`, `host`, `origin`), `path`, `remote` (peer address). At most one line per `reason`+`remote` per 60 s, with `count` |
| `guard.decision` | info, or warning when `action` is `rejected`/`timeout` | every guard decision | `action` (`redacted`, `approved`, `rejected`, `timeout`), `decided_by` (`policy`, `user`), `findings` (object: category → count), `reasons` (string array) |
| `approval.pending` | info | a request waits for human approval | `kind` (`guard`, `tool`, `network`), `timeout_sec` |
| `tool.permission` | info, or warning on `deny` | a tool call is allowed or denied | `tool`, `decision` (`allow`, `always`, `deny`), `decided_by` (`user`, `policy`, `auto`), `command`? , `path`?, `url`?/`net_host`? |
| `data.block` | warning | sensitive-workspace policy blocks a raw data read | `command`?, `path`?, `reason` |
| `sandbox.network` | info, or warning on `deny` | a sandboxed command asks to reach a new host | `net_host`, `decision` (`allow`, `deny`) |
| `sandbox.unavailable` | warning | sandbox probe failed, auto mode disabled | `reason` |
| `protected.reverted` | critical | unapproved changes to git hooks/config or agent config were put back | `changes` (array of `{path, change}`), `failed` (paths that could not be reverted) |
| `terminal.open` | warning | browser terminal session started | `workspace` |
| `session.start` / `session.end` | info | agent session starts/ends | `agent` (`claude`, `codex`), `sensitive` (bool) |

Unknown event types must be tolerated by consumers; new optional fields can be
added without bumping `schema`.

## Example

```json
{"ts":"2026-11-13T10:15:02.123Z","schema":1,"source":"hib","host":"devbox","hib_version":"0.4.0","event":"protected.reverted","severity":"critical","mode":"workspace","session_id":"s_7f3a","workspace":"/home/m/code/app","account":"claude@personal","changes":[{"path":".git/hooks/pre-commit","change":"added"}],"failed":[]}
```

## SIB side

See [HIB integration](hib-integration.md) for collecting this log and the
alerts built on it.
