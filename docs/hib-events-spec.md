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
- `[events] enabled` (default `true`); `[events] heartbeat_sec` (default 300) for `daemon.alive`. Directory mode 0700, files 0600 (the
  collector reads as root inside its container).

## Common fields (every event)

| Field | Type | Notes |
|-------|------|-------|
| `ts` | string | RFC 3339 UTC with milliseconds, e.g. `2026-11-13T10:15:02.123Z` |
| `schema` | int | `1` |
| `source` | string | always `"hib"` |
| `host` | string | machine hostname |
| `hib_version` | string | the `version` in hib's package.json (`0.1.0` since hib PR #10); `0.0.0+<git sha>` only if package.json has none |
| `event` | string | one of the types below |
| `severity` | string | `info`, `warning` or `critical` (fixed per event type, see below) |
| `mode` | string | `router`, `workspace` or `daemon` |
| `session_id` | string? | workspace/agent session, when there is one |
| `run_id` | string? | router/engine run, when there is one |
| `workspace` | string? | workspace root path (absolute); with `[events] workspace = "name"` only its last folder, with `"hash"` a 16-hex keyed hash (stable per machine). See [Coarsening](#coarsening) |
| `account` | string? | `<provider>@<account>`; with `[events] account = "hash"` the account part is a 16-hex keyed hash (`claude@<16 hex>`) |
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

## Coarsening

HIB can log less detail. `[events] profile` picks the defaults:

- `"local"` (default): every field is logged whole.
- `"siem"`: `workspace = "hash"`, `account = "hash"`, `net_host = "domain"`,
  `command = "program"`, `remote = false`.

A setting given on its own overrides the profile.

| Setting | Values | Effect |
|---------|--------|--------|
| `workspace` | `path` (default), `name`, `hash` | `name`: last folder only; `hash`: 16 hex chars |
| `account` | `name` (default), `hash` | `<provider>@<16 hex>` |
| `net_host` | `full` (default), `domain` | see below; `url` is cut to `scheme://<net_host value>` |
| `command` | `full` (default), `program` | a best-effort program label, e.g. `curl`; `[COMMAND]` when it can't be told safely (unbalanced quotes, `$(…)` or backticks before the program, a leading redirection) |
| `remote` | `true` (default), `false` | `false` leaves `remote` out of `auth.failure` |

With `net_host = "domain"`, `net_host` is one of:

- the registrable domain under an ICANN public suffix
  (`acme-payroll.s3.amazonaws.com` → `amazonaws.com`, `you.github.io` →
  `github.io`); internationalised names as punycode;
- `localhost`;
- `[IP-INTERNAL]`: private and other non-public ranges, including
  `169.254.0.0/16` (cloud metadata), `100.64.0.0/10`, `0.0.0.0/8`, IPv6 ULA,
  link-local and multicast;
- `[IP-EXTERNAL]`: any other IP address;
- `[INTERNAL]`: a name under no ICANN suffix (`.corp`, `.local`, `.internal`,
  `.arpa`, single labels);
- `[HOST]`: the host could not be parsed; `url` is `[URL]` when it has no
  parseable host.

A redaction placeholder in the host keeps only its category (e.g.
`[IP-INTERNAL]`), so `net_host` and `url` of one request agree.

The program label is not an executable's identity: for what actually ran,
Falco (or auditd) is authoritative.

Hashes are an HMAC-SHA256 keyed by `~/.hib/events.key`, outside the events
directory. HIB uses the key only if it is a regular file (not a symlink) owned
by the user, with no group or other permission bits, holding exactly 64
lowercase hex characters (plus an optional newline). Otherwise every event
that carries `workspace` or `account` is dropped, never written with the field
whole, and HIB writes one `events.key_refused` per daemon run. When a setting
is `"hash"`, HIB loads the key (or creates it if missing) at daemon start, so a
bad key shows up right after `daemon.start`.

## Event types

| `event` | `severity` | When | Extra fields |
|---------|-----------|------|--------------|
| `daemon.start` | info | daemon listening | `bind`, `port`, `sandbox` (`available` / `unavailable`), `script_driver` (`true` only when `[testing] script_dir` turns on the scripted test agent; HIB 0.2.0+) |
| `daemon.stop` | info | clean shutdown (`/hib/shutdown`, SIGTERM/SIGINT); pending `auth.failure` counts are written first | `signal`? |
| `daemon.alive` | info | heartbeat every `[events] heartbeat_sec` (default 300, `0` = off) while the daemon runs | `uptime_sec` |
| `auth.failure` | warning | request rejected: bad/missing token, Host or Origin mismatch | `reason` (`token`, `host`, `origin`), `path`, `remote` (peer address). At most one line per `reason`+`remote` per 60 s, with `count` |
| `guard.decision` | info, or warning when `action` is `rejected`/`timeout` | every guard decision | `action` (`redacted`, `approved`, `rejected`, `timeout`), `decided_by` (`policy`, `user`), `findings` (object: category → count), `reasons` (string array) |
| `approval.pending` | info | a request waits for human approval | `kind` (`guard`, `tool`, `network`), `timeout_sec` |
| `tool.permission` | info, or warning on `deny` | a tool call is allowed or denied | `tool`, `decision` (`allow`, `always`, `deny`), `decided_by` (`user`, `policy`, `auto`), `command`? , `path`?, `url`?/`net_host`? |
| `data.block` | warning | sensitive-workspace policy blocks a raw data read | `command`?, `path`?, `reason`: the full (redacted) sentence, which may name the file or script; with `command = "program"` one of `it reads a data file directly`, `it runs inline code that could read data files`, `it runs a script from outside this folder` |
| `sandbox.network` | info, or warning on `deny` | a sandboxed command asks to reach a new host | `net_host`, `decision` (`allow`, `deny`) |
| `sandbox.unavailable` | warning | sandbox probe failed, auto mode disabled | `reason` |
| `events.key_refused` | warning | the hash key (`[events]` setting `"hash"`) is unusable; at most once per daemon run, mode `daemon`, no `workspace`/`account`. Events carrying those fields are dropped until the key is fixed and the daemon restarted | `reason` (`symlink`, `not_regular`, `not_owner`, `mode`, `format`, `unreadable`); never the path |
| `protected.reverted` | critical | unapproved changes to git hooks/config or agent config were put back | `changes` (array of `{path, change}`), `failed` (paths that could not be reverted) |
| `home.changed` | critical, or warning when every change was an edit the user approved | an agent turn changed files outside the workspace that steer later sessions: shell startup files, Claude/Codex settings, instructions, hooks, agents, commands and skills, `~/.gitconfig`, ssh config, `authorized_keys`/`rc`, autostart entries, systemd user units (HIB 0.2.0+). Reported, never put back | `changes` (array of `{path, change, approved}`; `change` is `added`, `changed` or `removed`; `path` is `~/…` or `[CLI home]/…` for a Claude/Codex config folder, `(link target)` appended when a symlink's target changed) |
| `terminal.open` | warning | browser terminal session started | `workspace` |
| `session.start` / `session.end` | info | agent session starts/ends | `agent` (`claude`, `codex`), `sensitive` (bool) |

HIB 0.2.0 is the first version with `home.changed` and `script_driver`;
the `hib_version` field says which version wrote a line.

Unknown event types must be tolerated by consumers; new optional fields can be
added without bumping `schema`.

## Example

```json
{"ts":"2026-11-13T10:15:02.123Z","schema":1,"source":"hib","host":"devbox","hib_version":"0.4.0","event":"protected.reverted","severity":"critical","mode":"workspace","session_id":"s_7f3a","workspace":"/home/m/code/app","account":"claude@personal","changes":[{"path":".git/hooks/pre-commit","change":"added"}],"failed":[]}
```

## SIB side

See [HIB integration](hib-integration.md) for collecting this log and the
alerts built on it.
