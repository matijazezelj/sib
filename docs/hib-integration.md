---
layout: default
title: HIB Integration - SIEM in a Box
---

# HIB Integration

[HIB](https://github.com/matijazezelj/hib) runs coding agents (Claude Code,
Codex) behind a redaction guard and a sandbox. Agents with shell access are
exactly the kind of workload SIB should watch, from two sides:

- **Falco** sees what the agents' processes do at the syscall level, including
  anything that slips past HIB's own controls.
- **HIB's security event log** tells SIB what HIB decided: denied tool calls,
  blocked data reads, rejected guard decisions, reverted hook changes, API
  authentication failures.

Both are opt-in, per host.

## 1. Falco rules for coding agents

`detection/config/rules/coding_agent_rules.yaml` is an opt-in rule pack (like
the cloud and web server packs). It keys on the `claude` and `codex` CLIs and
everything they start:

| Rule | Priority | Fires when |
|------|----------|------------|
| Coding Agent Read Credential Store | WARNING | an agent or its child reads `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.kube`, `.netrc`, `.git-credentials`, `~/.docker/config.json` or `.pgpass` with something other than that store's own tool (ssh/git for `~/.ssh`, `gh`, git's credential helpers, gpg, docker, kubectl/helm, `aws`, psql are expected; `cat`, a script or the agent CLI are not) |
| Coding Agent Subprocess Read Agent Credentials | CRITICAL | a child of an agent (not the CLI itself) reads `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.hib/token` or `~/.hib/vault.key` |
| Coding Agent Write Shell or Login Persistence | CRITICAL | an agent or its child writes a shell startup file (bash, zsh, fish, `/etc/profile.d`, …), `authorized_keys`, a crontab, or a systemd/autostart unit, or moves or links a file there |
| Coding Agent Write Repository or Agent Hook | WARNING | an agent (the CLI itself included) or its child writes or moves/links a file into `.git/hooks/` (not git's inert `*.sample` templates); a child of an agent writes `.mcp.json`, `.claude/settings*` or `.codex/config.toml` |
| HIB Secrets Read by Unexpected Process | WARNING | anything other than the HIB daemon (`bun`) reads HIB's token or vault key |

The agents' own CLIs legitimately read their credentials and write their
settings, so those rules only flag the agents' *children*; a git hook is
flagged whoever writes it. HIB's sandbox denies these paths to agents, so a
hit usually means an unsandboxed agent or a sandbox bypass.

Agents are recognised by process name and executable path (`claude`, `codex`;
Claude Code does part of its file I/O on threads named `Bun Pool N`, which the
path catches). Not covered: Claude Code installed through npm and running
under `node`, and anything that detaches from the agent (`setsid`, `nohup`,
reparented to init) or runs more than 8 levels below it.

**What Falco can't see:** Claude Code's own Write and Edit tools don't write
to a file by its path. They open the directory, then create and rename the
file through `/proc/self/fd/<n>/<name>`, which Falco reports as is. So these
rules see where the agent's *children* write (a shell, `sed -i`, `mv`, `ln`,
`git`) but not where the CLI itself writes: a hook or `~/.bashrc` written by
the Write tool doesn't alert. (Its reads use real paths and are covered.) When
the agent runs under HIB, HIB covers what the CLI writes after each agent turn:

- `protected.reverted`: the workspace's git hooks and git config, its
  `.claude/`, `.codex/` and `.hib/` folders and `.mcp.json`. Unapproved
  changes are put back.
- `home.changed` (HIB 0.2.0+): shell startup files, Claude and Codex settings,
  instructions, hooks, agents, commands and skills in `~/.claude`, `~/.codex`
  and each account's config folder, `~/.gitconfig`, ssh config,
  `authorized_keys` and `rc`, autostart entries and systemd user units. These
  are reported, never put back.

Both compare snapshots around a turn, so a file changed and restored within
one turn goes unseen, and an agent outside HIB isn't covered at all.

The exemptions for a store's own tool match on the process name, so a binary
renamed to `gh` would be exempt too.

Enable it:

- **SIB server:** add `- /etc/falco/rules/coding_agent_rules.yaml` to
  `rules_files` in `detection/config/falco.yaml.template` (it is listed there,
  commented out), then `make install-detection`.
- **Fleet host:** add it to that host's `falco_custom_rules`, e.g. in the
  inventory:

  ```yaml
  devbox:
    ansible_host: 192.168.1.20
    falco_custom_rules: [custom_rules.yaml, coding_agent_rules.yaml]
  ```

  then `make deploy-fleet LIMIT=devbox` (or `make update-rules LIMIT=devbox`).

Events land in the Events Explorer like any other Falco detection, and the
standard *Burst of Critical/Error events* alert covers them.

### Testing the rules on a host

`scripts/test-coding-agent-rules.sh` runs Falco privileged with the modern
eBPF probe for a minute and plays 13 cases that must alert and 9 that must
not, with stand-in processes named `claude`, `codex`, `bun` and `gh` against a
throwaway fake home (never real credentials). The positive cases include
files moved, hard-linked and symlinked into place; the negative cases include `ssh` reading `~/.ssh`, `gh` reading its own
config, git's credential helper reading `.git-credentials`, an agent CLI reading its own credentials or writing its settings, HIB's
daemon reading its vault key, and `git init` writing its sample hooks. A case
whose command fails (a missing tool) fails too, so a negative case can't pass
without having run. Run it from a normal shell,
not from inside Claude Code or Codex: the rules key on agent ancestry, so
everything started from an agent's own terminal counts as agent activity.

```bash
./scripts/test-coding-agent-rules.sh                        # FALCO_VERSION from the environment, default 0.45.2
FALCO_VERSION=0.44.1 ./scripts/test-coding-agent-rules.sh   # another Falco release
```

It ends with `PASS`/`FAIL` per case and lists any other coding-agent alerts the
host raised meanwhile (real activity), which is a quick false-positive check.

All 22 cases pass with Falco 0.45.2, which SIB runs. (On Linux 7.2 aarch64,
Falco 0.44.1's modern eBPF probe doesn't load at all: the kernel's verifier
rejects its `signal_deliver` program. That's why SIB moved to 0.45.2.)

## 2. HIB's security event log

HIB writes JSON lines to `~/.hib/events/` (format:
[HIB security event log](hib-events-spec.md)). Use HIB 0.2.0 or later: older
versions don't write `home.changed`, so shell startup files and the user's agent
config changed by the CLI go unreported. On a fleet host that runs HIB,
point the collector at that directory:

```yaml
devbox:
  ansible_host: 192.168.1.20
  hib_events_dir: /home/alice/.hib/events
```

then `make deploy-fleet LIMIT=devbox`. The directory must already exist:
start HIB once on the host first (otherwise the deploy stops, rather than let
Docker create it as root and lock HIB out).

What the collector can read:

- **Vector:** only that directory is mounted, never `~/.hib` itself (which
  holds HIB's token and vault key).
- **Alloy:** it already reads the whole host filesystem read-only (Docker
  mounts `/` at `/host`; native Alloy runs as root) for its other logs and
  metrics, so it could read `~/.hib/token` and `vault.key` too. On a host where
  that matters, use the VM stack, or keep Alloy's access in mind when deciding
  who may change its config.

- **VM stack (Vector):** the directory is mounted read-only into the Vector
  container; events go to VictoriaLogs with stream fields `hostname`,
  `source=hib`, and every event field searchable
  (`source:hib event:tool.permission decision:deny`).
- **Grafana stack (Alloy):** Alloy reads it through its host mount; events go
  to Loki with labels `source="hib"`, `hostname`, `event`, `severity`, the rest
  in the JSON line (`{source="hib"} | json`).

The `hostname` is the inventory name, the same as for the host's other logs
and metrics; HIB's own `host` field is kept as `hib_host`.

Both collectors store an event at its own `ts`. Loki silently drops lines more
than about an hour older than the stream's newest line, so when Alloy first
starts on a host where HIB has been running for a while, the older history in
`events.jsonl` doesn't reach Loki (VictoriaLogs keeps it).

## Alerts

`make install-grafana` provisions a **HIB** group in the SIB alert folder
(see [Grafana Alerts](grafana-alerts.md)):

| Rule | Fires when | Severity |
|------|------------|----------|
| HIB critical security event | any `critical` HIB event in 10 minutes: `protected.reverted` (an agent changed the workspace's git hooks or agent config without approval; put back) or `home.changed` (an agent turn changed a shell startup file or the user's agent config without approval; reported only) | critical |
| HIB authentication failures | more than 5 failed requests in 15 minutes (sum of the events' `count`; HIB aggregates repeats within 60 s into one line) | warning |
| HIB agent denials burst | more than 5 denied tool calls or blocked data reads in 15 minutes (a denied network request is a denied tool call too; `sandbox.network` isn't counted again) | warning |
| HIB sandbox unavailable | `sandbox.unavailable` in the last hour | warning |
| HIB event hash key refused | `events.key_refused` in the last 24 hours: HIB drops session, tool, guard and data events until the key is fixed and HIB restarted (it reports this once per run, hence the long window) | warning |
| HIB running in test mode | `daemon.start` with `script_driver: true` in the last 24 hours: HIB was started with `[testing] script_dir`, its scripted agent for acceptance tests. Silence it for test hosts | warning |
| HIB daemon not running | HIB's last heartbeat (`daemon.alive`, every 5 min) or `daemon.start` in the last 24 hours is more than 15 minutes old, and no clean `daemon.stop` came after it: a crash, a kill, or events no longer reaching SIB | warning |

They stay quiet on hosts without HIB. `guard.decision` is written for every
prompt; only its `warning` lines (`rejected`, `timeout`) are worth a look, e.g.
`source:hib event:guard.decision severity:warning` in the Events Explorer.

*HIB daemon not running* needs a HIB version that writes `daemon.alive`
heartbeats. Only a stop that is HIB's last word silences it: after a clean stop
and a restart, a later crash fires as usual. A host that last ran HIB more than
24 hours ago is forgotten.

## End-to-end test

`make e2e` checks the whole chain, from HIB's event log through the collector
and storage to Grafana's alert rules:

```bash
make e2e                 # Vector -> VictoriaLogs
make e2e STACK=grafana   # Alloy -> Loki
```

It runs an isolated Docker project (`sib-e2e`: own network, volumes and
ports), built from SIB's real compose services, generated alert rules and
datasources, and the collector configs rendered from the Ansible templates. A
running SIB install isn't touched and `.env` isn't read, so no test alert can
reach a real Slack or Telegram. It simulates three hosts:

- **`e2e-hib`:** a real HIB daemon (`HIB_DIR`, default `../hib`; HIB 0.2.0 or
  later and bun) with 5-second heartbeats, requests with a wrong token, clean
  stops and a refused `events.key`. One run uses the `siem` profile and HIB's
  scripted test agent: an agent turn whose six commands and one network request
  are denied, which adds a git hook (put back) and changes `~/.bashrc` in a
  throwaway home folder. These are real `session.*`, `tool.permission`,
  `sandbox.network`, `protected.reverted` and `home.changed` events; no agent
  CLI runs and no command is executed.
- **`e2e-replay`:** recorded HIB events, so the session alerts are also checked
  without HIB: `protected.reverted`, a burst of denials, `sandbox.unavailable`,
  and heartbeats that stopped 20 minutes ago.
- **`e2e-stopped`:** heartbeats followed by a clean `daemon.stop`.

It then checks, in order: the events were written; they reached storage under
the right `hostname`; and every HIB alert rule is healthy, has evaluated since
the data arrived, and fires for exactly the expected hosts (21 checks per
stack); the critical-event alert must fire for both `protected.reverted` and
`home.changed`. `KEEP=1 make e2e` leaves the stack up for a look (Grafana's address and
password are printed); remove it with `docker compose -p sib-e2e down -v`.

Not covered yet: Falco through Falcosidekick into storage (the Falco rules have
their own test, `scripts/test-coding-agent-rules.sh`), `data.block` (it needs a
sensitive workspace), and events from a real agent CLI.

## Privacy of the event log

HIB keeps payloads out of the log: no prompts, model output, file contents or
secrets, and the free-text fields (`command`, `url`, `reasons`) are redacted
before they are written. The metadata still says a lot: absolute workspace
paths (often a customer or project name), session and account names, when
agents work and for how long, which tools they use and which files or hosts
they touch. Treat the HIB stream in VictoriaLogs/Loki like the rest of SIB's
security data: restrict who can query it and keep the retention short for
sensitive workloads.

HIB can coarsen that metadata before it leaves the machine. For a host that
ships its log to SIB, the `siem` profile in HIB's `config.toml` is the short
way (default `local`, which logs every field whole):

```toml
[events]
profile = "siem"      # workspace and account hashed, net_host cut to the domain,
                      # command cut to the program, remote left out
# Each setting can still be set on its own and overrides the profile, e.g.:
# workspace = "name"  # last folder instead of a hash
```

Hashes are a keyed HMAC, the same for the same value on one machine, so
grouping and correlation still work. With `net_host = "domain"`, internal
addresses show up as `[IP-INTERNAL]` (including cloud metadata,
`169.254.169.254`) and private names as `[INTERNAL]`; details in the
[event log spec](hib-events-spec.md#coarsening). None of SIB's alerts depend on
these fields, so any combination is safe to turn on.

HIB drops an event rather than log a field whole when its hash key
(`~/.hib/events.key`) is unusable: wrong owner or permissions, a symlink, or
bad content. Only events that carry `workspace` or `account` are dropped
(`session.*`, `tool.*`, `guard.decision`, `data.block`); heartbeats and
`auth.failure` keep arriving, so *HIB daemon not running* doesn't notice. HIB
reports it with one `events.key_refused` event per daemon run (its `reason`
says what is wrong), which raises *HIB event hash key refused*. Fix the key
(`chmod 600`, owned by the user, a regular file of 64 hex characters), then
restart HIB.

## What to look at when one fires

- **protected.reverted:** the event's `changes` list shows what the agent tried
  to change. A new git hook or `.mcp.json` entry is a persistence attempt;
  check the session that produced it in HIB.
- **home.changed:** `changes` lists each file (`~/.bashrc`,
  `[CLI home]/settings.json`, …) with `added`, `changed` or `removed` and
  whether you approved that edit. HIB didn't undo it: look at the file now. A
  change you made yourself in another session during the turn (e.g. `/model`
  rewriting `~/.claude/settings.json`) shows up here too.
- **Test mode:** a production host has `[testing]` in `~/.hib/config.toml`;
  remove it and restart HIB.
- **Credential reads (Falco):** the `cmdline` and ancestors show which agent
  command did it. HIB's own logs for that session show whether a human approved
  the command.
- **Auth failures:** something local is calling HIB's API without the token;
  `remote` and `path` say from where and what.
