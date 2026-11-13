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
| Coding Agent Read Credential Store | WARNING | an agent or its child reads `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.kube`, `.netrc`, `.git-credentials`, `~/.docker/config.json`, `.pgpass` (git/ssh reading `~/.ssh` excepted) |
| Coding Agent Subprocess Read Agent Credentials | CRITICAL | a child of an agent (not the CLI itself) reads `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.hib/token` or `~/.hib/vault.key` |
| Coding Agent Write Shell or Login Persistence | CRITICAL | an agent or its child writes a shell rc file, `authorized_keys`, a crontab, or a user systemd/autostart unit |
| Coding Agent Write Repository or Agent Hook | WARNING | a child of an agent writes `.git/hooks/*` (not git's inert `*.sample` templates), `.mcp.json`, `.claude/settings*` or `.codex/config.toml` |
| HIB Secrets Read by Unexpected Process | WARNING | anything other than the HIB daemon (`bun`) reads HIB's token or vault key |

The agents' own CLIs legitimately read their config and credentials, so most
rules only flag the agents' *children*. HIB's sandbox denies these paths to
agents, so a hit usually means an unsandboxed agent or a sandbox bypass.

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
eBPF probe for a minute and plays 7 cases that must alert and 6 that must not,
with stand-in processes named `claude`, `codex` and `bun` against a throwaway
fake home (never real credentials). The negative cases include `ssh` reading
`~/.ssh`, an agent CLI reading its own credentials, HIB's daemon reading its
vault key, and `git init` writing its sample hooks. Run it from a normal shell,
not from inside Claude Code or Codex: the rules key on agent ancestry, so
everything started from an agent's own terminal counts as agent activity.

```bash
./scripts/test-coding-agent-rules.sh                        # FALCO_VERSION from the environment, default 0.44.1
FALCO_VERSION=0.45.2 ./scripts/test-coding-agent-rules.sh   # another Falco release
```

It ends with `PASS`/`FAIL` per case and lists any other coding-agent alerts the
host raised meanwhile (real activity), which is a quick false-positive check.

All 13 cases pass with Falco 0.45.2. On Linux 7.2 (aarch64), Falco 0.44.1's
modern eBPF probe doesn't load at all (the kernel's verifier rejects its
`signal_deliver` program), so there the script fails before any case runs and
Falco 0.45.2 is needed.

## 2. HIB's security event log

HIB writes JSON lines to `~/.hib/events/` (format:
[HIB security event log](hib-events-spec.md)). On a fleet host that runs HIB,
point the collector at that directory:

```yaml
devbox:
  ansible_host: 192.168.1.20
  hib_events_dir: /home/alice/.hib/events
```

then `make deploy-fleet LIMIT=devbox`. Only that directory is given to the
collector, never `~/.hib` itself (which holds HIB's token and vault key).

- **VM stack (Vector):** the directory is mounted read-only into the Vector
  container; events go to VictoriaLogs with stream fields `hostname`,
  `source=hib`, and every event field searchable
  (`source:hib event:tool.permission decision:deny`).
- **Grafana stack (Alloy):** Alloy reads it through its host mount; events go
  to Loki with labels `source="hib"`, `hostname`, `event`, `severity`, the rest
  in the JSON line (`{source="hib"} | json`).

The `hostname` is the inventory name, the same as for the host's other logs
and metrics; HIB's own `host` field is kept as `hib_host`.

## Alerts

`make install-grafana` provisions a **HIB** group in the SIB alert folder
(see [Grafana Alerts](grafana-alerts.md)):

| Rule | Fires when | Severity |
|------|------------|----------|
| HIB critical security event | any `critical` HIB event in 10 minutes (`protected.reverted`: an agent changed git hooks or agent config without approval) | critical |
| HIB authentication failures | more than 5 failed requests in 15 minutes (sum of the events' `count`; HIB aggregates repeats within 60 s into one line) | warning |
| HIB agent denials burst | more than 5 denied tool calls or blocked data reads in 15 minutes (a denied network request is a denied tool call too; `sandbox.network` isn't counted again) | warning |
| HIB sandbox unavailable | `sandbox.unavailable` in the last hour | warning |
| HIB daemon not running | heartbeats (`daemon.alive`, every 5 min) in the last 24 hours, none for 15 minutes, and no clean `daemon.stop` in those 24 hours: a crash, a kill, or events no longer reaching SIB | warning |

They stay quiet on hosts without HIB. `guard.decision` is written for every
prompt; only its `warning` lines (`rejected`, `timeout`) are worth a look, e.g.
`source:hib event:guard.decision severity:warning` in the Events Explorer.

*HIB daemon not running* needs a HIB version that writes `daemon.alive`
heartbeats. A clean stop suppresses it for 24 hours, so a crash within a day
of a deliberate stop and restart is only noticed once the 24-hour window
moves past that stop.

## Privacy of the event log

HIB keeps payloads out of the log: no prompts, model output, file contents or
secrets, and the free-text fields (`command`, `url`, `reasons`) are redacted
before they are written. The metadata still says a lot: absolute workspace
paths (often a customer or project name), session and account names, when
agents work and for how long, which tools they use and which files or hosts
they touch. Treat the HIB stream in VictoriaLogs/Loki like the rest of SIB's
security data: restrict who can query it and keep the retention short for
sensitive workloads.

## What to look at when one fires

- **protected.reverted:** the event's `changes` list shows what the agent tried
  to change. A new git hook or `.mcp.json` entry is a persistence attempt;
  check the session that produced it in HIB.
- **Credential reads (Falco):** the `cmdline` and ancestors show which agent
  command did it. HIB's own logs for that session show whether a human approved
  the command.
- **Auth failures:** something local is calling HIB's API without the token;
  `remote` and `path` say from where and what.
