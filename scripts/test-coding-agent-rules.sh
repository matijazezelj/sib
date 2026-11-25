#!/bin/bash
# Runtime test for detection/config/rules/coding_agent_rules.yaml
#
# Usage: sudo-less if your user can run Docker; needs a kernel with BTF (modern eBPF).
#   ./scripts/test-coding-agent-rules.sh
#
# Starts Falco (FALCO_VERSION, default 0.45.2) privileged with the modern eBPF
# probe, loading only falco_rules.yaml (for its macros) and the coding agent
# pack. Then it plays positive and negative cases with stand-in processes named
# claude / codex / bun against a throwaway fake home: fake files only, never
# real credentials. Falco and the fixtures are removed afterwards.
#
# The kernel names a script's process after the script file, so a shell
# script called "claude" is a process "claude" to Falco, like the real CLI.
#
# Run it from a shell that is NOT inside a coding agent (not from Claude Code's
# or Codex's own terminal tool): the rules key on agent ancestry, so every
# process started there is an agent descendant and the negative cases fire.

set -u

# Same for HIB_SESSION: processes carrying it count as agent activity.
if [ -n "${HIB_SESSION:-}" ]; then
    echo "HIB_SESSION is set: this shell runs under a HIB agent session. Run the test from a plain shell."; exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
FALCO_IMAGE="falcosecurity/falco:${FALCO_VERSION:-0.45.2}"
NAME="sib-falco-agent-test"
FX="$(mktemp -d /tmp/sib-agent-rules.XXXXXX)"
OUT="$FX/falco.jsonl"
FAILED=0

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1
    rm -rf "$FX"
}
trap cleanup EXIT

# --- fixtures -------------------------------------------------------------------
H="$FX/home"
mkdir -p "$H/.ssh" "$H/.aws" "$H/.claude" "$H/.codex" "$H/.hib" "$H/.config/gh" "$H/repo/.git/hooks" "$H/repo/.claude" "$H/repo/src" "$FX/bin"
# A second home for the HIB_SESSION cases, so their alerts can't be mistaken
# for the first home's cases on the same file names.
H2="$FX/home2"; H3="$FX/home3"; mkdir -p "$H2/.claude" "$H2/.codex" "$H3/.claude" "$H3/.codex"
for f in .claude/.credentials.json .codex/auth.json; do
    echo "fake test content, not a secret" > "$H2/$f"; echo "fake test content, not a secret" > "$H3/$f"
done
# A git template with a real (non-.sample) hook: git init copies it, which must alert.
mkdir -p "$FX/tpl/hooks" && printf '#!/bin/sh\nexit 0\n' > "$FX/tpl/hooks/post-checkout" && chmod +x "$FX/tpl/hooks/post-checkout"
for f in .ssh/id_case1 .ssh/id_case3 .ssh/id_case14 .ssh/id_case18 .aws/credentials_case17 .aws/credentials_case18 .ssh/config .ssh/known_hosts .aws/credentials_case2 .claude/.credentials.json \
         .codex/auth.json .hib/token .hib/vault.key .bashrc .aws/credentials_case12 .config/gh/hosts.yml .git-credentials; do
    echo "fake test content, not a secret" > "$H/$f"
done
# ssh -G must parse the config, so it gets real (harmless) syntax.
printf 'Host sib-test.invalid\n  User sib-test\n' > "$H/.ssh/config"
chmod -R a+rX "$FX"

# Stand-ins: each runs the command it is given, as a child process.
for agent in claude codex; do
    printf '#!/bin/sh\nexec_child() { "$@"; }\nexec_child "$@"\n' > "$FX/bin/$agent"
done
# Variants that open the file themselves (the CLI / daemon reading its own files).
printf '#!/bin/sh\nexec 3< "$1"\nexec 3<&-\n' > "$FX/bin/claude-self"
cp "$FX/bin/claude-self" "$FX/bin/bun"
mkdir -p "$FX/self" && cp "$FX/bin/claude-self" "$FX/self/claude"
# A stand-in tool that reads its argument itself (gh reading a credential store).
cp "$FX/bin/claude-self" "$FX/bin/gh"
# git's credential store helper; the kernel cuts its name to "git-credential-".
cp "$FX/bin/claude-self" "$FX/bin/git-credential-store"
# The CLI writing a file itself (its Write/Edit tool), no child process.
mkdir -p "$FX/selfw" && printf '#!/bin/sh\necho x > "$1"\n' > "$FX/selfw/claude"
# HIB_SESSION stand-ins: an agent CLI under another name (Claude Code from npm
# runs as node), and HIB's daemon (bun) starting it.
cp "$FX/bin/claude" "$FX/bin/node"
mkdir -p "$FX/hibd" && cp "$FX/bin/claude" "$FX/hibd/bun"
cp "$FX/bin/claude-self" "$FX/self/node"
chmod +x "$FX/bin/"* "$FX/self/claude" "$FX/self/node" "$FX/selfw/claude" "$FX/hibd/bun"
SID="w_5e55105e55105e55"   # a made-up HIB session id
# Falco keeps only the first 4096 bytes of a process's environment. bash
# re-exports variables in its own order, so the variable's place can't be
# relied on in a big environment (HIB gives its CLIs a small one).
# sess runs a command with a small environment (a server, HIB started by
# systemd), where Falco sees it; sess_late appends it after 5000 bytes, out of
# Falco's sight (N12: the known limit).
sess() { env -i PATH="$PATH" HOME="$HOME" HIB_SESSION="$SID" "$@"; }
sess_late() { env SIB_TEST_PAD="$(printf '%05000d' 0)" HIB_SESSION="$SID" "$@"; }
# A HIB session scope, as HIB 0.4.0+ makes them (a transient systemd user
# scope, removed when its processes end). No HIB_SESSION: the cgroup alone.
scoped() {
    systemd-run --user --scope --quiet --collect \
        --unit="hib-$SID-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n').scope" -- "$@"
}
SCOPES=1
if ! systemd-run --user --scope --quiet --collect -- true >/dev/null 2>&1; then
    SCOPES=0; echo "NOTE: no user systemd (systemd-run --user --scope failed): skipping the session scope cases"
fi

# --- Falco -----------------------------------------------------------------------
docker rm -f "$NAME" >/dev/null 2>&1
docker run -d --name "$NAME" --privileged \
    -v /proc:/host/proc:ro -v /etc:/host/etc:ro -v /dev:/host/dev:ro \
    -v /var/run/docker.sock:/host/var/run/docker.sock:ro \
    -v "$ROOT/detection/config/rules/coding_agent_rules.yaml:/etc/falco/rules.d/coding_agent_rules.yaml:ro" \
    -e HOST_ROOT=/host -e FALCOCTL_DRIVER_TYPE=modern_ebpf \
    "$FALCO_IMAGE" falco -o engine.kind=modern_ebpf -o json_output=true -o priority=debug \
        >/dev/null || { echo "could not start Falco"; exit 1; }
# The image's default rules_files loads falco_rules.yaml and /etc/falco/rules.d.

for _ in $(seq 1 60); do
    docker logs "$NAME" 2>&1 | grep -q "Starting health webserver\|Opening 'syscall' source" && break
    sleep 1
done
sleep 5   # let the probe attach
if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "Falco exited:"; docker logs "$NAME" 2>&1 | tail -5; exit 1
fi

# --- cases -----------------------------------------------------------------------
# id | expected rule ("-" = no coding agent alert) | command
cases=(
  "P1|Coding Agent Read Credential Store|$FX/bin/claude cat $H/.ssh/id_case1"
  "P2|Coding Agent Read Credential Store|$FX/bin/codex sh -c 'cat $H/.aws/credentials_case2'"
  "P3|Coding Agent Subprocess Read Agent Credentials|$FX/bin/claude cat $H/.claude/.credentials.json"
  "P4|Coding Agent Write Shell or Login Persistence|$FX/bin/claude sh -c 'echo x >> $H/.bashrc'"
  "P5|Coding Agent Write Repository or Agent Hook|$FX/bin/codex sh -c 'echo x > $H/repo/.git/hooks/pre-commit'"
  "P6|HIB Secrets Read by Unexpected Process|cat $H/.hib/token"
  "N1|-|$FX/self/claude $H/.codex/auth.json"
  "N2|-|$FX/bin/claude ssh -G -F $H/.ssh/config sib-test.invalid"
  "N3|-|cat $H/.ssh/id_case3"
  "N4|-|$FX/bin/bun $H/.hib/vault.key"
  "N5|-|$FX/bin/claude sh -c 'echo x > $H/repo/src/app.ts'"
  "N6|-|$FX/bin/claude git init -q $H/repo"
  "P7|Coding Agent Write Repository or Agent Hook|$FX/bin/claude git init -q --template=$FX/tpl $H/repo2"
  "P8|Coding Agent Write Repository or Agent Hook|$FX/selfw/claude $H/repo/.git/hooks/post-merge"
  "P9|Coding Agent Write Shell or Login Persistence|$FX/bin/claude sh -c 'echo x > $FX/tmp9 && mv $FX/tmp9 $H/.bash_profile'"
  "P10|Coding Agent Write Shell or Login Persistence|$FX/bin/codex sh -c 'echo x >> $H/.zshenv'"
  "P11|Coding Agent Write Repository or Agent Hook|$FX/bin/claude ln -s /bin/true $H/repo/.git/hooks/post-commit"
  "P12|Coding Agent Read Credential Store|$FX/bin/claude $FX/bin/gh $H/.aws/credentials_case12"
  "P13|Coding Agent Write Shell or Login Persistence|$FX/bin/claude sh -c 'echo x > $FX/tmp13 && ln $FX/tmp13 $H/.zlogin'"
  "N7|-|$FX/bin/claude $FX/bin/gh $H/.config/gh/hosts.yml"
  "N9|-|$FX/bin/claude $FX/bin/git-credential-store $H/.git-credentials"
  "N8|-|$FX/selfw/claude $H/repo/.claude/settings.local.json"
  # HIB_SESSION: no claude/codex process anywhere in the ancestry.
  # The stand-ins are shell scripts: the variable survives the shells that
  # re-export the environment to their children.
  "P14|Coding Agent Read Credential Store|sess $FX/bin/node cat $H/.ssh/id_case14"
  "P15|Coding Agent Subprocess Read Agent Credentials|sess $FX/hibd/bun $FX/bin/node cat $H2/.codex/auth.json"
  "P17|Coding Agent Read Credential Store|sess $FX/bin/node bash -c 'zsh -c \"cat $H/.aws/credentials_case17\"'"
  "N10|-|sess $FX/hibd/bun $FX/self/node $H2/.claude/.credentials.json"
  "N12|-|sess_late cat $H/.aws/credentials_case18"
  # Detached: the agent exits, its child is reparented, then writes. Only the
  # variable still ties it to the agent (N11, without it, is the known gap).
  "P16|Coding Agent Write Shell or Login Persistence|sess $FX/bin/claude setsid -f sh -c 'sleep 2; echo x >> $H/.zprofile'"
  "N11|-|$FX/bin/claude setsid -f sh -c 'sleep 2; echo x >> $H/.zlogout'"
)
# Session scopes: the cgroup ties a process to the session through env -i and
# setsid, where neither ancestry nor HIB_SESSION is left.
if [ "$SCOPES" = 1 ]; then cases+=(
  "P18|Coding Agent Read Credential Store|scoped $FX/bin/node cat $H/.ssh/id_case18"
  "P19|Coding Agent Write Shell or Login Persistence|scoped $FX/bin/claude env -i /usr/bin/setsid -f /bin/sh -c 'sleep 2; echo x >> $H/.bash_login'"
  "P20|Coding Agent Subprocess Read Agent Credentials|scoped $FX/hibd/bun $FX/bin/node cat $H3/.codex/auth.json"
  "N13|-|scoped $FX/hibd/bun $FX/self/node $H3/.claude/.credentials.json"
); fi
# A case whose command fails (a missing tool, a typo) didn't exercise the rule,
# so it fails too, rather than passing a negative case vacuously.
declare -A RC
for c in "${cases[@]}"; do
    IFS='|' read -r id _ cmd <<< "$c"
    eval "$cmd" >/dev/null 2>&1
    RC[$id]=$?
    sleep 0.5
done
sleep 5   # also lets the detached cases (sleep 2) write
docker logs "$NAME" 2>/dev/null | grep '^{' > "$OUT"

# --- check -----------------------------------------------------------------------
# An alert belongs to this run if it mentions the fixture directory.
hits() { grep -F "$FX" "$OUT" | grep -F "\"rule\":\"$1\"" ; }
agent_hits_for() { grep -F "$1" "$OUT" | grep -E '"rule":"(Coding Agent|HIB Secrets)' ; }

target_of() { # the fixture path a case touches
    case "$1" in
        P1) echo "$H/.ssh/id_case1" ;; N3) echo "$H/.ssh/id_case3" ;; P2) echo "$H/.aws/credentials_case2" ;;
        P3) echo "$H/.claude/.credentials.json" ;; P4) echo "$H/.bashrc" ;;
        P5) echo "$H/repo/.git/hooks/pre-commit" ;; P6) echo "$H/.hib/token" ;;
        P7) echo "$H/repo2/.git/hooks/post-checkout" ;;
        P8) echo "$H/repo/.git/hooks/post-merge" ;; P9) echo "$H/.bash_profile" ;; P10) echo "$H/.zshenv" ;;
        P11) echo "$H/repo/.git/hooks/post-commit" ;; P12) echo "$H/.aws/credentials_case12" ;; P13) echo "$H/.zlogin" ;;
        N7) echo "$H/.config/gh/hosts.yml" ;; N8) echo "$H/repo/.claude/settings.local.json" ;; N9) echo "$H/.git-credentials" ;;
        N1) echo "$H/.codex/auth.json" ;; N2) echo "$H/.ssh/config" ;; N4) echo "$H/.hib/vault.key" ;;
        N5) echo "$H/repo/src/app.ts" ;;
        N6) echo "$H/repo/.git/" ;;
        P14) echo "$H/.ssh/id_case14" ;; P15) echo "$H2/.codex/auth.json" ;; N10) echo "$H2/.claude/.credentials.json" ;;
        P16) echo "$H/.zprofile" ;; N11) echo "$H/.zlogout" ;;
        P17) echo "$H/.aws/credentials_case17" ;; N12) echo "$H/.aws/credentials_case18" ;;
        P18) echo "$H/.ssh/id_case18" ;; P19) echo "$H/.bash_login" ;; P20) echo "$H3/.codex/auth.json" ;;
        N13) echo "$H3/.claude/.credentials.json" ;;
    esac
}

for c in "${cases[@]}"; do
    IFS='|' read -r id rule _ <<< "$c"
    t=$(target_of "$id")
    if [ "${RC[$id]}" -ne 0 ]; then
        echo "FAIL $id command exited ${RC[$id]}: case not exercised"; FAILED=1; continue
    fi
    if [ "$rule" = "-" ]; then
        if [ "$id" = N6 ]; then n=$(agent_hits_for "$t" | grep -c '\.sample' || true); else n=$(agent_hits_for "$t" | wc -l); fi
        if [ "$n" -eq 0 ]; then echo "PASS $id no alert          ($t)"; else echo "FAIL $id unexpected alert ($t)"; agent_hits_for "$t" | head -2; FAILED=1; fi
    else
        if hits "$rule" | grep -qF "$t"; then echo "PASS $id $rule"; else echo "FAIL $id expected '$rule' for $t"; FAILED=1; fi
    fi
done

# The HIB_SESSION cases must name the session in the alert.
for id in P14 P15 P16 P17; do
    if agent_hits_for "$(target_of "$id")" | grep -qF "session=$SID"; then echo "PASS $id names session=$SID"
    else echo "FAIL $id alert doesn't name session=$SID"; FAILED=1; fi
done
# The scope cases must name the scope.
if [ "$SCOPES" = 1 ]; then for id in P18 P19 P20; do
    if agent_hits_for "$(target_of "$id")" | grep -qF "/hib-$SID-"; then echo "PASS $id names the scope hib-$SID-"
    else echo "FAIL $id alert doesn't name the scope hib-$SID-"; FAILED=1; fi
done; fi

others=$(grep -E '"rule":"(Coding Agent|HIB Secrets)' "$OUT" | grep -vcF "$FX" || true)
echo "Other coding-agent alerts on this host during the test (real activity, not fixtures): $others"
grep -E '"rule":"(Coding Agent|HIB Secrets)' "$OUT" | grep -vF "$FX" | head -5 | cut -c1-300
exit $FAILED
