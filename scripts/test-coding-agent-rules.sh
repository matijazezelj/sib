#!/bin/bash
# Runtime test for detection/config/rules/coding_agent_rules.yaml
#
# Usage: sudo-less if your user can run Docker; needs a kernel with BTF (modern eBPF).
#   ./scripts/test-coding-agent-rules.sh
#
# Starts Falco (FALCO_VERSION, default 0.44.1) privileged with the modern eBPF
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
FALCO_IMAGE="falcosecurity/falco:${FALCO_VERSION:-0.44.1}"
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
mkdir -p "$H/.ssh" "$H/.aws" "$H/.claude" "$H/.codex" "$H/.hib" "$H/repo/.git/hooks" "$H/repo/src" "$FX/bin"
# A git template with a real (non-.sample) hook: git init copies it, which must alert.
mkdir -p "$FX/tpl/hooks" && printf '#!/bin/sh\nexit 0\n' > "$FX/tpl/hooks/post-checkout" && chmod +x "$FX/tpl/hooks/post-checkout"
for f in .ssh/id_case1 .ssh/id_case3 .ssh/config .ssh/known_hosts .aws/credentials_case2 .claude/.credentials.json \
         .codex/auth.json .hib/token .hib/vault.key .bashrc; do
    echo "fake test content, not a secret" > "$H/$f"
done
chmod -R a+rX "$FX"

# Stand-ins: each runs the command it is given, as a child process.
for agent in claude codex; do
    printf '#!/bin/sh\nexec_child() { "$@"; }\nexec_child "$@"\n' > "$FX/bin/$agent"
done
# Variants that open the file themselves (the CLI / daemon reading its own files).
printf '#!/bin/sh\nexec 3< "$1"\nexec 3<&-\n' > "$FX/bin/claude-self"
cp "$FX/bin/claude-self" "$FX/bin/bun"
mkdir -p "$FX/self" && cp "$FX/bin/claude-self" "$FX/self/claude"
chmod +x "$FX/bin/"* "$FX/self/claude"

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
)
for c in "${cases[@]}"; do
    IFS='|' read -r _ _ cmd <<< "$c"
    eval "$cmd" >/dev/null 2>&1
    sleep 0.5
done
sleep 5
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
        N1) echo "$H/.codex/auth.json" ;; N2) echo "$H/.ssh/config" ;; N4) echo "$H/.hib/vault.key" ;;
        N5) echo "$H/repo/src/app.ts" ;;
        N6) echo "$H/repo/.git/" ;;
    esac
}

for c in "${cases[@]}"; do
    IFS='|' read -r id rule _ <<< "$c"
    t=$(target_of "$id")
    if [ "$rule" = "-" ]; then
        if [ "$id" = N6 ]; then n=$(agent_hits_for "$t" | grep -c '\.sample' || true); else n=$(agent_hits_for "$t" | wc -l); fi
        if [ "$n" -eq 0 ]; then echo "PASS $id no alert          ($t)"; else echo "FAIL $id unexpected alert ($t)"; agent_hits_for "$t" | head -2; FAILED=1; fi
    else
        if hits "$rule" | grep -qF "$t"; then echo "PASS $id $rule"; else echo "FAIL $id expected '$rule' for $t"; FAILED=1; fi
    fi
done

others=$(grep -E '"rule":"(Coding Agent|HIB Secrets)' "$OUT" | grep -vcF "$FX" || true)
echo "Other coding-agent alerts on this host during the test (real activity, not fixtures): $others"
grep -E '"rule":"(Coding Agent|HIB Secrets)' "$OUT" | grep -vF "$FX" | head -5 | cut -c1-300
exit $FAILED
