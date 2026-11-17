#!/bin/bash
# SIB end-to-end test: HIB events -> collector -> storage -> Grafana alert rules.
#
#   make e2e STACK=vm        # Vector -> VictoriaLogs (default)
#   make e2e STACK=grafana   # Alloy -> Loki
#
# Runs an isolated Docker project (sib-e2e: own network, volumes and ports) built
# from SIB's real compose services, generated alert rules, datasources and the
# collector configs rendered from the Ansible templates. A running SIB install
# is not touched, and .env is never read (no test alert can reach a real Slack
# or Telegram).
#
# Three simulated hosts, one collector each:
#   e2e-hib      a real HIB daemon (HIB_DIR, default ../hib; 0.3.0 or later):
#                heartbeats, wrong-token requests, a scripted agent session
#                (HIB's test agent: denials, a reverted git hook, a changed
#                ~/.bashrc; ~/.claude/settings.json changed twice: model
#                only, then a hook), clean stops, a refused events.key
#   e2e-replay   recorded HIB events: protected.reverted, a denial burst,
#                sandbox.unavailable, heartbeats that stopped 20 minutes ago
#   e2e-stopped  recorded heartbeats followed by a clean daemon.stop
# Then scripts/e2e/e2e.py checks: events written, events in storage under the
# right hostname, and every HIB rule healthy, evaluated after the data arrived,
# and firing for exactly the expected hosts.
#
# Needs Docker (Compose 2.24+), python3, ansible-playbook, and bun for the real
# HIB part (skipped with a notice when HIB isn't found). KEEP=1 leaves the stack
# running for inspection (remove it with: docker compose -p sib-e2e down -v).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STACK="${STACK:-vm}"
case "$STACK" in vm|grafana) ;; *) echo "STACK must be vm or grafana"; exit 2 ;; esac
HIB_DIR="${HIB_DIR:-$ROOT/../hib}"
E2E_DIR="$(mktemp -d /tmp/sib-e2e.XXXXXX)"
export E2E_DIR
export E2E_LOGS_PORT="${E2E_LOGS_PORT:-19428}"
export E2E_GRAFANA_PORT="${E2E_GRAFANA_PORT:-13000}"
export E2E_GRAFANA_PASSWORD="e2e-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
HIB_PORT="${E2E_HIB_PORT:-18877}"
HIB_PID=""

compose() {
    # Clean environment: only what the compose file needs, never .env.
    env -i PATH="$PATH" HOME="$HOME" ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} \
        E2E_DIR="$E2E_DIR" E2E_LOGS_PORT="$E2E_LOGS_PORT" E2E_GRAFANA_PORT="$E2E_GRAFANA_PORT" \
        E2E_GRAFANA_PASSWORD="$E2E_GRAFANA_PASSWORD" \
        E2E_VECTOR_IMAGE="${E2E_VECTOR_IMAGE:-}" E2E_ALLOY_IMAGE="${E2E_ALLOY_IMAGE:-}" \
        docker compose -p sib-e2e -f "$ROOT/scripts/e2e/compose-$STACK.yaml" "$@"
}

cleanup() {
    [ -n "$HIB_PID" ] && kill "$HIB_PID" 2>/dev/null || true
    if [ "${KEEP:-0}" = 1 ]; then
        echo "KEEP=1: stack left running (Grafana http://127.0.0.1:$E2E_GRAFANA_PORT, admin / $E2E_GRAFANA_PASSWORD; files in $E2E_DIR)"
        return
    fi
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$E2E_DIR"
}
trap cleanup EXIT

step() { echo; echo "--- $*"; }

# --- collector images and configs, from the Ansible inventory and templates ----
read -r E2E_VECTOR_IMAGE E2E_ALLOY_IMAGE < <(python3 -c '
import yaml,sys; v=yaml.safe_load(open(sys.argv[1]))
print(v["vector_image"], "grafana/alloy:" + v["alloy_version"])' "$ROOT/ansible/inventory/group_vars/all.yml")
export E2E_VECTOR_IMAGE E2E_ALLOY_IMAGE

step "Rendering configs ($STACK) in $E2E_DIR"
mkdir -p "$E2E_DIR"/{collectors,grafana/datasources,hosts}
for h in e2e-hib e2e-replay e2e-stopped; do mkdir -m 700 -p "$E2E_DIR/hosts/$h"; done
cat > "$E2E_DIR/render.yml" <<'EOF'
- hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.template: {src: "{{ tpl }}", dest: "{{ out }}", mode: "0644"}
EOF
for h in e2e-hib e2e-replay e2e-stopped; do
    if [ "$STACK" = vm ]; then
        tpl="$ROOT/ansible/roles/vm_collectors/templates/vector.toml.j2"; out="$E2E_DIR/collectors/$h.toml"
    else
        tpl="$ROOT/ansible/roles/alloy/templates/config.alloy.j2"; out="$E2E_DIR/collectors/$h.alloy"
    fi
    # Only the HIB pipeline: the Alloy toggles turn off host logs and metrics.
    ANSIBLE_LOCALHOST_WARNING=False ansible-playbook -i localhost, -c local "$E2E_DIR/render.yml" \
        -e @"$ROOT/ansible/inventory/group_vars/all.yml" \
        -e "ansible_python_interpreter=$(command -v python3)" \
        -e "tpl=$tpl out=$out inventory_hostname=$h ansible_host=$h hib_events_dir=$E2E_DIR/hosts/$h" \
        -e "effective_deployment=docker sib_victorialogs_url=http://sib-victorialogs:9428" \
        -e "sib_loki_url=http://sib-loki:3100 sib_prometheus_url=http://sib-prometheus:9090" \
        -e '{"alloy_collect_logs": false, "alloy_collect_docker_logs": false, "alloy_collect_journal": false, "alloy_collect_metrics": false, "mtls_enabled": false}' \
        >/dev/null
done

# Grafana: SIB's datasources for the stack, and the alert rules from the real
# generator, run in a scratch copy with a clean environment (no .env).
cp "$ROOT/grafana/provisioning/datasources/templates/datasources-$STACK.yml" "$E2E_DIR/grafana/datasources/datasources.yml"
gen="$E2E_DIR/gen"; mkdir -p "$gen/scripts" "$gen/grafana/provisioning/alerting" "$gen/detection/config"
cp "$ROOT/scripts/generate-grafana-alerting.sh" "$gen/scripts/"
cp -r "$ROOT/grafana/provisioning/alerting/templates" "$gen/grafana/provisioning/alerting/"
env -i PATH="$PATH" STACK="$STACK" bash "$gen/scripts/generate-grafana-alerting.sh" >/dev/null
mkdir -p "$E2E_DIR/grafana/alerting"
cp "$gen/grafana/provisioning/alerting/"*.yml "$E2E_DIR/grafana/alerting/"

# --- e2e-hib: a real HIB daemon ------------------------------------------------
E2E_HIB=1
if [ -f "$HIB_DIR/src/cli.ts" ] && (cd "$HIB_DIR" && bun --version >/dev/null 2>&1); then
    step "Real HIB daemon ($HIB_DIR) -> e2e-hib"
    HH="$E2E_DIR/hibhome"; mkdir -m 700 -p "$HH"
    # A throwaway home folder: HIB's home watch and the scripted agent's
    # ~/.bashrc write land there, never in the real one.
    UH="$E2E_DIR/userhome"; mkdir -m 700 -p "$UH"
    # bun's own path, found from HIB's folder (where a version manager such as
    # mise picks its version), so the daemon can run with the throwaway HOME.
    BUN="$(cd "$HIB_DIR" && bun -e 'console.log(process.execPath)')"
    hib_config() { printf '%s\n[events]\ndir = "%s"\nheartbeat_sec = 5\n%s' "${2:-}" "$E2E_DIR/hosts/e2e-hib" "$1" > "$HH/config.toml"; }
    hib_start() {
        (cd "$HIB_DIR" && exec env -u CLAUDE_CONFIG_DIR -u CODEX_HOME HOME="$UH" HIB_HOME="$HH" "$BUN" src/cli.ts daemon run --port "$HIB_PORT") >>"$E2E_DIR/hib.log" 2>&1 &
        HIB_PID=$!
        for _ in $(seq 60); do
            [ -s "$HH/token" ] && curl -sf -o /dev/null -H "Authorization: Bearer $(cat "$HH/token")" \
                "http://127.0.0.1:$HIB_PORT/hib/info" && return 0
            sleep 0.5
        done
        echo "HIB did not start:"; tail -5 "$E2E_DIR/hib.log"; exit 1
    }
    hib_stop() {
        curl -sf -o /dev/null -X POST -H "Authorization: Bearer $(cat "$HH/token")" "http://127.0.0.1:$HIB_PORT/hib/shutdown"
        wait "$HIB_PID" 2>/dev/null || true; HIB_PID=""
    }
    # Run 1: heartbeats, then 8 requests with a wrong token (HIB logs one line and
    # folds the rest into count, flushed at the clean stop).
    hib_config ""; hib_start; sleep 11
    for _ in $(seq 8); do curl -s -o /dev/null -H "Authorization: Bearer wrong" "http://127.0.0.1:$HIB_PORT/hib/info"; done
    hib_stop
    # Run 2: the siem profile (it creates events.key) and HIB's scripted test
    # agent ([testing] script_dir; daemon.start says script_driver: true). One
    # agent turn through HIB's real permission, protected-file and home checks.
    WS="$E2E_DIR/workspace"; mkdir -p "$WS"; git -C "$WS" init -q
    hib_config "$(printf 'profile = "siem"\n')" "$(printf '[testing]\nscript_dir = "%s"\n' "$E2E_DIR/hib-scripts")"
    mkdir -p "$E2E_DIR/hib-scripts"; hib_start
    python3 "$ROOT/scripts/e2e/e2e.py" session "$HIB_PORT" "$HH/token" "$E2E_DIR/hib-scripts" "$WS" "$UH"
    hib_stop
    # Run 3: the key readable by others is refused (events.key_refused), then a
    # clean stop.
    hib_config "$(printf 'profile = "siem"\n')"
    chmod 644 "$HH/events.key"
    hib_start; sleep 2; hib_stop
    echo "  $(wc -l < "$E2E_DIR/hosts/e2e-hib/events.jsonl") events written"
else
    E2E_HIB=0
    echo "SKIP real HIB: no HIB checkout at $HIB_DIR (set HIB_DIR) or no bun; e2e-hib is not checked"
fi
export E2E_HIB

# --- e2e-replay / e2e-stopped: recorded events --------------------------------
step "Recorded events -> e2e-replay, e2e-stopped"
python3 "$ROOT/scripts/e2e/e2e.py" replay "$E2E_DIR/hosts/e2e-replay" e2e-replay
python3 "$ROOT/scripts/e2e/e2e.py" replay "$E2E_DIR/hosts/e2e-stopped" e2e-stopped
chmod -R go-rwx "$E2E_DIR/hosts"

# --- stack ---------------------------------------------------------------------
step "Starting the sib-e2e stack ($STACK)"
compose up -d --quiet-pull 2>&1 | grep -v "^ *$" | tail -3
for _ in $(seq 90); do
    curl -sf -o /dev/null "http://127.0.0.1:$E2E_GRAFANA_PORT/api/health" && break; sleep 2
done
curl -sf -o /dev/null "http://127.0.0.1:$E2E_GRAFANA_PORT/api/health" || { echo "Grafana did not come up"; compose logs grafana | tail -20; exit 1; }

step "Checking"
rc=0
python3 "$ROOT/scripts/e2e/e2e.py" check "$STACK" "$E2E_DIR" || rc=$?
if [ "$rc" -ne 0 ]; then
    echo; echo "Collector logs (last lines):"
    compose logs --tail 5 collector-hib collector-replay collector-stopped 2>/dev/null | cut -c1-200
fi
exit "$rc"
