#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT="$ROOT/alerting/config/config.yaml"
BACKUP=$(mktemp)
trap 'if [ -s "$BACKUP" ]; then cp "$BACKUP" "$OUTPUT"; else rm -f "$OUTPUT"; fi; rm -f "$BACKUP"' EXIT
[ ! -f "$OUTPUT" ] || cp "$OUTPUT" "$BACKUP"

WEBHOOK_ADDRESS='http://127.0.0.1:8644/webhooks/falco?source="sib"' \
WEBHOOK_HEADER_NAME='X-Gitlab-Token' \
WEBHOOK_HEADER_VALUE='test-"secret"-with-\slash' \
WEBHOOK_MINIMUM_PRIORITY='warning' \
    "$ROOT/scripts/generate-sidekick-config.sh" >/dev/null

python3 - "$OUTPUT" <<'PY'
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
expected = [
    'hostport: "http://sib-victorialogs:9428"',
    'endpoint: "/insert/loki/api/v1/push"',
    'webhook:',
    'address: "http://127.0.0.1:8644/webhooks/falco?source=\\"sib\\""',
    'X-Gitlab-Token: "test-\\"secret\\"-with-\\\\slash"',
    'minimumpriority: "warning"',
]
for item in expected:
    assert item in text, item
assert (Path(sys.argv[1]).stat().st_mode & 0o777) == 0o640
PY

STACK=grafana "$ROOT/scripts/generate-sidekick-config.sh" >/dev/null
grep -q 'hostport: "http://sib-loki:3100"' "$OUTPUT"
grep -q 'endpoint: "/loki/api/v1/push"' "$OUTPUT"

if WEBHOOK_ADDRESS=http://127.0.0.1 \
   WEBHOOK_HEADER_NAME='Bad Header' \
   WEBHOOK_HEADER_VALUE=secret \
   "$ROOT/scripts/generate-sidekick-config.sh" >/dev/null 2>&1; then
    echo "invalid webhook header name was accepted" >&2
    exit 1
fi

echo "sidekick config tests: PASS"