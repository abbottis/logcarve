#!/bin/sh
# Demo health/readiness probe.
#
# - GET /healthz is public and minimal (liveness only).
# - GET /readyz requires a private admin session: an unauthenticated 401 is
#   the EXPECTED proof of gating, not a health signal. Authenticated
#   readiness logs in with the demo admin password read from the protected
#   secrets file inside Python (never in argv) and sent via curl stdin
#   (`--data @-`), using a temporary cookie jar inside the protected
#   secrets directory that is always deleted. Nothing secret is printed.
set -eu

# shellcheck disable=SC1091
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

need_file "$DEMO_ENV_FILE"

echo "== public liveness =="
health=$(curl -sf "$DEMO_BASE_URL/healthz")
echo "$health"
echo "$health" | python3 -c 'import json,sys; d = json.load(sys.stdin); assert d["status"] == "ok" and d["ai_enabled"] is False, d'

echo "== gated readiness (unauthenticated must be 401 once seeded) =="
code=$(curl -s -o /dev/null -w '%{http_code}' "$DEMO_BASE_URL/readyz")
echo "unauthenticated /readyz -> $code"
if [ "$code" = "503" ]; then
  echo "store not migrated/seeded yet (503 before migrations); run ./scripts/demo/start.sh" >&2
  exit 1
fi
[ "$code" = "401" ] || { echo "expected 401, got $code" >&2; exit 1; }

echo "== gated readiness (private admin session) =="
jar="$DEMO_SECRET_DIR/.health-cookies.$$"
trap 'rm -f "$jar"' EXIT INT TERM
# Password travels file -> Python -> pipe -> curl stdin; never argv/env/echo.
python3 - "$DEMO_ENV_FILE" <<'EOF' | curl -sf -b "$jar" -c "$jar" \
  -H "Content-Type: application/json" --data @- \
  "$DEMO_BASE_URL/api/v1/admin/login" \
  | python3 -c 'import json,sys; assert json.load(sys.stdin)["csrf_token"], "login failed"'
import json
import sys

secrets = dict(
    line.strip().split("=", 1)
    for line in open(sys.argv[1])
    if "=" in line
)
print(json.dumps({"username": "demo-admin", "password": secrets["LOGCARVE_ADMIN_PASSWORD"]}))
EOF
ready=$(curl -sf -b "$jar" "$DEMO_BASE_URL/readyz")
echo "$ready"
echo "$ready" | python3 -c 'import json,sys; assert json.load(sys.stdin).get("ready") is True'
echo "demo ready"
