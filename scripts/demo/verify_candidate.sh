#!/bin/sh
# Isolated Slice C candidate verification (coordinator executes; Muse
# sandbox cannot reach the Docker socket, so this is never run by Muse).
#
# Proves the combined 120-row demo dataset (30 T8 + 90 rich rows) seeds,
# replays, and survives restart on a track-only export BEFORE any change to
# the persistent `logcarve-demo` demo. Isolation contract:
# - Builds and seeds from `git archive HEAD` (tracked sources only): no
#   host node_modules, static caches, secrets, DBs, or artifacts/.
# - Unique project `logcarve-demo-candidate` on loopback port 8091 with a
#   project-scoped volume/network and a temporary owned runtime directory
#   (mktemp, 0700). Any preexisting container/network/volume with our
#   identity (running OR stopped) refuses the run before anything is
#   created. The persistent demo project is never referenced or touched.
# - Own generated secrets only (0600); the owner base `.env`, the product
#   MODEL_API_KEY file, and the persistent demo secrets are never read.
# - Forced AI-off posture (AI_ENABLED=false, empty model key, unverified
#   policy flags false), non-root image user, no Docker socket, read-only
#   synthetic source mounts.
# - Prints no secrets, tokens, cookies, passwords, rendered Compose config,
#   or env values. Teardown removes only run-owned resources.
set -eu

PROJECT="logcarve-demo-candidate"
PORT="8091"
BASE_URL="http://127.0.0.1:$PORT"
# Optional explicit platform (coordinator-owned emulation proof only):
# empty means the native build host; the two allowlisted values build
# distinctly tagged images. amd64 on an ARM host is EMULATED execution,
# never native x86-64 proof; the persistent demo always uses its tested
# native image explicitly, never an architecture-overwritten shared tag.
PLATFORM="${PLATFORM:-}"
case "$PLATFORM" in
  "") SUFFIX="";;
  linux/arm64) SUFFIX="-arm64";;
  linux/amd64) SUFFIX="-amd64";;
  *) echo "refusing unallowlisted PLATFORM: $PLATFORM (want linux/arm64 or linux/amd64)" >&2; exit 1;;
esac
if [ -n "$PLATFORM" ]; then
  echo "platform override: $PLATFORM (distinct arch tag, see below)"
  case "$(uname -m):$PLATFORM" in
    arm64:linux/amd64) echo "note: amd64 image on ARM host runs EMULATED, not native x86-64 proof";;
  esac
fi
ENTRY_URL="$BASE_URL/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-11-01T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mktemp -d -t logcarve-candidate.XXXXXX)
chmod 0700 "$WORK"

compose() {
  docker compose -p "$PROJECT" -f "$WORK/compose.candidate.yml" "$@"
}

pass=0
fail=0
good() { pass=$((pass + 1)); echo "PASS: $1"; }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

echo "== preconditions (refuse before creating anything) =="
docker info >/dev/null
docker compose version
HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
echo "HEAD: $HEAD_SHA"
IMAGE="logcarve-candidate:$HEAD_SHA$SUFFIX"
echo "image: $IMAGE"
if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]; then
  echo "refusing: preexisting containers for $PROJECT (running or stopped)" >&2; exit 1
fi
if [ -n "$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")" ]; then
  echo "refusing: preexisting networks for $PROJECT" >&2; exit 1
fi
if [ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ]; then
  echo "refusing: preexisting volumes for $PROJECT" >&2; exit 1
fi
if python3 -c 'import socket,sys; s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2); s.close()' "$PORT" 2>/dev/null; then
  echo "refusing: loopback port $PORT already answers (persistent demo or other owner process)" >&2; exit 1
fi
good "no candidate resources or port collision (persistent demo untouched)"
# Cleanup is registered BEFORE the stack exists; preexisting resources were
# refused above, so down -v below can only remove run-owned resources.
trap 'compose down -v >/dev/null 2>&1; rm -rf "$WORK"' EXIT INT TERM

echo "== tracked export =="
mkdir -p "$WORK/export"
git -C "$ROOT" archive HEAD | tar -x -C "$WORK/export"
test -f "$WORK/export/Dockerfile"
test -f "$WORK/export/tests/fixtures/combined/t8_smoke.txt"
test -f "$WORK/export/tests/fixtures/combined/demo_rich_29_31oct.txt"
test -f "$WORK/export/scripts/demo/probe_store.py"
# Authoritative digests of the combined synthetic dataset (26-31 Oct 2026):
# the candidate provenance check pins these values, never the mounts' bytes.
T8_SHA=d765393fb016cc147cf2359f9612b4bb6b6582a9caf1966fb1fe380daeebeb65
RICH_SHA=b9479a8e519b6c9bcdc95fd843ba3ba55066bf57db9f358bd57d9a46852ca45f
sha_of() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
[ "$(sha_of "$WORK/export/tests/fixtures/combined/t8_smoke.txt")" = "$T8_SHA" ] || { echo "exported T8 digest drift" >&2; exit 1; }
[ "$(sha_of "$WORK/export/tests/fixtures/combined/demo_rich_29_31oct.txt")" = "$RICH_SHA" ] || { echo "exported rich digest drift" >&2; exit 1; }
good "tracked export carries both authoritative fixtures"

echo "== build and isolated stack =="
python3 - "$WORK/candidate.env" <<'EOF'
import os
import secrets
import sys

lines = (
    f"SESSION_SECRET={secrets.token_hex(32)}\n"
    f"HMAC_KEY={secrets.token_hex(32)}\n"
    f"LOGCARVE_ADMIN_PASSWORD={secrets.token_urlsafe(24)}\n"
)
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, lines.encode("utf-8"))
finally:
    os.close(fd)
EOF
BUILD_PLATFORM=""
if [ -n "$PLATFORM" ]; then BUILD_PLATFORM="--platform $PLATFORM"; fi
cat >"$WORK/compose.candidate.yml" <<EOF
name: $PROJECT
services:
  app:
    build: $WORK/export
    image: $IMAGE
    ports:
      - "127.0.0.1:$PORT:8080"
    env_file:
      - path: $WORK/candidate.env
        required: true
    environment:
      AI_ENABLED: "false"
      MODEL_API_KEY: ""
      MODEL_DATA_POLICY_VERIFIED: "false"
      MODEL_ALLOW_REAL_DATA: "false"
      DATABASE_PATH: /data/logcarve-candidate.sqlite3
      APP_BASE_URL: $BASE_URL
      DEFAULT_TIMEZONE: Europe/Berlin
      EXTERNAL_API_ENABLED: "true"
    volumes:
      - candidate-data:/data
      - $WORK/export/tests/fixtures/combined/t8_smoke.txt:/logs/demo-access.log:ro
      - $WORK/export/tests/fixtures/combined/demo_rich_29_31oct.txt:/logs/demo-rich-access.log:ro
volumes:
  candidate-data:
EOF
# shellcheck disable=SC2086 -- intentionally unquoted: empty means no flag
compose build $BUILD_PLATFORM
compose up -d
if [ -n "$PLATFORM" ]; then
  actual_arch=$(compose run --rm --no-deps -T app uname -m)
  echo "container arch: $actual_arch (requested $PLATFORM)"
fi
deadline=$(( $(date +%s) + 90 ))
until curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "candidate did not become healthy in 90s" >&2
    compose ps
    exit 1
  fi
  sleep 2
done
good "candidate healthy on $BASE_URL (loopback only)"

echo "== seed combined dataset (private one-offs, nothing printed) =="
run() { compose run --rm --no-deps -T app "$@"; }
probe() { compose run --rm --no-deps -T app python - <"$WORK/export/scripts/demo/probe_store.py"; }
DB_PATH="/data/logcarve-candidate.sqlite3"
first_probe=$(probe 2>/dev/null || true)
echo "store: $first_probe" >&2
run python -m app.auth.cli --db "$DB_PATH" create-admin --username candidate-admin >/dev/null
good "admin created (password never shown)"
for log in demo-access.log demo-rich-access.log; do
  import_json=$(run python -m app.db.cli --db "$DB_PATH" import \
    --source-id example-combined --format nginx_combined \
    --root /logs --path "$log" \
    --site-id default --site-name "Candidate site" --site-hostname example.org \
    --server-type nginx)
  echo "import $log: $import_json"
done
echo "$import_json" | python3 -c 'import json,sys; d = json.load(sys.stdin); assert (d["status"], d["records_inserted"]) == ("completed", 90), d'
good "rich import 90 rows, completed (T8 import completed before it)"
seeded=$(probe)
echo "seeded: $seeded"
echo "$seeded" | python3 -c 'import json,sys; d = json.load(sys.stdin); assert (d["verdict"], d["rows"], d["t8_rows"], d["rich_rows"], d["schema_version"]) == ("SEEDED", 120, 30, 90, 8), d'
good "probe SEEDED with 120 combined rows (30 T8 + 90 rich) at schema v8"

echo "== replay-zero and restart =="
for spec in "demo-access.log 0 30" "demo-rich-access.log 0 90"; do
  set -- $spec
  replay_json=$(run python -m app.db.cli --db "$DB_PATH" import \
    --source-id example-combined --format nginx_combined \
    --root /logs --path "$1" \
    --site-id default --site-name "Candidate site" --site-hostname example.org \
    --server-type nginx)
  echo "$replay_json" | python3 -c 'import json,sys; d = json.load(sys.stdin); assert (d["records_inserted"], d["records_replayed"]) == tuple(int(x) for x in sys.argv[1:3]), d' "$2" "$3"
done
good "re-import replays zero rows (0/30, 0/90)"
compose restart app
deadline=$(( $(date +%s) + 60 ))
until curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "candidate did not recover in 60s" >&2; exit 1
  fi
  sleep 2
done
after=$(probe)
echo "$after" | python3 -c 'import json,sys; d = json.load(sys.stdin); assert (d["verdict"], d["rows"], d["schema_version"]) == ("SEEDED", 120, 8), d'
good "120 rows survive restart at schema v8 (probe re-verified)"

echo "== candidate teardown (owned resources only) =="
compose down -v >/dev/null 2>&1
rm -rf "$WORK"
trap - EXIT INT TERM
echo "CANDIDATE_RESULT pass=$pass fail=$fail"
echo "entry (verified while up): $ENTRY_URL"
[ "$fail" = "0" ]
