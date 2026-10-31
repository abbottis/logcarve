#!/bin/sh
# Finite isolated Compose smoke for the T10 demo image (coordinator executes;
# Muse sandbox cannot reach the Docker socket, so this is never run by Muse).
#
# Isolation contract:
# - Builds from `git archive HEAD` (tracked sources only): no host
#   node_modules, static caches, .uv-python, secrets, DBs, or artifacts/.
# - Unique project `logcarve-smoke-<stamp>` with project-scoped volume and
#   network (no explicit global `name:` shared with the persistent demo).
#   Any preexisting container/network/volume with our identity (running OR
#   stopped) refuses the run before anything is created. No host-port
#   listener check: internal networks publish no host port by design.
# - Offline proof: the smoke network is `internal: true` (verified by label
#   then inspect; isolation failure aborts); every HTTP check executes
#   INSIDE the network via scripts/smoke_offline_probe.py over the service
#   address, with no remote scan or probe of any kind.
# - Prints no secrets, tokens, cookies, passwords, rendered Compose config,
#   or env values. The persistent demo project is never touched; teardown
#   removes only run-owned resources.
# - Browser/layout proof stays separate against the persistent loopback demo
#   (bridge network); static file existence alone never proves the Tailwind
#   build.
set -eu

# Compose project names must be lowercase: the default stamp uses lowercase
# t/z separators (docker compose config rejects uppercase T/Z).
STAMP=${SMOKE_STAMP:-$(date -u +%Y%m%dt%H%M%Sz)}
case "$STAMP" in
  *[!0-9a-z-]* | "") echo "refusing unsafe SMOKE_STAMP: $STAMP" >&2; exit 1 ;;
esac
if [ "${#STAMP}" -gt 32 ]; then
  echo "refusing overlong SMOKE_STAMP: $STAMP" >&2; exit 1
fi
# No SMOKE_PORT: the internal stack publishes no host port, so a port knob
# would only suggest host reachability that cannot exist.
PROJECT="logcarve-smoke-$STAMP"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d -t logcarve-smoke.XXXXXX)
chmod 0700 "$WORK"

compose() {
  docker compose -p "$PROJECT" -f "$WORK/compose.smoke.yml" "$@"
}

# ALL HTTP checks execute inside the isolated network via the tracked helper
# (Docker 29 publishes no host port on `internal: true` networks, so host
# curl is impossible by design). The helper speaks to http://app:8080 over
# the smoke network; the token file is mounted read-only into the one-off.
offline_probe() {
  # Mount the token only once issued: mounting a missing source would make
  # Docker create a directory at its path and break exclusive file creation.
  if [ -e "$WORK/token.txt" ]; then
    compose run --rm --no-deps -T \
      -v "$WORK/token.txt:/run/smoke/token.txt:ro" \
      app python - <"$WORK/export/scripts/smoke_offline_probe.py" "$@"
  else
    compose run --rm --no-deps -T \
      app python - <"$WORK/export/scripts/smoke_offline_probe.py" "$@"
  fi
}

pass=0
fail=0
note() { echo "$1"; }
good() { pass=$((pass + 1)); echo "PASS: $1"; }
bad() { fail=$((fail + 1)); echo "FAIL: $1"; }

echo "== preconditions (refuse before creating anything) =="
docker info >/dev/null
docker compose version
HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
echo "HEAD: $HEAD_SHA"
# No host-port listener check: the smoke stack publishes no host port by
# design (internal network), so foreign listeners cannot collide with it.
if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]; then
  echo "refusing: preexisting containers for $PROJECT (running or stopped)" >&2; exit 1
fi
if [ -n "$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")" ]; then
  echo "refusing: preexisting networks for $PROJECT" >&2; exit 1
fi
if [ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ]; then
  echo "refusing: preexisting volumes for $PROJECT" >&2; exit 1
fi
demo_was_running=""
if docker compose -p logcarve-demo ps --status running 2>/dev/null | grep -q app; then
  demo_was_running="yes"
fi
# Cleanup is registered BEFORE the stack exists; preexisting resources were
# refused above, so down -v below can only remove run-owned resources.
trap 'compose down -v >/dev/null 2>&1; rm -rf "$WORK"' EXIT INT TERM

echo "== tracked export =="
mkdir -p "$WORK/export"
git -C "$ROOT" archive HEAD | tar -x -C "$WORK/export"
test -f "$WORK/export/Dockerfile"
test -f "$WORK/export/tests/fixtures/combined/t8_smoke.txt"
# Authoritative digest of the 30-row synthetic fixture (26–28 Oct 2026):
# the smoke provenance check pins this value, never the mount's own bytes.
FIXTURE_SHA=d765393fb016cc147cf2359f9612b4bb6b6582a9caf1966fb1fe380daeebeb65
actual_sha=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' \
  "$WORK/export/tests/fixtures/combined/t8_smoke.txt")
[ "$actual_sha" = "$FIXTURE_SHA" ] || { echo "exported fixture digest drift" >&2; exit 1; }
# Portable host stat (macOS stat -c does not exist): size + mtime via Python.
src_stat_before=$(python3 -c 'import os,sys; st = os.stat(sys.argv[1]); print(st.st_size, int(st.st_mtime))' \
  "$WORK/export/tests/fixtures/combined/t8_smoke.txt")
good "tracked export carries authoritative fixture"

echo "== build =="
docker build "$WORK/export" -t "logcarve-smoke:$STAMP"
docker run --rm "logcarve-smoke:$STAMP" python -c \
  "import pathlib; [pathlib.Path(p).stat() for p in ('/srv/logcarve/app/web/static/app.css', '/srv/logcarve/app/web/static/vendor/js/htmx.min.js', '/srv/logcarve/app/web/static/vendor/js/chart.umd.min.js', '/srv/logcarve/app/web/static/vendor/PROVENANCE.md', '/srv/logcarve/app/web/static/icons/LUCIDE-ISC.txt', '/srv/logcarve/app/web/static/fonts/INTER-OFL.txt', '/srv/logcarve/app/web/static/fonts/JETBRAINS-MONO-OFL.txt')]; import glob; assert glob.glob('/srv/logcarve/app/web/templates/icons/*.svg'), 'no template icons'"
good "image carries static tree, template icons, and license notices"

echo "== isolated stack (internal network) =="
python3 - "$WORK/smoke.env" <<'EOF'
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
cat >"$WORK/compose.smoke.yml" <<EOF
name: $PROJECT
services:
  app:
    image: logcarve-smoke:$STAMP
    # No ports: internal networks publish no host port (Docker 29 suppresses
    # the mapping), so a requested mapping would only create claim/safety
    # portability ambiguity. Loopback exposure is asserted independently on
    # the persistent bridge profile.
    env_file:
      - path: $WORK/smoke.env
        required: true
    environment:
      AI_ENABLED: "false"
      MODEL_API_KEY: ""
      MODEL_DATA_POLICY_VERIFIED: "false"
      MODEL_ALLOW_REAL_DATA: "false"
      DATABASE_PATH: /data/smoke.sqlite3
      APP_BASE_URL: http://app:8080
      EXTERNAL_API_ENABLED: "true"
    volumes:
      - smoke-data:/data
      - $WORK/export/tests/fixtures/combined/t8_smoke.txt:/logs/smoke-access.log:ro
    networks:
      - smoke-net
volumes:
  smoke-data:
networks:
  smoke-net:
    internal: true
EOF
compose up -d

# Identify the network by Compose labels, never by a guessed hyphen/underscore
# name, then inspect its real ID. A failed isolation proof aborts the run:
# continuing without offline containment would void every later claim.
net_id=$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.network=smoke-net" | head -n 1)
if [ -z "$net_id" ]; then
  echo "smoke network not found by label; refusing to continue without isolation proof" >&2
  exit 1
fi
net_internal=$(docker network inspect "$net_id" --format '{{.Internal}}')
if [ "$net_internal" = "true" ]; then
  good "smoke network $net_id is internal (offline proof)"
else
  echo "smoke network $net_id is NOT internal; refusing to continue" >&2
  exit 1
fi

# Startup wait runs inside the network: the host cannot reach the stack.
if offline_probe --wait; then
  good "stack healthy inside isolated network (ai_enabled=false)"
else
  echo "smoke stack did not start" >&2; exit 1
fi

echo "== execution identity and mounts =="
uid=$(compose run --rm --no-deps -T app id -u)
[ "$uid" != "0" ] && good "container runs non-root (uid $uid)" || bad "container runs as root"
# The source must stay immutable: never probe with a write, not even touch.
# Inspect the live mount table instead and prove RW == false for the log mount.
app_id=$(docker ps -q --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=app" | head -n 1)
[ -n "$app_id" ] || { echo "smoke app container not found by label" >&2; exit 1; }
docker inspect "$app_id" --format '{{json .Mounts}}' \
  | python3 -c 'import json,sys; mounts = json.load(sys.stdin); log = [m for m in mounts if m["Destination"] == "/logs/smoke-access.log"]; assert log and log[0]["RW"] is False, mounts'
good "source mount is read-only (Mounts RW false, no write attempted)"
# No host port binding exists on an internal network by design (Docker 29
# suppresses publishing); loopback-only exposure is asserted on the
# persistent demo bridge profile instead. Nothing to check here.
note "no host port published (internal network by design; see demo profile)"

echo "== seed (private one-offs, nothing printed) =="
run() { compose run --rm --no-deps -T app "$@"; }
run python -m app.auth.cli --db /data/smoke.sqlite3 create-admin --username smoke-admin >/dev/null
good "admin created (password never shown)"
import_json=$(run python -m app.db.cli --db /data/smoke.sqlite3 import \
  --source-id example-combined --format nginx_combined --root /logs --path smoke-access.log \
  --site-id default --site-name "Smoke site" --site-hostname example.org --server-type nginx)
echo "$import_json" | python3 -c 'import json,sys; d = json.load(sys.stdin); assert (d["status"], d["records_inserted"]) == ("completed", 30), d'
good "import 30 rows, completed"
replay_json=$(run python -m app.db.cli --db /data/smoke.sqlite3 import \
  --source-id example-combined --format nginx_combined --root /logs --path smoke-access.log \
  --site-id default --site-name "Smoke site" --site-hostname example.org --server-type nginx)
echo "$replay_json" | python3 -c 'import json,sys; d = json.load(sys.stdin); assert (d["records_inserted"], d["records_replayed"]) == (0, 30), d'
good "replay adds zero rows"
container_sha=$(compose exec -T app sha256sum /logs/smoke-access.log | cut -d' ' -f1)
[ "$container_sha" = "$FIXTURE_SHA" ] && good "source sha matches authoritative digest" \
  || bad "source sha mismatch ($container_sha)"
# -c keeps code in argv so stdin stays the token-JSON pipe.
run python -m app.auth.cli --db /data/smoke.sqlite3 issue-token \
  --name smoke-client --site-id default --scopes analytics:read \
  | python3 -c 'import json, os, sys; fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); token = (json.load(sys.stdin)["token"] + "\n").encode("utf-8"); os.write(fd, token); os.close(fd)' \
  "$WORK/token.txt"
chmod 0600 "$WORK/token.txt"
good "scoped token issued to protected file"

echo "== offline probe: readiness, client, chat guard (inside network) =="
# Store is migrated now, so the 401 gating proof is valid (pre-migration the
# endpoint answers 503, which would mask the distinction).
if probe_out=$(offline_probe); then
  echo "$probe_out"
  good "offline probe: liveness, 401 gating, private readyz, client 30 rows, chat guard"
else
  echo "${probe_out:-offline probe produced no output}"
  bad "offline probe failed"
fi

echo "== restart persistence =="
compose restart app
if probe_out=$(offline_probe --wait && offline_probe); then
  echo "$probe_out"
  good "30 rows survive restart (in-network re-verified)"
else
  echo "${probe_out:-offline probe produced no output after restart}"
  bad "post-restart probe failed"
fi

echo "== backup / isolated restore / retention =="
backup_json=$(run python -m app.db.cli --db /data/smoke.sqlite3 backup --dest-dir /data/backups --keep 2)
backup_path=$(echo "$backup_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["backup"])')
[ -n "$backup_path" ] && good "backup created" || bad "backup missing"
mode=$(compose exec -T app stat -c %a "$backup_path")
[ "$mode" = "600" ] && good "backup permissions 0600" || bad "backup permissions $mode"
# Restore AND verify in the SAME ephemeral container: /tmp is per-container,
# so a split run/exec pair would assert a file that no longer exists.
run sh -c "python -m app.db.cli --db /data/smoke.sqlite3 restore --backup '$backup_path' --dest /tmp/smoke-restored.sqlite3 --retention-days 30 && python -c \"import sqlite3; c = sqlite3.connect('file:/tmp/smoke-restored.sqlite3?mode=ro', uri=True); assert c.execute('SELECT COUNT(*) FROM requests').fetchone()[0] == 30; assert c.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'\""
good "isolated restore: 30 rows, integrity ok, retention reapplied in restore"
retention_json=$(run python -m app.db.cli --db /data/smoke.sqlite3 retention --days 30)
echo "$retention_json" | python3 -c 'import json,sys; assert json.load(sys.stdin)["deleted"] == 0, "retention deleted rows"'
good "retention --days 30 deletes nothing (all rows in window)"
container_sha_after=$(compose exec -T app sha256sum /logs/smoke-access.log | cut -d' ' -f1)
[ "$container_sha_after" = "$FIXTURE_SHA" ] && good "source still unchanged after retention" \
  || bad "source changed after retention"
src_stat_after=$(python3 -c 'import os,sys; st = os.stat(sys.argv[1]); print(st.st_size, int(st.st_mtime))' \
  "$WORK/export/tests/fixtures/combined/t8_smoke.txt")
[ "$src_stat_after" = "$src_stat_before" ] && good "source size/mtime unchanged" \
  || bad "source stat changed ($src_stat_before -> $src_stat_after)"

echo "== teardown (owned resources only) =="
compose down -v
trap 'rm -rf "$WORK"' EXIT INT TERM
# Empty-output tests (wc -l padding breaks numeric comparison across platforms).
[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ] \
  && good "no smoke containers remain (running or stopped)" \
  || bad "smoke containers remain"
[ -z "$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")" ] \
  && good "no smoke networks remain" || bad "smoke networks remain"
[ -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ] \
  && good "no smoke volumes remain" || bad "smoke volumes remain"
if [ -n "$demo_was_running" ]; then
  if docker compose -p logcarve-demo ps --status running 2>/dev/null | grep -q app; then
    good "persistent demo still running (untouched)"
  else
    bad "persistent demo stopped during smoke"
  fi
else
  note "demo project was not running (left as found)"
fi

echo "== SEPARATE (persistent demo, not this stack): browser/layout =="
note "Static file existence cannot prove a correct Tailwind build. Browser"
note "proof runs against the persistent loopback demo (bridge network, host"
note "reachable), never against this internal-only stack, and is recorded in"
note "docs/verification.md before any release claim:"
note "  ./scripts/demo/health.sh  # persistent demo on 127.0.0.1:8080"
note "  uv run --locked pytest tests/e2e -q"

echo "smoke result: $pass passed, $fail failed"
[ "$fail" = "0" ]
