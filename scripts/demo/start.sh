#!/bin/sh
# Build, start, and seed the persistent demo. Idempotent: safe to re-run.
# Never removes volumes; seeding preserves existing users/tokens/history.
set -eu

# shellcheck disable=SC1091
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

need_file "$DEMO_ENV_FILE"

compose build
compose up -d

deadline=$(( $(date +%s) + 90 ))
until curl -sf "$DEMO_BASE_URL/healthz" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "demo did not become healthy in 90s" >&2
    compose ps
    exit 1
  fi
  sleep 2
done
echo "healthy: $DEMO_BASE_URL/healthz"

sh "$DEMO_ROOT/scripts/demo/seed.sh"

echo "entry: $DEMO_ENTRY_URL"
echo "posture: $(demo_posture)"
