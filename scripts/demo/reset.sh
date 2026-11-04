#!/bin/sh
# Nondestructive verified reseed of the persistent demo.
#
# Runs the idempotent seeder (replay-zero on a SEEDED store) and restarts
# the service so the dashboard picks up the verified state. Explicitly:
# - never `down -v` the persistent demo volume,
# - never restores an old usage ledger or renews any allowance,
# - never edits, truncates, moves, or deletes source logs,
# - refuses FOREIGN stores untouched.
set -eu

# shellcheck disable=SC1091
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

need_file "$DEMO_ENV_FILE"

sh "$DEMO_ROOT/scripts/demo/seed.sh"
compose restart app

deadline=$(( $(date +%s) + 60 ))
until curl -sf "$DEMO_BASE_URL/healthz" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "demo did not recover in 60s" >&2
    exit 1
  fi
  sleep 2
done
echo "reset complete (nondestructive): $DEMO_ENTRY_URL"
