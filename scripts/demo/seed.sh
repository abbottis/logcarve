#!/bin/sh
# Idempotent verified synthetic seeder for the persistent demo (and reset).
#
# Safety contract (violations abort with exit 1 before any mutation):
# - Verifies the store BEFORE writing: FRESH/PARTIAL demo stores are seeded,
#   SEEDED stores only re-import (replay-zero proof), FOREIGN stores
#   (unknown sites/sources/rows/fingerprints) are refused untouched.
# - Preserves users, tokens, import history, ai_spend and smoke counters:
#   only missing admin/token/rows are created, nothing is deleted, no
#   ledger is restored, no allowance is renewed.
# - Source logs are read-only: imports read /logs/demo-access.log, never
#   edit, truncate, move, or delete it.
# - No secret/token plaintext on stdout: the issued demo token goes only to
#   artifacts/local-demo-secrets/demo-token.txt (0600).
set -eu

# shellcheck disable=SC1091
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

need_file "$DEMO_ENV_FILE"

# The probe is a tracked file (ruff/py_compile gated), piped over stdin so
# the image needs no extra copy; inline heredoc Python is banned here after
# a top-level-return SyntaxError slipped through uncompiled.
probe() {
  compose run --rm --no-deps -T app python - <"$DEMO_ROOT/scripts/demo/probe_store.py"
}

DB_PATH="/data/logcarve-demo.sqlite3"
ADMIN_USER="demo-admin"

verdict_json=$(probe)
verdict=$(printf '%s' "$verdict_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])')
echo "store: $verdict_json" >&2

case "$verdict" in
  FOREIGN)
    echo "refusing foreign store: seed only the verified synthetic demo dataset" >&2
    exit 1
    ;;
  PARTIAL | FRESH)
    users=$(printf '%s' "$verdict_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("users", 0))')
    if [ "$users" = "0" ]; then
      # create-admin also runs pending migrations on a fresh store.
      compose run --rm --no-deps -T app python -m app.auth.cli --db "$DB_PATH" \
        create-admin --username "$ADMIN_USER" >/dev/null
      echo "admin created: $ADMIN_USER (password in demo.env, not shown)"
    else
      echo "admin present, kept"
    fi
    import_json=$(compose run --rm --no-deps -T app python -m app.db.cli --db "$DB_PATH" import \
      --source-id example-combined --format nginx_combined \
      --root /logs --path demo-access.log \
      --site-id default --site-name "Demo site" --site-hostname example.org \
      --server-type nginx)
    echo "import: $import_json"
    status=$(printf '%s' "$import_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
    if [ "$status" != "completed" ]; then
      echo "import did not complete" >&2
      exit 1
    fi
    has_token=$(printf '%s' "$verdict_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("demo_token", 0))')
    refuse_symlink "$DEMO_TOKEN_FILE"
    if [ "$has_token" != "0" ] && [ -e "$DEMO_TOKEN_FILE" ]; then
      echo "token present, existing bytes preserved"
    elif [ "$has_token" = "0" ] && [ ! -e "$DEMO_TOKEN_FILE" ]; then
      # -c keeps code in argv so stdin stays the token-JSON pipe (a
      # `python - ... <<EOF` heredoc would steal stdin for code instead).
      compose run --rm --no-deps -T app python -m app.auth.cli --db "$DB_PATH" issue-token \
        --name demo-client --site-id default --scopes analytics:read \
        | python3 -c 'import json, os, sys; fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); token = (json.load(sys.stdin)["token"] + "\n").encode("utf-8"); os.write(fd, token); os.close(fd)' \
        "$DEMO_TOKEN_FILE"
      echo "token issued: $DEMO_TOKEN_FILE (0600 exclusive, plaintext never shown)"
    else
      echo "token file and database disagree: remove $DEMO_TOKEN_FILE explicitly to issue a fresh token, then re-run" >&2
      exit 1
    fi
    ;;
  SEEDED)
    import_json=$(compose run --rm --no-deps -T app python -m app.db.cli --db "$DB_PATH" import \
      --source-id example-combined --format nginx_combined \
      --root /logs --path demo-access.log \
      --site-id default --site-name "Demo site" --site-hostname example.org \
      --server-type nginx)
    echo "re-import: $import_json"
    replay=$(printf '%s' "$import_json" | python3 -c 'import json,sys; d = json.load(sys.stdin); print(d["records_inserted"], d["records_replayed"])')
    if [ "$replay" != "0 30" ]; then
      echo "expected idempotent replay (0 inserted, 30 replayed), got: $replay" >&2
      exit 1
    fi
    echo "reseed verified: replay-zero, history preserved"
    # Recover an interrupted first init (rows landed but the token step never
    # ran): a SEEDED store with no demo-client token is repaired, not kept.
    has_token=$(printf '%s' "$verdict_json" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("demo_token", 0))')
    refuse_symlink "$DEMO_TOKEN_FILE"
    if [ "$has_token" != "0" ] && [ -e "$DEMO_TOKEN_FILE" ]; then
      echo "token present, existing bytes preserved"
    elif [ "$has_token" = "0" ] && [ ! -e "$DEMO_TOKEN_FILE" ]; then
      compose run --rm --no-deps -T app python -m app.auth.cli --db "$DB_PATH" issue-token \
        --name demo-client --site-id default --scopes analytics:read \
        | python3 -c 'import json, os, sys; fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); token = (json.load(sys.stdin)["token"] + "\n").encode("utf-8"); os.write(fd, token); os.close(fd)' \
        "$DEMO_TOKEN_FILE"
      echo "recovered missing demo token: $DEMO_TOKEN_FILE (0600 exclusive)"
    else
      echo "token file and database disagree: remove $DEMO_TOKEN_FILE explicitly to issue a fresh token, then re-run" >&2
      exit 1
    fi
    ;;
esac

final=$(probe)
final_verdict=$(printf '%s' "$final" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verdict"])')
if [ "$final_verdict" != "SEEDED" ]; then
  echo "seed did not converge: $final" >&2
  exit 1
fi
echo "seeded: $final"
