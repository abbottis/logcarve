#!/bin/sh
# Shared demo helpers. POSIX sh, no secrets on stdout, no network probes.
set -eu

DEMO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DEMO_PROJECT="logcarve-demo"
DEMO_COMPOSE_FILE="$DEMO_ROOT/docker-compose.demo.yml"
DEMO_SECRET_DIR="$DEMO_ROOT/artifacts/local-demo-secrets"
DEMO_ENV_FILE="$DEMO_SECRET_DIR/demo.env"
DEMO_TOKEN_FILE="$DEMO_SECRET_DIR/demo-token.txt"
DEMO_BASE_URL="http://127.0.0.1:8080"
DEMO_ENTRY_URL="$DEMO_BASE_URL/?site=default&range=custom&from=2026-10-26T00:00:00%2B00:00&to=2026-10-29T00:00:00%2B00:00&tz=Europe%2FBerlin&source=example-combined"

compose() {
  docker compose -p "$DEMO_PROJECT" -f "$DEMO_COMPOSE_FILE" "$@"
}

need_file() {
  if [ ! -f "$1" ]; then
    echo "missing required file: $1 (run ./scripts/demo/init.sh first)" >&2
    exit 1
  fi
}

# Refuse symlink paths before creating or trusting protected files:
# -f/-e tests follow links and .tmp/mv would clobber through them.
refuse_symlink() {
  if [ -L "$1" ]; then
    echo "refusing symlinked path: $1" >&2
    exit 1
  fi
}

# Create a directory at or under DEMO_ROOT, refusing symlinked parents.
# Fresh tracked exports have no ignored artifacts/ tree, so parents may be
# missing entirely; plain `mkdir` (no -p) is used level by level so a link
# can never be followed or chmodded through.
ensure_dir() {
  case "$1" in
    "$DEMO_ROOT" | "$DEMO_ROOT"/*) ;;
    *) echo "refusing path outside workspace: $1" >&2; exit 1 ;;
  esac
  if [ "$1" != "$DEMO_ROOT" ]; then
    ensure_dir "$(dirname -- "$1")"
  fi
  refuse_symlink "$1"
  if [ ! -e "$1" ]; then
    mkdir "$1"
  elif [ ! -d "$1" ]; then
    echo "refusing: $1 exists and is not a directory" >&2
    exit 1
  fi
}

# Print VAR=value lines only for fixed non-secret demo posture (never secrets).
demo_posture() {
  echo "AI_ENABLED=false MODEL_API_KEY=<empty> MODEL_DATA_POLICY_VERIFIED=false MODEL_ALLOW_REAL_DATA=false"
}
