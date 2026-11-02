#!/bin/sh
# One-time demo initialization: generate demo-only secrets under ignored
# artifacts/local-demo-secrets/ (directory 0700, files 0600).
#
# - Creates files ONLY when safely absent; existing files (or symlinks at
#   their paths) are never overwritten, followed, rotated, or merged. Delete
#   a file explicitly to regenerate it.
# - Creation is exclusive (O_EXCL): a concurrent init cannot clobber bytes.
# - The existing product MODEL_API_KEY file is never read, copied, or referenced.
# - No Docker, no network, no provider contact.
set -eu

# shellcheck disable=SC1091
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

FIXTURE="$DEMO_ROOT/tests/fixtures/combined/t8_smoke.txt"

ensure_dir "$DEMO_SECRET_DIR"
chmod 0700 "$DEMO_SECRET_DIR"

refuse_symlink "$DEMO_ENV_FILE"
if [ -e "$DEMO_ENV_FILE" ]; then
  echo "already initialized: $DEMO_ENV_FILE exists, existing bytes preserved"
else
  python3 - "$DEMO_ENV_FILE" <<'EOF'
import os
import secrets
import sys

path = sys.argv[1]
lines = (
    f"SESSION_SECRET={secrets.token_hex(32)}\n"
    f"HMAC_KEY={secrets.token_hex(32)}\n"
    f"LOGCARVE_ADMIN_PASSWORD={secrets.token_urlsafe(24)}\n"
)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, lines.encode("utf-8"))
finally:
    os.close(fd)
EOF
  chmod 0600 "$DEMO_ENV_FILE"
  echo "created: $DEMO_ENV_FILE (0600, exclusive)"
fi

refuse_symlink "$DEMO_ORIGINAL_IP_ENV_FILE"
if [ -e "$DEMO_ORIGINAL_IP_ENV_FILE" ]; then
  echo "optional adjunct present, existing bytes preserved: $DEMO_ORIGINAL_IP_ENV_FILE"
else
  echo "optional adjunct absent (ordinary demos stay honestly unavailable): $DEMO_ORIGINAL_IP_ENV_FILE"
fi

# Local geodata directory for the coordinator-owned public MMDB only.
# Created empty when absent; existing files are never overwritten, and no
# example key values or database files are ever written here by this helper.
ensure_dir "$DEMO_GEODATA_DIR"

if [ ! -f "$FIXTURE" ]; then
  echo "missing synthetic fixture: $FIXTURE" >&2
  exit 1
fi
echo "fixture: $FIXTURE"
echo "sha256: $(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$FIXTURE")"
echo "posture: $(demo_posture)"
echo "next: ./scripts/demo/start.sh"
