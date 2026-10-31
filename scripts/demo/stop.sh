#!/bin/sh
# Stop the demo containers but KEEP all data. Never uses down -v.
set -eu

# shellcheck disable=SC1091
. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

compose stop
echo "stopped (data preserved). Restart with ./scripts/demo/start.sh"
