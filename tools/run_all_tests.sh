#!/bin/sh
# Deprecated alias kept so older notes and scripts keep working.
# The canonical entry point is tools/run_tests.sh.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$HERE/run_tests.sh" "$@"
