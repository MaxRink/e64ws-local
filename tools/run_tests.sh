#!/bin/sh
# Repository-wide test entry point.
#
#   sh tools/run_tests.sh            # run every offline suite
#   sh tools/run_tests.sh --verbose  # also print passing suite output
#
# Uses only the Python standard library.  Set PYTHON to pick an interpreter,
# for example: PYTHON=python3.11 sh tools/run_tests.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${PYTHON:-python3}

exec "$PYTHON" "$HERE/run_tests.py" "$@"
