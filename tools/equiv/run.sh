#!/bin/sh
# Convenience wrapper for the equivalence harness.
#
#   ./run.sh baseline         # run every scenario twice against the vendor stack
#   ./run.sh determinism      # strict run1-vs-run2 gate for the vendor baseline
#   ./run.sh compare recon    # vendor baseline vs runs/recon
#   ./run.sh contract         # print the 116-row observable contract
#   ./run.sh coverage         # which contract rows the suite exercises
#   ./run.sh selftest         # prove the comparator detects a one-value change
set -eu
cd "$(dirname "$0")"
case "${1:-}" in
  baseline)
    python3 -m harness.run run --target targets/vendor.json --scenario all --repeat 2
    ;;
  determinism)
    python3 -m harness.run determinism --target vendor
    ;;
  compare)
    python3 -m harness.run compare --baseline vendor --candidate "${2:?candidate name required}"
    ;;
  contract)
    python3 -m harness.run contract
    ;;
  coverage)
    python3 -m harness.run coverage
    ;;
  selftest)
    python3 tools/selftest.py
    ;;
  *)
    sed -n '2,9p' "$0"
    exit 2
    ;;
esac
