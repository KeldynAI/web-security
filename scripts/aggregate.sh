#!/usr/bin/env bash
#
# Step 3 of 4: normalise every scanner's output into one report.
#
# This step deliberately succeeds even when security findings exist: it writes
# report.json, the job summary and the Action outputs, and records the verdict.
# scripts/enforce.sh then turns that verdict into the step's exit status.
#
# Splitting the two means the Action's outputs are always populated, including
# on a failing run, so a consumer's later steps can read them.

# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

main() {
  ws::cli aggregate
}

main "$@"
