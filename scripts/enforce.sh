#!/usr/bin/env bash
#
# Step 4 of 4: turn the recorded verdict into the Action's exit status.
#
#   pass   0   no actionable findings at or above the severity threshold
#   fail   1   actionable findings remain after justified suppressions
#   error  1   a scanner could not run (unless fail-on-error is false)
#
# A missing or unreadable verdict file is also a failure: this Action must
# never report success because its own bookkeeping went missing.

# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

main() {
  local result_file
  result_file="$(ws::state_dir)/result.json"

  if [[ ! -s "${result_file}" ]]; then
    ws::fail "the aggregation step did not record a result. This is a bug in keldynai/web-security; please report it with the job log."
  fi

  local result reason
  # Read through Node rather than parsing JSON in shell.
  result="$(node -e 'const fs=require("node:fs");process.stdout.write(String(JSON.parse(fs.readFileSync(process.argv[1],"utf8")).result??""))' "${result_file}")"
  reason="$(node -e 'const fs=require("node:fs");process.stdout.write(String(JSON.parse(fs.readFileSync(process.argv[1],"utf8")).reason??""))' "${result_file}")"

  case "${result}" in
    pass)
      ws::log "Web Security: PASS. ${reason}."
      return 0
      ;;
    fail)
      ws::error "FAIL: ${reason}."
      ws::error "Fix the findings above, or add a justified entry to the ignore file (see the suggested snippet for each finding)."
      return 1
      ;;
    error)
      ws::error "ERROR: ${reason}."
      ws::error "One or more scanners could not run, so this repository was not fully scanned."
      return 1
      ;;
    *)
      ws::fail "unrecognised result '${result}' recorded by the aggregation step."
      ;;
  esac
}

main "$@"
