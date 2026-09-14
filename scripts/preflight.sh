#!/usr/bin/env bash
#
# Step 1 of 4: validate, discover, plan.
#
# This runs before anything is downloaded so that a bad input or an invalid
# ignore file fails in seconds rather than after a scanner install. It also
# creates the private state directory that the remaining steps write into.

# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

main() {
  # Node runs the discovery, validation and reporting logic; the rest are used
  # to install and verify pinned scanner releases.
  ws::require_cmd node "GitHub-hosted runners include Node.js; a self-hosted runner needs Node 20 or newer."
  ws::require_cmd curl
  ws::require_cmd tar
  ws::require_cmd sha256sum "Install coreutils on this runner."

  local node_major
  node_major="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
  if [[ "${node_major}" -lt 20 ]]; then
    ws::fail "Node.js 20 or newer is required (found $(node --version))."
  fi

  case "$(uname -s)" in
    Linux) : ;;
    *)
      ws::fail "this Action currently supports Linux runners only (found $(uname -s)). Use runs-on: ubuntu-latest."
      ;;
  esac

  # A fresh, unpredictable state directory per invocation, so two uses of this
  # Action in one job cannot read each other's results.
  local state_dir
  state_dir="$(ws::make_temp_dir)"
  export WEB_SECURITY_STATE="${state_dir}"
  mkdir -p "${state_dir}/raw" "${state_dir}/status" "${state_dir}/bin"

  ws::cli preflight
}

main "$@"
