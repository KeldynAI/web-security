# shellcheck shell=bash
#
# Shared shell helpers for keldynai/web-security.
#
# Every script sources this file and therefore runs under `set -Eeuo pipefail`:
# an unset variable or a failing command in a security scanner must abort the
# step rather than continue with half a result.
#
# Conventions used throughout the shell layer:
#   - Repository content and Action inputs are untrusted. They are passed
#     through environment variables and always quoted; no value is ever
#     concatenated into a command string, and `eval` is never used.
#   - Scanner arguments are built in Bash arrays, so a path containing spaces
#     stays a single argument.
#   - Scanner scripts do not decide pass/fail. They record an outcome and
#     leave raw output for the aggregation step.

set -Eeuo pipefail

# Resolve the Action's own directory (…/scripts/lib/common.sh -> …).
WEB_SECURITY_ACTION_ROOT="${WEB_SECURITY_ACTION_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
readonly WEB_SECURITY_ACTION_ROOT

# Directories that only ever add noise to a source-code scan.
# shellcheck disable=SC2034 # read by the scanner scripts that source this file
readonly WEB_SECURITY_EXCLUDED_DIRS=(
  node_modules
  bower_components
  vendor
  dist
  build
  out
  coverage
  .git
  .next
  .nuxt
  .svelte-kit
  .astro
  .angular
  .output
  .turbo
  .nx
  .cache
  .parcel-cache
  .yarn
  .pnpm-store
  .terraform
  .venv
  venv
  __pycache__
)

ws::log() { printf '%s\n' "$*"; }

ws::warn() { printf 'Web Security: warning: %s\n' "$*" >&2; }

ws::error() { printf 'Web Security: error: %s\n' "$*" >&2; }

# Aborts the step. Used only for conditions that make scanning impossible
# (missing interpreter, unsupported runner), never for scanner findings.
ws::fail() {
  ws::error "$*"
  exit 1
}

ws::group() { printf '::group::%s\n' "$*"; }

ws::endgroup() { printf '::endgroup::\n'; }

ws::require_cmd() {
  local cmd="$1"
  local hint="${2-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    ws::fail "required command '${cmd}' was not found on this runner.${hint:+ ${hint}}"
  fi
}

ws::state_dir() {
  printf '%s' "${WEB_SECURITY_STATE:?WEB_SECURITY_STATE is not set; Action steps ran out of order}"
}

ws::bin_dir() {
  printf '%s/bin' "$(ws::state_dir)"
}

ws::raw_dir() {
  printf '%s/raw' "$(ws::state_dir)"
}

# Runs the Node CLI. Node ships with every GitHub-hosted runner, so this adds
# no download and no third-party dependency.
ws::cli() {
  node "${WEB_SECURITY_ACTION_ROOT}/src/cli.mjs" "$@"
}

# Records a scanner outcome. Free-form tool output is passed by file so that it
# can never be interpreted as an argument.
#   ws::record_status <scanner> <state> <exit-code> <message-file|""> [tool] [version]
ws::record_status() {
  local scanner="$1" state="$2" exit_code="$3" message_file="${4-}" tool="${5-}" version="${6-}"
  local args=(record-status "--scanner=${scanner}" "--state=${state}" "--exit-code=${exit_code}")
  [[ -n "${message_file}" && -s "${message_file}" ]] && args+=("--message-file=${message_file}")
  [[ -n "${tool}" ]] && args+=("--tool=${tool}")
  [[ -n "${version}" ]] && args+=("--version=${version}")
  ws::cli "${args[@]}"
}

# Creates a private temporary directory that is removed when the script exits.
# `mktemp -d` keeps the path unpredictable, so no other process on the runner
# can pre-create or swap our scanner output files.
ws::make_temp_dir() {
  local template="${RUNNER_TEMP:-/tmp}/web-security.XXXXXXXXXX"
  mktemp -d "${template}"
}

# Runs a scanner with a wall-clock limit so a pathological repository cannot
# hang a pull-request job until the runner is killed.
#   ws::with_timeout <seconds> <command...>
ws::with_timeout() {
  local seconds="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout --kill-after=15s "${seconds}s" "$@"
  else
    "$@"
  fi
}

# Extracts a version number from arbitrary `--version` output. The result is
# reduced to a safe character set because it is written into JSON and logs.
ws::clean_version() {
  printf '%s' "$1" | tr -cd '0-9A-Za-z.+-' | cut -c1-40
}
