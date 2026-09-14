#!/usr/bin/env bash
#
# SAST with Semgrep Community Edition.
#
# Why Semgrep CE: it is open source, runs entirely locally, needs no account or
# API token, has by far the best maintained JavaScript/TypeScript security
# rule coverage of the OSS scanners, and its rule packs are versioned content
# rather than a proprietary engine.
#
# Default rule packs (see README for the rationale):
#   p/javascript      JS/TS/React/Express/Angular application security
#   p/nodejsscan      Node-specific: eval/vm injection, OS command execution,
#                     weak crypto, insecure randomness, deserialisation, ReDoS
#   p/github-actions  insecure workflow patterns, script injection in ${{ }}
#
# Hardening notes:
#   --metrics=off        no telemetry leaves the runner.
#   --disable-nosem      `// nosemgrep` comments in repository code do not
#                        suppress findings; suppression must go through the
#                        justified ignore file. Probed before use so a future
#                        Semgrep release cannot break the step.
#   --no-git-ignore      scan coverage is not controlled by .gitignore, since a
#                        committed-but-ignored file would otherwise be skipped.

# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

readonly SAST_TIMEOUT_SECONDS=900

readonly DEFAULT_SEMGREP_CONFIGS=(
  "p/javascript"
  "p/nodejsscan"
  "p/github-actions"
)

# Returns success when `semgrep scan --help` advertises the given flag.
semgrep_supports() {
  local semgrep="$1" flag="$2"
  "${semgrep}" scan --help 2>/dev/null | grep -q -- "${flag}"
}

# Runs Semgrep from the scan root, capturing its streams.
#   semgrep_run <semgrep> <scan-path> <state-dir> <tmp-dir> <args...>
semgrep_run() {
  local semgrep="$1" scan_path="$2" state_dir="$3" tmp_dir="$4"
  shift 4

  (
    cd "${scan_path}" || exit 3
    # Keep Semgrep's settings and caches inside the Action's state directory so
    # it does not write into the runner's home directory, and switch off every
    # outbound call that is not a rule download.
    export SEMGREP_SETTINGS_FILE="${state_dir}/semgrep-settings.yml"
    export SEMGREP_VERSION_CACHE_PATH="${state_dir}/semgrep-version-cache"
    export SEMGREP_ENABLE_VERSION_CHECK=0
    export SEMGREP_SEND_METRICS=off
    ws::with_timeout "${SAST_TIMEOUT_SECONDS}" "${semgrep}" "$@"
  ) > "${tmp_dir}/stdout" 2> "${tmp_dir}/stderr"
}

main() {
  local scan_path="${WEB_SECURITY_SCAN_PATH:?WEB_SECURITY_SCAN_PATH is not set}"
  local extra_configs="${WEB_SECURITY_SAST_CONFIG:-}"

  local bin_dir raw_dir tmp_dir state_dir
  bin_dir="$(ws::bin_dir)"
  raw_dir="$(ws::raw_dir)"
  state_dir="$(ws::state_dir)"
  tmp_dir="$(ws::make_temp_dir)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp_dir}'" EXIT

  local semgrep="${bin_dir}/semgrep"
  if [[ ! -x "${semgrep}" ]]; then
    printf 'the pinned Semgrep installation is missing; the install step did not complete.\n' > "${tmp_dir}/error"
    ws::record_status sast error 1 "${tmp_dir}/error" semgrep ""
    return 0
  fi

  local -a args=(scan --json --output "${raw_dir}/semgrep.json" --metrics=off --quiet)

  local config
  for config in "${DEFAULT_SEMGREP_CONFIGS[@]}"; do
    args+=(--config "${config}")
  done
  # Consumer-supplied configs are validated in preflight against a strict
  # character allowlist, so they cannot smuggle in another CLI flag.
  if [[ -n "${extra_configs}" ]]; then
    # shellcheck disable=SC2206 # deliberate word splitting of a validated list
    local -a extra=(${extra_configs//,/ })
    for config in "${extra[@]}"; do
      [[ -z "${config}" ]] && continue
      args+=(--config "${config}")
    done
  fi

  local excluded
  for excluded in "${WEB_SECURITY_EXCLUDED_DIRS[@]}"; do
    args+=(--exclude "${excluded}")
  done

  if semgrep_supports "${semgrep}" "--disable-nosem"; then
    args+=(--disable-nosem)
  else
    ws::warn "this Semgrep build does not support --disable-nosem; '// nosemgrep' comments in repository code will suppress findings outside this Action's justification policy."
  fi
  if semgrep_supports "${semgrep}" "--no-git-ignore"; then
    args+=(--no-git-ignore)
  fi

  ws::group "SAST (Semgrep): scanning ${scan_path}"

  local exit_code=0
  semgrep_run "${semgrep}" "${scan_path}" "${state_dir}" "${tmp_dir}" "${args[@]}" || exit_code=$?

  # semgrep-core runs one parallel worker per core and needs locked memory for
  # each. On a memory-constrained runner, or a repository large enough to
  # exhaust it, the engine dies with exit 2 while the CLI still reports a
  # complete scan with zero findings. One serial retry recovers the scan
  # instead of reporting a scanner failure for a repository that can be
  # analysed; it is slower, which is why it is not the default.
  if [[ "${exit_code}" -gt 1 && "${exit_code}" -ne 124 && "${exit_code}" -ne 137 ]]; then
    ws::warn "Semgrep exited with status ${exit_code}; retrying with a single worker (--jobs 1)."
    exit_code=0
    semgrep_run "${semgrep}" "${scan_path}" "${state_dir}" "${tmp_dir}" "${args[@]}" --jobs 1 \
      || exit_code=$?
  fi

  cat "${tmp_dir}/stdout"
  tail -n 40 "${tmp_dir}/stderr" >&2 || true
  ws::endgroup

  # Semgrep exits 0 when it completed and 1 when it completed with findings
  # (only with --error, which is not used here). Anything else is a failure of
  # the scanner itself.
  if [[ "${exit_code}" -gt 1 ]]; then
    if [[ "${exit_code}" -eq 124 || "${exit_code}" -eq 137 ]]; then
      printf 'Semgrep timed out after %s seconds.\n' "${SAST_TIMEOUT_SECONDS}" > "${tmp_dir}/error"
    else
      printf 'Semgrep exited with status %s.\n' "${exit_code}" > "${tmp_dir}/error"
      tail -n 12 "${tmp_dir}/stderr" >> "${tmp_dir}/error" 2>/dev/null || true
    fi
    ws::record_status sast error "${exit_code}" "${tmp_dir}/error" semgrep ""
    return 0
  fi

  if [[ ! -s "${raw_dir}/semgrep.json" ]]; then
    printf 'Semgrep reported success but wrote no JSON report. Check that the rule packs could be downloaded from semgrep.dev.\n' > "${tmp_dir}/error"
    ws::record_status sast error 1 "${tmp_dir}/error" semgrep ""
    return 0
  fi

  # Semgrep can exit successfully having written the placeholder
  # "<ERROR: missing output>" into its report instead of JSON, which happens
  # when its engine died. Treating that as a completed scan would report PASS
  # for a repository that was never analysed.
  if [[ "$(head -c 1 "${raw_dir}/semgrep.json")" != "{" ]]; then
    printf 'Semgrep wrote no usable report: its output is not JSON, which means the scan did not complete. This is usually the engine running out of memory on a large repository.\n' \
      > "${tmp_dir}/error"
    tail -n 12 "${tmp_dir}/stderr" >> "${tmp_dir}/error" 2>/dev/null || true
    ws::record_status sast error 1 "${tmp_dir}/error" semgrep ""
    return 0
  fi

  ws::record_status sast ok 0 "" semgrep ""
}

main "$@"
