#!/usr/bin/env bash
#
# Trivy: dependency vulnerabilities, IaC/configuration misconfiguration and
# (optionally) secrets, in one filesystem scan.
#
# Trivy is a primary scanner here, not an add-on: it is the only tool in the
# set that covers Dockerfiles, Kubernetes manifests, Terraform, Helm and
# lockfiles for ecosystems beyond npm, and its vulnerability database is
# updated continuously.
#
# Two deliberate isolation decisions, because repository content is
# attacker-controlled on a pull request:
#   --config     points at an empty file, so a `trivy.yaml` committed to the
#                repository cannot silently reconfigure or weaken the scan.
#   --ignorefile points at an empty file, so a `.trivyignore` cannot suppress
#                findings without the justification this Action requires.
# Suppression happens later, from the justified ignore file only.
#
# Trivy's own exit code is forced to 0 (`--exit-code 0`): the aggregation step
# decides pass/fail after suppressions are applied. A non-zero exit therefore
# means Trivy itself failed, which is reported as ERROR.

# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

readonly TRIVY_TIMEOUT_SECONDS=900

main() {
  local scan_path="${WEB_SECURITY_SCAN_PATH:?WEB_SECURITY_SCAN_PATH is not set}"
  local severities="${WEB_SECURITY_TRIVY_SEVERITY:?WEB_SECURITY_TRIVY_SEVERITY is not set}"
  local scanners="${WEB_SECURITY_TRIVY_SCANNERS:?WEB_SECURITY_TRIVY_SCANNERS is not set}"

  local state_dir bin_dir raw_dir tmp_dir
  state_dir="$(ws::state_dir)"
  bin_dir="$(ws::bin_dir)"
  raw_dir="$(ws::raw_dir)"
  tmp_dir="$(ws::make_temp_dir)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp_dir}'" EXIT

  local trivy="${bin_dir}/trivy"
  if [[ ! -x "${trivy}" ]]; then
    printf 'the pinned Trivy binary is missing; the install step did not complete.\n' > "${tmp_dir}/error"
    ws::record_status trivy error 1 "${tmp_dir}/error" trivy ""
    return 0
  fi

  # Empty stand-ins that neutralise repository-provided Trivy configuration.
  : > "${tmp_dir}/trivy-config.yaml"
  : > "${tmp_dir}/trivyignore"

  local -a skip_args=()
  local excluded
  for excluded in "${WEB_SECURITY_EXCLUDED_DIRS[@]}"; do
    skip_args+=(--skip-dirs "**/${excluded}")
  done

  local -a args=(
    fs .
    --scanners "${scanners}"
    --severity "${severities}"
    --format json
    --output "${raw_dir}/trivy.json"
    --config "${tmp_dir}/trivy-config.yaml"
    --ignorefile "${tmp_dir}/trivyignore"
    --cache-dir "${state_dir}/trivy-cache"
    --exit-code 0
    --no-progress
    --disable-telemetry
    # Keep the JSON report about findings rather than a full package inventory.
    --list-all-pkgs=false
    # Match `npm audit`, which reports devDependencies by default, so the two
    # scanners agree on scope and their findings can be merged.
    --include-dev-deps
    # Trivy's own timeout is shorter than the wall-clock limit below, so it
    # gets the chance to exit with a useful message instead of being killed.
    --timeout "$(((TRIVY_TIMEOUT_SECONDS - 60) / 60))m"
  )
  args+=("${skip_args[@]}")

  ws::group "Trivy: scanning ${scan_path} (scanners: ${scanners}; severity: ${severities})"

  local exit_code=0
  # Running from inside the scan path keeps every reported target relative.
  (
    cd "${scan_path}" || exit 3
    ws::with_timeout "${TRIVY_TIMEOUT_SECONDS}" "${trivy}" "${args[@]}"
  ) > "${tmp_dir}/stdout" 2> "${tmp_dir}/stderr" || exit_code=$?

  # Trivy logs progress and database updates to stderr; it is worth showing.
  cat "${tmp_dir}/stdout"
  cat "${tmp_dir}/stderr" >&2
  ws::endgroup

  if [[ "${exit_code}" -ne 0 ]]; then
    if [[ "${exit_code}" -eq 124 || "${exit_code}" -eq 137 ]]; then
      printf 'Trivy timed out after %s seconds.\n' "${TRIVY_TIMEOUT_SECONDS}" > "${tmp_dir}/error"
    else
      printf 'Trivy exited with status %s.\n' "${exit_code}" > "${tmp_dir}/error"
      tail -n 12 "${tmp_dir}/stderr" >> "${tmp_dir}/error" 2>/dev/null || true
    fi
    ws::record_status trivy error "${exit_code}" "${tmp_dir}/error" trivy ""
    return 0
  fi

  if [[ ! -s "${raw_dir}/trivy.json" ]]; then
    printf 'Trivy reported success but wrote no JSON report.\n' > "${tmp_dir}/error"
    ws::record_status trivy error 1 "${tmp_dir}/error" trivy ""
    return 0
  fi

  ws::record_status trivy ok 0 "" trivy ""
}

main "$@"
