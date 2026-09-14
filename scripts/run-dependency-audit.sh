#!/usr/bin/env bash
#
# Dependency auditing, once per detected package tree.
#
# Package manager selection comes from the lockfile that is actually present
# (see src/detect.mjs); Yarn repositories are audited with Yarn, not npm.
#
# Nothing is installed and no project lifecycle script runs:
#   npm           `npm audit --package-lock-only` resolves from the lockfile
#   Yarn Classic  `yarn audit` builds its tree from yarn.lock
#   Yarn Berry    `yarn npm audit --all --recursive`
#   pnpm          `pnpm audit`
# `--ignore-scripts` and `YARN_ENABLE_SCRIPTS=false` are set as belt and
# braces, because installing a pull request's dependencies would mean running
# its postinstall scripts on the runner.
#
# Each audit's raw JSON is kept and interpreted later by
# src/normalize/dependency.mjs, which understands all five output formats. The
# exit code is only used to distinguish "ran" from "failed": which findings
# matter is decided after suppressions are applied.

# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

readonly AUDIT_TIMEOUT_SECONDS=300

# Resolved commands for the current project, set by resolve_command().
declare -a AUDIT_COMMAND=()
declare -a AUDIT_VERSION_COMMAND=()
AUDIT_TOOL=""

# Warns when a project reconfigures the registry that the audit will query,
# because audit results come from that registry.
warn_about_custom_registry() {
  local dir="$1"
  local npmrc="${dir}/.npmrc"
  [[ -f "${npmrc}" ]] || return 0
  local line
  if line="$(grep -m1 -E '^[[:space:]]*(@[^:]+:)?registry[[:space:]]*=' "${npmrc}" 2>/dev/null)"; then
    ws::warn "${dir}/.npmrc configures a package registry (${line}). Advisory data for this project comes from that registry, not from npm's public advisory database."
  fi
}

# Chooses how to invoke the package manager for one project.
#
# Corepack is used when the project pins a `packageManager` version, which is
# the only way to honour a Yarn Berry or pnpm version reliably. That does mean
# Corepack downloads the version the repository asks for; the README documents
# this and how to avoid it.
resolve_command() {
  local package_manager="$1" yarn_major="$2" package_manager_field="$3"
  AUDIT_COMMAND=()
  AUDIT_VERSION_COMMAND=()
  AUDIT_TOOL=""

  case "${package_manager}" in
    npm)
      command -v npm >/dev/null 2>&1 || return 1
      AUDIT_TOOL="npm"
      AUDIT_COMMAND=(npm audit --json --package-lock-only --ignore-scripts "--audit-level=${WEB_SECURITY_AUDIT_LEVEL:-high}")
      AUDIT_VERSION_COMMAND=(npm --version)
      ;;

    yarn)
      local installed_major=""
      if command -v yarn >/dev/null 2>&1; then
        installed_major="$(yarn --version 2>/dev/null | cut -d. -f1 || true)"
      fi

      if [[ "${yarn_major}" =~ ^[0-9]+$ ]] && [[ "${yarn_major}" -ge 2 ]]; then
        # Yarn Berry: `yarn npm audit`.
        AUDIT_TOOL="yarn-berry"
        if [[ -n "${package_manager_field}" ]] && command -v corepack >/dev/null 2>&1; then
          AUDIT_COMMAND=(corepack yarn npm audit --all --recursive --json)
          AUDIT_VERSION_COMMAND=(corepack yarn --version)
        elif [[ "${installed_major}" =~ ^[0-9]+$ ]] && [[ "${installed_major}" -ge 2 ]]; then
          AUDIT_COMMAND=(yarn npm audit --all --recursive --json)
          AUDIT_VERSION_COMMAND=(yarn --version)
        elif command -v corepack >/dev/null 2>&1; then
          AUDIT_COMMAND=(corepack yarn npm audit --all --recursive --json)
          AUDIT_VERSION_COMMAND=(corepack yarn --version)
        else
          return 1
        fi
      else
        # Yarn Classic.
        AUDIT_TOOL="yarn-classic"
        if [[ "${installed_major}" == "1" ]]; then
          AUDIT_COMMAND=(yarn audit --json --no-progress)
          AUDIT_VERSION_COMMAND=(yarn --version)
        elif command -v corepack >/dev/null 2>&1; then
          # Pinned rather than "latest 1.x", so the audit tool itself is
          # deterministic when the runner has no Yarn installed.
          AUDIT_COMMAND=(corepack yarn@1.22.22 audit --json --no-progress)
          AUDIT_VERSION_COMMAND=(corepack yarn@1.22.22 --version)
        else
          return 1
        fi
      fi
      ;;

    pnpm)
      AUDIT_TOOL="pnpm"
      if command -v pnpm >/dev/null 2>&1; then
        AUDIT_COMMAND=(pnpm audit --json)
        AUDIT_VERSION_COMMAND=(pnpm --version)
      elif command -v corepack >/dev/null 2>&1; then
        AUDIT_COMMAND=(corepack pnpm audit --json)
        AUDIT_VERSION_COMMAND=(corepack pnpm --version)
      else
        return 1
      fi
      ;;

    *)
      return 1
      ;;
  esac

  return 0
}

# Maps an exit status onto "the audit ran" vs "the audit failed".
audit_ran_successfully() {
  local tool="$1" exit_code="$2"

  case "${exit_code}" in
    124 | 137) return 1 ;; # killed by the wall-clock timeout
  esac

  case "${tool}" in
    yarn-classic)
      # Yarn Classic encodes the severities it found as a bitmask (1..31).
      [[ "${exit_code}" -ge 0 && "${exit_code}" -le 31 ]]
      ;;
    *)
      # npm, Yarn Berry and pnpm: 0 = clean, 1 = vulnerabilities found.
      [[ "${exit_code}" -eq 0 || "${exit_code}" -eq 1 ]]
      ;;
  esac
}

audit_project() {
  local index="$1" dir="$2" package_manager="$3" yarn_major="$4" lockfile="$5" package_manager_field="$6"
  local scan_path="$7" raw_dir="$8" tmp_dir="$9"

  local label="${dir}"
  [[ "${dir}" == "." ]] && label="repository root"

  local project_dir="${scan_path}"
  [[ "${dir}" != "." ]] && project_dir="${scan_path}/${dir}"

  local padded output_name
  padded="$(printf '%03d' "${index}")"
  output_name="audit-${padded}.json"

  local -a meta=(
    record-audit
    "--index=${index}"
    "--dir=${dir}"
    "--package-manager=${package_manager}"
    "--lockfile=${lockfile}"
  )

  if ! resolve_command "${package_manager}" "${yarn_major}" "${package_manager_field}"; then
    printf 'no usable %s installation was found on this runner.\n' "${package_manager}" > "${tmp_dir}/error"
    ws::cli "${meta[@]}" --state=error --exit-code=1 "--message-file=${tmp_dir}/error" "--tool=${package_manager}"
    ws::error "${label}: no usable ${package_manager} installation found."
    return 0
  fi

  warn_about_custom_registry "${project_dir}"

  # Read the version from inside the project, so a pinned packageManager
  # version is reflected in the log and the report.
  local tool_version=""
  tool_version="$(ws::clean_version "$( (cd "${project_dir}" && ws::with_timeout 120 "${AUDIT_VERSION_COMMAND[@]}" 2>/dev/null | tail -n 1) || true )")"

  ws::log "  ${label}: ${AUDIT_TOOL}${tool_version:+ ${tool_version}} (${lockfile})"

  local exit_code=0
  (
    cd "${project_dir}" || exit 3
    ws::with_timeout "${AUDIT_TIMEOUT_SECONDS}" "${AUDIT_COMMAND[@]}"
  ) > "${raw_dir}/${output_name}" 2> "${tmp_dir}/stderr-${padded}" || exit_code=$?

  if ! audit_ran_successfully "${AUDIT_TOOL}" "${exit_code}"; then
    {
      if [[ "${exit_code}" -eq 124 || "${exit_code}" -eq 137 ]]; then
        printf 'the audit timed out after %s seconds.\n' "${AUDIT_TIMEOUT_SECONDS}"
      else
        printf '%s exited with status %s.\n' "${AUDIT_TOOL}" "${exit_code}"
      fi
      tail -n 10 "${tmp_dir}/stderr-${padded}" 2>/dev/null || true
    } > "${tmp_dir}/error-${padded}"

    ws::error "${label}: ${AUDIT_TOOL} failed (exit ${exit_code})."
    tail -n 10 "${tmp_dir}/stderr-${padded}" >&2 2>/dev/null || true

    ws::cli "${meta[@]}" --state=error "--exit-code=${exit_code}" \
      "--message-file=${tmp_dir}/error-${padded}" "--tool=${AUDIT_TOOL}" "--version=${tool_version}"
    return 1
  fi

  ws::cli "${meta[@]}" --state=ok "--exit-code=${exit_code}" \
    "--tool=${AUDIT_TOOL}" "--version=${tool_version}" "--output=${output_name}"
  return 0
}

main() {
  local scan_path="${WEB_SECURITY_SCAN_PATH:?WEB_SECURITY_SCAN_PATH is not set}"

  local raw_dir tmp_dir
  raw_dir="$(ws::raw_dir)"
  tmp_dir="$(ws::make_temp_dir)"
  # shellcheck disable=SC2064
  trap "rm -rf '${tmp_dir}'" EXIT

  # Hardening for every package manager invoked below: no lifecycle scripts,
  # no interactive prompts, no telemetry, no auto-pinning of the project's
  # packageManager field.
  export npm_config_ignore_scripts=true
  export npm_config_fund=false
  export npm_config_update_notifier=false
  export COREPACK_ENABLE_AUTO_PIN=0
  export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
  export YARN_ENABLE_SCRIPTS=false
  export YARN_ENABLE_TELEMETRY=0
  export CI=true

  ws::group "Dependency audit"

  local failures=0
  local projects=0
  local index dir package_manager yarn_major lockfile package_manager_field

  # ASCII Unit Separator, not tab: bash collapses runs of IFS whitespace, which
  # would shift the columns after an empty field. See `audit-plan` in cli.mjs.
  while IFS=$'\x1f' read -r index dir package_manager yarn_major lockfile package_manager_field; do
    [[ -z "${index}" ]] && continue
    projects=$((projects + 1))
    if ! audit_project "${index}" "${dir}" "${package_manager}" "${yarn_major}" "${lockfile}" \
      "${package_manager_field}" "${scan_path}" "${raw_dir}" "${tmp_dir}"; then
      failures=$((failures + 1))
    fi
  done < <(ws::cli audit-plan)

  ws::endgroup

  if [[ "${projects}" -eq 0 ]]; then
    ws::cli record-status --scanner=dependency --state=skipped --exit-code=0 \
      --projects-from-audit
    return 0
  fi

  if [[ "${failures}" -gt 0 ]]; then
    printf '%s of %s project audit(s) could not be completed.\n' "${failures}" "${projects}" > "${tmp_dir}/summary-error"
    ws::cli record-status --scanner=dependency --state=error --exit-code=1 \
      "--message-file=${tmp_dir}/summary-error" --projects-from-audit
    return 0
  fi

  ws::cli record-status --scanner=dependency --state=ok --exit-code=0 --projects-from-audit
}

main "$@"
