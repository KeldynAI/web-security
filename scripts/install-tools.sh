#!/usr/bin/env bash
#
# Step 2 of 4: install the pinned scanners.
#
# Supply-chain rules for this step:
#   - No `curl … | sh`. Release archives are downloaded to a private temporary
#     directory and their SHA-256 checksum is verified against the value pinned
#     in tools.json before anything is extracted or executed.
#   - No floating "latest". Versions come from tools.json only.
#   - Downloads are forced over HTTPS (`--proto '=https'`) so a redirect cannot
#     downgrade the transport.
#   - Binaries are installed into the Action's own state directory. PATH is not
#     modified and nothing is installed into the consumer's project.
#
# Only the scanners that are actually enabled get installed.

# shellcheck source=scripts/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

readonly DOWNLOAD_MAX_SECONDS=300

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "${machine}" in
    x86_64 | amd64) printf 'x64' ;;
    aarch64 | arm64) printf 'arm64' ;;
    *)
      ws::fail "unsupported CPU architecture '${machine}'. This Action pins scanner binaries for linux x64 and arm64."
      ;;
  esac
}

# Downloads, verifies and extracts a single pinned release archive.
install_release_tool() {
  local name="$1" arch="$2" tmp_dir="$3" bin_dir="$4"
  local version url sha256 binary file

  # The manifest is emitted line by line so the shell never has to parse JSON.
  {
    read -r version
    read -r url
    read -r sha256
    read -r binary
    read -r file
  } < <(ws::cli tool-manifest "--name=${name}" --os=linux "--arch=${arch}")

  if [[ -z "${version:-}" || -z "${url:-}" || -z "${sha256:-}" || -z "${binary:-}" || -z "${file:-}" ]]; then
    ws::fail "could not read the pinned manifest for '${name}' from tools.json."
  fi

  local archive="${tmp_dir}/${file}"
  ws::log "  ${name} ${version}: downloading ${file}"
  if ! curl \
    --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    --retry 3 --retry-delay 2 --retry-connrefused \
    --max-time "${DOWNLOAD_MAX_SECONDS}" \
    --output "${archive}" \
    "${url}"; then
    ws::fail "could not download ${name} ${version} from ${url}. The runner needs outbound HTTPS access to github.com."
  fi

  # Refuse to execute a binary we cannot prove is the pinned release.
  if ! printf '%s  %s\n' "${sha256}" "${archive}" | sha256sum --check --status; then
    ws::fail "SHA-256 checksum mismatch for ${name} ${version}. The download does not match the checksum pinned in tools.json; refusing to execute it."
  fi
  ws::log "  ${name} ${version}: checksum verified"

  if ! tar -xzf "${archive}" -C "${bin_dir}" --no-same-owner "${binary}"; then
    ws::fail "could not extract '${binary}' from ${file}."
  fi
  chmod 0755 "${bin_dir}/${binary}"
  rm -f "${archive}"
}

# Semgrep is only distributed as a Python package, so it goes into a private
# virtualenv. `--only-binary` prevents pip from executing a source
# distribution's setup.py, which would be arbitrary code execution at install
# time.
install_semgrep() {
  local bin_dir="$1"
  local version package binary

  {
    read -r version
    read -r package
    read -r binary
  } < <(ws::cli tool-manifest --name=semgrep)

  if [[ -z "${version:-}" || -z "${package:-}" ]]; then
    ws::fail "could not read the pinned Semgrep version from tools.json."
  fi

  ws::require_cmd python3 "Semgrep is a Python package; install python3 or set sast: false."

  local venv
  venv="$(ws::state_dir)/semgrep-venv"
  if ! python3 -m venv "${venv}" >/dev/null 2>&1; then
    ws::fail "could not create a Python virtualenv for Semgrep. Install python3-venv, or set sast: false."
  fi

  local -a pip_args=(
    install --quiet --no-input --no-cache-dir
    --disable-pip-version-check
    --timeout 60 --retries 3
  )

  ws::log "  semgrep ${version}: installing ${package} from PyPI"
  if ! "${venv}/bin/python" -m pip "${pip_args[@]}" --only-binary=:all: "${package}"; then
    ws::warn "Semgrep could not be installed from pre-built wheels only; retrying with source distributions allowed. This permits package build scripts to run during installation."
    if ! "${venv}/bin/python" -m pip "${pip_args[@]}" "${package}"; then
      ws::fail "could not install ${package} from PyPI. The runner needs outbound HTTPS access to pypi.org, or set sast: false."
    fi
  fi

  ln -sf "${venv}/bin/${binary}" "${bin_dir}/${binary}"
}

report_version() {
  local label="$1" raw="$2"
  ws::log "  ${label}: $(ws::clean_version "${raw}")"
}

main() {
  local bin_dir tmp_dir arch
  bin_dir="$(ws::bin_dir)"
  mkdir -p "${bin_dir}"
  tmp_dir="$(ws::make_temp_dir)"
  # shellcheck disable=SC2064 # expand tmp_dir now, not at trap time
  trap "rm -rf '${tmp_dir}'" EXIT
  arch="$(detect_arch)"

  ws::group "Web Security: install pinned scanners (linux-${arch})"

  local -a json_entries=()
  local version

  if [[ "${WEB_SECURITY_NEED_TRIVY:-false}" == "true" ]]; then
    install_release_tool trivy "${arch}" "${tmp_dir}" "${bin_dir}"
    version="$(ws::clean_version "$("${bin_dir}/trivy" --version | head -n 1 | sed -E 's/^Version:[[:space:]]*//')")"
    json_entries+=("\"trivy\": \"${version}\"")
    report_version "Trivy" "${version}"
  fi

  if [[ "${WEB_SECURITY_NEED_SECRETS:-false}" == "true" ]]; then
    install_release_tool gitleaks "${arch}" "${tmp_dir}" "${bin_dir}"
    version="$(ws::clean_version "$("${bin_dir}/gitleaks" version 2>&1 | tail -n 1)")"
    json_entries+=("\"gitleaks\": \"${version}\"")
    report_version "Gitleaks" "${version}"
  fi

  if [[ "${WEB_SECURITY_NEED_SAST:-false}" == "true" ]]; then
    install_semgrep "${bin_dir}"
    version="$(ws::clean_version "$("${bin_dir}/semgrep" --version 2>/dev/null | tail -n 1)")"
    json_entries+=("\"semgrep\": \"${version}\"")
    report_version "Semgrep" "${version}"
  fi

  # Versions are sanitised by ws::clean_version, so this is safe to write
  # directly as JSON.
  local joined=""
  local entry
  for entry in "${json_entries[@]-}"; do
    [[ -z "${entry}" ]] && continue
    [[ -n "${joined}" ]] && joined+=", "
    joined+="${entry}"
  done
  printf '{%s}\n' "${joined}" > "$(ws::state_dir)/tools.json"

  ws::endgroup
}

main "$@"
