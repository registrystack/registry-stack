#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
DEFAULT_REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly DEFAULT_REPO_ROOT
readonly REPO_ROOT="${REGISTRY_STACK_INSTALLER_REPO_ROOT:-${DEFAULT_REPO_ROOT}}"
readonly EXTENSION_ID="registrystack.registry-stack"
REGISTRYCTL_PATH=''

usage() {
  cat <<'EOF'
Install Registry Stack semantic navigation for an editor.

Usage:
  ./editors/install.sh <vscode|zed> [options]

Options:
  --profile <name>           Existing VS Code profile to use (default: active profile)
  --open <path>              Open an existing directory after installation
  -h, --help                 Show this help

The installer never trusts a workspace automatically. Installing for VS Code
updates the active profile unless --profile selects an existing profile. Zed
requires one final command-palette action because its CLI cannot install a
local development extension. Project configuration remains a separate
registryctl init or registryctl authoring editor operation.
EOF
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  local command_name="$1"
  command -v "${command_name}" >/dev/null 2>&1 ||
    fail "required command '${command_name}' was not found on PATH"
}

external_command_path() {
  local command_name="$1"
  local command_path
  command_path="$(type -P "${command_name}")" ||
    fail "required external command '${command_name}' was not found on PATH"
  case "${command_path}" in
    /*) ;;
    */*)
      command_path="$(cd -- "${command_path%/*}" && pwd -P)/${command_path##*/}"
      ;;
    *)
      command_path="${PWD}/${command_path}"
      ;;
  esac
  [[ -f "${command_path}" && -x "${command_path}" ]] ||
    fail "command '${command_name}' is not an executable file: ${command_path}"
  printf '%s\n' "${command_path}"
}

workspace_version() {
  awk '
    /^\[workspace\.package\][[:space:]]*$/ { in_workspace_package = 1; next }
    in_workspace_package && /^\[/ { exit }
    in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0
      sub(/^[^=]*=[[:space:]]*"/, "", line)
      sub(/".*$/, "", line)
      print line
      exit
    }
  ' "${REPO_ROOT}/Cargo.toml"
}

registryctl_version() {
  local version_output
  version_output="$("${REGISTRYCTL_PATH}" --version)" ||
    fail "could not run registryctl --version"
  case "${version_output}" in
    'registryctl '*)
      version_output="${version_output#registryctl }"
      printf '%s\n' "${version_output%% *}"
      ;;
    *)
      fail "unexpected registryctl version output: ${version_output}"
      ;;
  esac
}

canonical_open_path() {
  local requested_path="$1"
  [[ -d "${requested_path}" ]] ||
    fail "directory to open does not exist: ${requested_path}"

  (cd -- "${requested_path}" && pwd -P)
}

verify_registryctl() {
  REGISTRYCTL_PATH="$(external_command_path registryctl)"

  local expected_version
  local installed_version
  expected_version="$(workspace_version)"
  [[ -n "${expected_version}" ]] ||
    fail "could not read the workspace version from ${REPO_ROOT}/Cargo.toml"
  installed_version="$(registryctl_version)"

  if [[ "${installed_version}" != "${expected_version}" ]]; then
    fail "this checkout is ${expected_version} but registryctl is ${installed_version}; install the matching registryctl"
  fi

  "${REGISTRYCTL_PATH}" authoring language-server --help >/dev/null ||
    fail "registryctl ${installed_version} does not provide authoring language-server"
  printf 'Using registryctl %s from %s\n' \
    "${installed_version}" "${REGISTRYCTL_PATH}"
}

install_vscode() {
  local open_path="$1"
  local profile="$2"
  local vscode_root="${REPO_ROOT}/editors/vscode"
  local vsix="${vscode_root}/registry-stack-dev.vsix"
  local install_metadata="${vscode_root}/dist/registryctl-path"
  local registryctl_path
  local profile_label='active profile'
  local -a profile_args=()

  registryctl_path="${REGISTRYCTL_PATH}"

  if [[ -n "${profile}" ]]; then
    profile_label="profile ${profile}"
    profile_args=(--profile "${profile}")
  fi

  require_command node
  require_command npm
  require_command code
  require_command unzip
  [[ -f "${vscode_root}/package.json" ]] ||
    fail "VS Code extension source was not found at ${vscode_root}"

  local node_version
  local node_major
  node_version="$(node --version)"
  node_major="${node_version#v}"
  node_major="${node_major%%.*}"
  [[ "${node_major}" =~ ^[0-9]+$ ]] ||
    fail "unexpected Node.js version output: ${node_version}"
  ((node_major >= 22)) ||
    fail "Node.js 22 or newer is required; found ${node_version}"

  printf 'Packaging Registry Stack for VS Code\n'
  npm --prefix "${vscode_root}" ci
  mkdir -p "${vscode_root}/dist"
  [[ -d "${vscode_root}/dist" && ! -L "${vscode_root}/dist" ]] ||
    fail "VS Code dist path must be a regular directory: ${vscode_root}/dist"
  [[ ! -e "${install_metadata}" && ! -L "${install_metadata}" ]] ||
    fail "temporary installer metadata already exists: ${install_metadata}"
  if ! (
    trap 'rm -f -- "${install_metadata}"' EXIT HUP INT TERM
    printf '%s\n' "${registryctl_path}" > "${install_metadata}"
    REGISTRY_STACK_EXPECT_REGISTRYCTL_PATH="${registryctl_path}" \
      npm --prefix "${vscode_root}" run package:dev
  ); then
    fail "VS Code extension packaging failed"
  fi
  [[ -f "${vsix}" && ! -L "${vsix}" ]] ||
    fail "VS Code package was not created at ${vsix}"

  printf 'Installing %s into the VS Code %s\n' "${EXTENSION_ID}" "${profile_label}"
  code "${profile_args[@]}" --install-extension "${vsix}" --force

  printf '\nRegistry Stack editor support is installed for VS Code.\n'
  printf 'Project setup remains a separate registryctl operation.\n'
  printf 'Workspace trust remains your decision when a project opens.\n'
  if [[ -n "${open_path}" ]]; then
    printf 'Opening %s with the VS Code %s.\n' "${open_path}" "${profile_label}"
    code "${profile_args[@]}" --new-window "${open_path}"
  else
    printf 'Open a Registry Stack project when you are ready.\n'
  fi
}

install_zed() {
  local open_path="$1"
  local zed_root="${REPO_ROOT}/editors/zed"

  require_command rustup
  require_command cargo
  [[ -f "${zed_root}/Cargo.toml" ]] ||
    fail "Zed extension source was not found at ${zed_root}"

  if ! rustup target list --installed | grep -Fxq 'wasm32-wasip2'; then
    printf 'Installing the Rust target required by Zed\n'
    rustup target add wasm32-wasip2
  fi

  printf 'Checking the Registry Stack extension for Zed\n'
  cargo check --locked --target wasm32-wasip2 \
    --manifest-path "${zed_root}/Cargo.toml"

  if [[ -n "${open_path}" ]]; then
    require_command zed
  fi

  printf '\nRegistry Stack editor support is prepared for Zed.\n'
  printf 'Project setup remains a separate registryctl operation.\n'
  printf 'Zed requires one manual installation step:\n'
  printf '  1. Run "Zed: Install Dev Extension" from the command palette.\n'
  printf '  2. Select %s\n' "${zed_root}"
  printf '  3. Run "editor: restart language server".\n'
  printf 'Development-extension approval remains your decision.\n'

  if [[ -n "${open_path}" ]]; then
    printf 'Opening %s in Zed. Quit an existing Zed process first if it does not inherit PATH.\n' \
      "${open_path}"
    zed "${open_path}"
  else
    printf 'Open a Registry Stack project from this shell when you are ready.\n'
  fi
}

main() {
  if (($# == 0)); then
    usage >&2
    exit 2
  fi

  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
  esac

  local editor="$1"
  shift
  case "${editor}" in
    vscode | zed) ;;
    *)
      usage >&2
      fail "unsupported editor '${editor}'; expected vscode or zed"
      ;;
  esac

  local requested_open_path=''
  local vscode_profile=''
  local profile_set="false"

  while (($# > 0)); do
    case "$1" in
      --open)
        (($# >= 2)) || fail "--open requires a path"
        [[ -n "$2" ]] || fail "--open cannot be empty"
        requested_open_path="$2"
        shift 2
        ;;
      --profile)
        (($# >= 2)) || fail "--profile requires a name"
        [[ -n "$2" ]] || fail "--profile cannot be empty"
        vscode_profile="$2"
        profile_set="true"
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        fail "unknown option: $1"
        ;;
    esac
  done

  if [[ "${editor}" == "zed" && "${profile_set}" == "true" ]]; then
    fail "--profile applies only to VS Code"
  fi

  [[ -f "${REPO_ROOT}/Cargo.toml" ]] ||
    fail "Registry Stack repository root was not found at ${REPO_ROOT}"

  local open_path=''
  if [[ -n "${requested_open_path}" ]]; then
    open_path="$(canonical_open_path "${requested_open_path}")"
  fi
  verify_registryctl

  case "${editor}" in
    vscode)
      install_vscode "${open_path}" "${vscode_profile}"
      ;;
    zed)
      install_zed "${open_path}"
      ;;
  esac
}

main "$@"
