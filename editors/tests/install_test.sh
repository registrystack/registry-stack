#!/usr/bin/env bash

set -euo pipefail

TEST_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly TEST_SCRIPT_DIR
REAL_REPO_ROOT="$(cd -- "${TEST_SCRIPT_DIR}/../.." && pwd -P)"
readonly REAL_REPO_ROOT
readonly INSTALLER="${REAL_REPO_ROOT}/editors/install.sh"
TEST_ROOT="$(mktemp -d)"
readonly TEST_ROOT
readonly FAKE_REPO_ROOT="${TEST_ROOT}/repo"
readonly FAKE_OPEN_ROOT="${TEST_ROOT}/directory with spaces"
readonly FAKE_BIN="${TEST_ROOT}/bin"
readonly COMMAND_LOG="${TEST_ROOT}/commands.log"

cleanup() {
  find "${TEST_ROOT}" -depth -delete
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

assert_contains() {
  local expected="$1"
  local file="$2"
  if ! grep -Fq -- "${expected}" "${file}"; then
    printf '%s\n' '--- actual content ---' >&2
    sed -n '1,160p' "${file}" >&2
    fail "expected '${expected}' in ${file}"
  fi
}

assert_not_contains() {
  local unexpected="$1"
  local file="$2"
  if grep -Fq -- "${unexpected}" "${file}"; then
    fail "did not expect '${unexpected}' in ${file}"
  fi
}

reset_log() {
  : > "${COMMAND_LOG}"
}

mkdir -p \
  "${FAKE_REPO_ROOT}/editors/vscode" \
  "${FAKE_REPO_ROOT}/editors/zed" \
  "${FAKE_OPEN_ROOT}" \
  "${FAKE_BIN}"
FAKE_OPEN_CANONICAL="$(cd -- "${FAKE_OPEN_ROOT}" && pwd -P)"
readonly FAKE_OPEN_CANONICAL

printf '%s\n' \
  '[workspace]' \
  '[workspace.package]' \
  'version = "0.12.0"' \
  > "${FAKE_REPO_ROOT}/Cargo.toml"
printf '{}\n' > "${FAKE_REPO_ROOT}/editors/vscode/package.json"
printf '[package]\nname = "registry-stack-zed"\n' \
  > "${FAKE_REPO_ROOT}/editors/zed/Cargo.toml"

cat > "${FAKE_BIN}/fake-command" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command_name="$(basename -- "$0")"
{
  printf '%s' "${command_name}"
  for argument in "$@"; do
    printf ' <%s>' "${argument}"
  done
  printf '\n'
} >> "${FAKE_COMMAND_LOG}"

case "${command_name}" in
  registryctl)
    if [[ "${1:-}" == "--version" ]]; then
      printf 'registryctl %s\n' "${FAKE_REGISTRYCTL_VERSION:-0.12.0}"
    fi
    ;;
  node)
    if [[ "${1:-}" == "--version" ]]; then
      printf '%s\n' "${FAKE_NODE_VERSION:-v22.12.0}"
    fi
    ;;
  npm)
    if [[ " $* " == *' package:dev '* ]]; then
      metadata="${FAKE_REPO_ROOT}/editors/vscode/dist/registryctl-path"
      [[ -f "${metadata}" ]]
      [[ "$(< "${metadata}")" == "${REGISTRY_STACK_EXPECT_REGISTRYCTL_PATH:-}" ]]
      : > "${FAKE_REPO_ROOT}/editors/vscode/registry-stack-dev.vsix"
      if [[ "${FAKE_NPM_FAIL_PACKAGE:-false}" == "true" ]]; then
        exit 41
      fi
    fi
    ;;
  rustup)
    if [[ "${1:-}" == "target" && "${2:-}" == "list" && "${3:-}" == "--installed" && "${FAKE_WASIP2_INSTALLED:-false}" == "true" ]]; then
      printf 'wasm32-wasip2\n'
    fi
    ;;
esac
EOF
chmod +x "${FAKE_BIN}/fake-command"

for command_name in registryctl node npm code rustup cargo zed; do
  ln -s "${FAKE_BIN}/fake-command" "${FAKE_BIN}/${command_name}"
done

export FAKE_COMMAND_LOG="${COMMAND_LOG}"
export FAKE_REPO_ROOT
export PATH="${FAKE_BIN}:${PATH}"
export REGISTRY_STACK_INSTALLER_REPO_ROOT="${FAKE_REPO_ROOT}"

reset_log
vscode_output="${TEST_ROOT}/vscode-output"
"${INSTALLER}" vscode \
  --profile 'Registry Stack Test' > "${vscode_output}"

assert_contains 'registryctl <authoring> <language-server> <--help>' "${COMMAND_LOG}"
assert_not_contains 'registryctl <authoring> <editor>' "${COMMAND_LOG}"
assert_contains "npm <--prefix> <${FAKE_REPO_ROOT}/editors/vscode> <ci>" "${COMMAND_LOG}"
assert_contains "npm <--prefix> <${FAKE_REPO_ROOT}/editors/vscode> <run> <package:dev>" "${COMMAND_LOG}"
assert_contains "code <--profile> <Registry Stack Test> <--install-extension> <${FAKE_REPO_ROOT}/editors/vscode/registry-stack-dev.vsix> <--force>" "${COMMAND_LOG}"
assert_not_contains '<--new-window>' "${COMMAND_LOG}"
assert_contains 'Workspace trust remains your decision' "${vscode_output}"
assert_contains 'Project setup remains a separate registryctl operation' "${vscode_output}"

reset_log
"${INSTALLER}" vscode > /dev/null
assert_contains "code <--install-extension> <${FAKE_REPO_ROOT}/editors/vscode/registry-stack-dev.vsix> <--force>" "${COMMAND_LOG}"
assert_not_contains '<--profile>' "${COMMAND_LOG}"
if [[ -e "${FAKE_REPO_ROOT}/editors/vscode/dist/registryctl-path" ]]; then
  fail 'temporary registryctl metadata remained after successful packaging'
fi

reset_log
package_failure_output="${TEST_ROOT}/package-failure-output"
if FAKE_NPM_FAIL_PACKAGE=true "${INSTALLER}" vscode \
  > "${package_failure_output}" 2>&1; then
  fail 'VS Code package failure should fail the installer'
fi
assert_contains 'VS Code extension packaging failed' "${package_failure_output}"
if [[ -e "${FAKE_REPO_ROOT}/editors/vscode/dist/registryctl-path" ]]; then
  fail 'temporary registryctl metadata remained after failed packaging'
fi

reset_log
"${INSTALLER}" vscode \
  --profile 'Registry Stack Test' \
  --open "${FAKE_OPEN_ROOT}" > /dev/null
assert_contains "code <--profile> <Registry Stack Test> <--new-window> <${FAKE_OPEN_CANONICAL}>" "${COMMAND_LOG}"

reset_log
zed_output="${TEST_ROOT}/zed-output"
"${INSTALLER}" zed > "${zed_output}"
assert_contains 'rustup <target> <add> <wasm32-wasip2>' "${COMMAND_LOG}"
assert_contains "cargo <check> <--locked> <--target> <wasm32-wasip2> <--manifest-path> <${FAKE_REPO_ROOT}/editors/zed/Cargo.toml>" "${COMMAND_LOG}"
assert_not_contains 'zed <' "${COMMAND_LOG}"
assert_contains 'Zed requires one manual installation step' "${zed_output}"
assert_contains "Select ${FAKE_REPO_ROOT}/editors/zed" "${zed_output}"

reset_log
FAKE_WASIP2_INSTALLED=true "${INSTALLER}" zed \
  --open "${FAKE_OPEN_ROOT}" > /dev/null
assert_not_contains 'rustup <target> <add> <wasm32-wasip2>' "${COMMAND_LOG}"
assert_contains "zed <${FAKE_OPEN_CANONICAL}>" "${COMMAND_LOG}"

reset_log
mismatch_output="${TEST_ROOT}/mismatch-output"
if FAKE_REGISTRYCTL_VERSION=0.10.0 "${INSTALLER}" vscode \
  > "${mismatch_output}" 2>&1; then
  fail 'version mismatch should fail'
fi
assert_contains 'this checkout is 0.12.0 but registryctl is 0.10.0' "${mismatch_output}"
assert_not_contains 'npm <' "${COMMAND_LOG}"

reset_log
old_node_output="${TEST_ROOT}/old-node-output"
if FAKE_NODE_VERSION=v20.19.0 "${INSTALLER}" vscode \
  > "${old_node_output}" 2>&1; then
  fail 'old Node.js version should fail'
fi
assert_contains 'Node.js 22 or newer is required' "${old_node_output}"
assert_not_contains 'npm <' "${COMMAND_LOG}"

missing_output="${TEST_ROOT}/missing-output"
if "${INSTALLER}" vscode --open "${TEST_ROOT}/missing-directory" \
  > "${missing_output}" 2>&1; then
  fail 'missing directory passed to --open should fail'
fi
assert_contains 'directory to open does not exist' "${missing_output}"

help_output="${TEST_ROOT}/help-output"
"${INSTALLER}" --help > "${help_output}"
assert_contains './editors/install.sh <vscode|zed>' "${help_output}"
assert_contains '--open <path>' "${help_output}"
assert_not_contains '--project-dir' "${help_output}"

printf 'Editor installer tests passed.\n'
