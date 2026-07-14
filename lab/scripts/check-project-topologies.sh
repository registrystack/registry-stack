#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab_root="$(cd "${script_dir}/.." && pwd)"
stack_root="$(cd "${lab_root}/.." && pwd)"
work_root="$(mktemp -d)"

cleanup() {
  rm -rf "${work_root}"
}
trap cleanup EXIT

export REGISTRYCTL_NO_UPDATE_CHECK=1
export CARGO_NET_OFFLINE=true

run_registryctl() {
  if [[ -n "${REGISTRYCTL_BIN:-}" ]]; then
    "${REGISTRYCTL_BIN}" "$@"
  else
    cargo run --locked --quiet --manifest-path "${stack_root}/Cargo.toml" -p registryctl -- "$@"
  fi
}

copy_project() {
  local name="$1"
  mkdir -p "${work_root}/${name}"
  cp -R "${lab_root}/projects/${name}/." "${work_root}/${name}/"
}

require_file() {
  local path="$1"
  [[ -f "${path}" ]] || {
    printf 'missing generated topology artifact: %s\n' "${path}" >&2
    exit 1
  }
}

require_absent() {
  local path="$1"
  [[ ! -e "${path}" ]] || {
    printf 'unexpected generated topology artifact: %s\n' "${path}" >&2
    exit 1
  }
}

for project in combined relay-only notary-only openspp-exact; do
  copy_project "${project}"
done

run_registryctl test \
  --project-dir "${work_root}/openspp-exact" \
  --environment local >/dev/null

for project in combined relay-only notary-only; do
  run_registryctl check \
    --project-dir "${work_root}/${project}" \
    --environment local \
    --explain >/dev/null
  run_registryctl build \
    --project-dir "${work_root}/${project}" \
    --environment local >/dev/null
done

combined="${work_root}/combined/.registry-stack/build/local/private"
relay_only="${work_root}/relay-only/.registry-stack/build/local/private"
notary_only="${work_root}/notary-only/.registry-stack/build/local/private"

require_file "${combined}/relay/config/relay.yaml"
require_file "${combined}/notary/config/notary.yaml"
require_file "${relay_only}/relay/config/relay.yaml"
require_absent "${relay_only}/notary"
require_file "${notary_only}/notary/config/notary.yaml"
require_absent "${notary_only}/relay"

if rg -n \
  'registry_data_api|source_adapter_sidecar|connector:[[:space:]]*(dci|registry_data_api|source_adapter_sidecar)|openfn|sidecar' \
  "${work_root}" --glob '!**/.registry-stack/build/*/reviewable/review.json'; then
  printf 'generated topology retained a superseded Notary source path\n' >&2
  exit 1
fi

printf 'Registry project topology checks passed: combined, Relay-only, Notary-only, and offline OpenSPP.\n'
