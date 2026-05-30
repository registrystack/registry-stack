#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
platform_input="${REGISTRY_PLATFORM_SOURCE_DIR:-${repo_root}/../registry-platform}"
cargo_platform_input="${repo_root}/../registry-platform"

absolute_dir() {
  local dir="$1"
  (cd "${dir}" && pwd -P)
}

if [[ ! -f "${platform_input}/Cargo.toml" ]]; then
  echo "registry-relay platform compatibility check failed: REGISTRY_PLATFORM_SOURCE_DIR does not point to a registry-platform checkout: ${platform_input}" >&2
  exit 2
fi

platform_dir="$(absolute_dir "${platform_input}")"
cargo_platform_dir="$(absolute_dir "${cargo_platform_input}" 2>/dev/null || true)"
work_root="${repo_root}"
tmp_root=""

cleanup() {
  if [[ -n "${tmp_root}" ]]; then
    rm -rf "${tmp_root}"
  fi
}
trap cleanup EXIT

if [[ "${platform_dir}" != "${cargo_platform_dir}" ]]; then
  if ! command -v rsync >/dev/null 2>&1; then
    echo "registry-relay platform compatibility check failed: rsync is required when REGISTRY_PLATFORM_SOURCE_DIR is not ../registry-platform" >&2
    exit 2
  fi

  cel_input="${CEL_MAPPING_SOURCE_DIR:-${repo_root}/../cel-mapping}"
  if [[ ! -f "${cel_input}/Cargo.toml" ]]; then
    echo "registry-relay platform compatibility check failed: CEL_MAPPING_SOURCE_DIR does not point to cel-mapping: ${cel_input}" >&2
    exit 2
  fi
  cel_dir="$(absolute_dir "${cel_input}")"

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-relay-platform-compat.XXXXXX")"
  work_root="${tmp_root}/registry-relay"
  mkdir -p "${work_root}"
  rsync -a --exclude '/.git' --exclude '/target' "${repo_root}/" "${work_root}/"
  ln -s "${platform_dir}" "${tmp_root}/registry-platform"
  ln -s "${cel_dir}" "${tmp_root}/cel-mapping"
  echo "==> registry-relay: using temporary compatibility workspace with registry-platform -> ${platform_dir}"
fi

run() {
  echo "==> registry-relay: $*"
  "$@"
}

cd "${work_root}"
run cargo check --all-features
run cargo test --lib auth::oidc::provider::tests
run cargo test --test audit_redaction_chain
run cargo test --test audit_sinks
