#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
platform_input="${REGISTRY_PLATFORM_SOURCE_DIR:-${repo_root}/../registry-platform}"
cargo_platform_input="${repo_root}/../registry-platform"

absolute_dir() {
  local dir="$1"
  (cd "${dir}" && pwd -L)
}

if [[ ! -f "${platform_input}/Cargo.toml" ]]; then
  echo "registry-notary platform compatibility check failed: REGISTRY_PLATFORM_SOURCE_DIR does not point to a registry-platform checkout: ${platform_input}" >&2
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
    echo "registry-notary platform compatibility check failed: rsync is required when REGISTRY_PLATFORM_SOURCE_DIR is not ../registry-platform" >&2
    exit 2
  fi

  # CEL_MAPPING_SOURCE_DIR is the deprecated name for CROSSWALK_SOURCE_DIR;
  # remove the fallback once operators have migrated.
  cel_input="${CROSSWALK_SOURCE_DIR:-${CEL_MAPPING_SOURCE_DIR:-${repo_root}/../crosswalk}}"
  if [[ ! -f "${cel_input}/Cargo.toml" ]]; then
    echo "registry-notary platform compatibility check failed: CROSSWALK_SOURCE_DIR does not point to crosswalk: ${cel_input}" >&2
    exit 2
  fi
  cel_dir="$(absolute_dir "${cel_input}")"

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-notary-platform-compat.XXXXXX")"
  work_root="${tmp_root}/registry-notary"
  mkdir -p "${work_root}"
  rsync -a --exclude '/.git' --exclude '/target' "${repo_root}/" "${work_root}/"
  ln -s "${platform_dir}" "${tmp_root}/registry-platform"
  ln -s "${cel_dir}" "${tmp_root}/crosswalk"
  echo "==> registry-notary: using temporary compatibility workspace with registry-platform -> ${platform_dir}"
fi

run() {
  echo "==> registry-notary: $*"
  "$@"
}

cd "${work_root}"
run cargo check -p registry-notary-server --all-features
run cargo test -p registry-notary-server --features registry-notary-cel --lib oid4vci_credential_issues_sd_jwt_and_rejects_nonce_replay
run cargo test -p registry-notary-server --no-default-features --test standalone_http audit_chain_bootstraps_from_sink_tail
