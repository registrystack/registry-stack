#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
platform_input="${REGISTRY_PLATFORM_SOURCE_DIR:-${repo_root}/../registry-platform}"
cargo_platform_input="${repo_root}/../registry-platform"
# CEL_MAPPING_SOURCE_DIR is the deprecated name for CROSSWALK_SOURCE_DIR;
# remove the fallback once operators have migrated.
if [[ -z "${CROSSWALK_SOURCE_DIR:-}" && -n "${CEL_MAPPING_SOURCE_DIR:-}" ]]; then
  echo "warning: CEL_MAPPING_SOURCE_DIR is deprecated, please use CROSSWALK_SOURCE_DIR instead" >&2
fi
crosswalk_input="${CROSSWALK_SOURCE_DIR:-${CEL_MAPPING_SOURCE_DIR:-${repo_root}/../crosswalk}}"
cargo_crosswalk_input="${repo_root}/../crosswalk"

absolute_dir() {
  local dir="$1"
  (cd "${dir}" && pwd -P)
}

if [[ ! -f "${platform_input}/Cargo.toml" ]]; then
  echo "registry-relay platform compatibility check failed: REGISTRY_PLATFORM_SOURCE_DIR does not point to a registry-platform checkout: ${platform_input}" >&2
  exit 2
fi
if [[ ! -f "${crosswalk_input}/Cargo.toml" ]]; then
  echo "registry-relay platform compatibility check failed: CROSSWALK_SOURCE_DIR does not point to crosswalk: ${crosswalk_input}" >&2
  exit 2
fi

platform_dir="$(absolute_dir "${platform_input}")"
cargo_platform_dir="$(absolute_dir "${cargo_platform_input}" 2>/dev/null || true)"
crosswalk_dir="$(absolute_dir "${crosswalk_input}")"
cargo_crosswalk_dir="$(absolute_dir "${cargo_crosswalk_input}" 2>/dev/null || true)"
work_root="${repo_root}"
tmp_root=""

cleanup() {
  if [[ -n "${tmp_root}" ]]; then
    rm -rf "${tmp_root}"
  fi
}
trap cleanup EXIT

if [[ "${platform_dir}" != "${cargo_platform_dir}" || "${crosswalk_dir}" != "${cargo_crosswalk_dir}" ]]; then
  if ! command -v rsync >/dev/null 2>&1; then
    echo "registry-relay platform compatibility check failed: rsync is required when REGISTRY_PLATFORM_SOURCE_DIR or CROSSWALK_SOURCE_DIR is not the sibling checkout path" >&2
    exit 2
  fi

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/registry-relay-platform-compat.XXXXXX")"
  work_root="${tmp_root}/registry-relay"
  mkdir -p "${work_root}"
  rsync -a --exclude '/.git' --exclude '/target' "${repo_root}/" "${work_root}/"
  ln -s "${platform_dir}" "${tmp_root}/registry-platform"
  ln -s "${crosswalk_dir}" "${tmp_root}/crosswalk"
  echo "==> registry-relay: using temporary compatibility workspace with registry-platform -> ${platform_dir}, crosswalk -> ${crosswalk_dir}"
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
