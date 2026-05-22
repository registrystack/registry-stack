#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
metadata_repo="${REGISTRY_METADATA_REPO:-"${repo_root}/../registry-metadata"}"
git_url="${REGISTRY_METADATA_GIT_URL:-https://github.com/jeremi/registry-metadata}"
git_tag="${REGISTRY_METADATA_GIT_TAG:-v0.1.0}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"

if [[ -n "${REGISTRY_METADATA_CLI:-}" ]]; then
  exec "${REGISTRY_METADATA_CLI}" "$@"
fi

if command -v registry-metadata >/dev/null 2>&1; then
  exec registry-metadata "$@"
fi

if [[ -f "${metadata_repo}/Cargo.toml" ]]; then
  cd "${metadata_repo}"
  exec cargo run --quiet -p registry-metadata-cli -- "$@"
fi

echo "registry-metadata CLI not found; installing ${git_url} at ${git_tag}" >&2
cargo install --locked --git "${git_url}" --tag "${git_tag}" registry-metadata-cli

exec "${CARGO_HOME:-${HOME}/.cargo}/bin/registry-metadata" "$@"
