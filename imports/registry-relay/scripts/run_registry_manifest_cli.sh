#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
metadata_repo="${REGISTRY_MANIFEST_REPO:-"${repo_root}/../registry-manifest"}"
git_url="${REGISTRY_MANIFEST_GIT_URL:-https://github.com/jeremi/registry-manifest}"
git_tag="${REGISTRY_MANIFEST_GIT_TAG:-v0.1.2}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"

if [[ -n "${REGISTRY_MANIFEST_CLI:-}" ]]; then
  exec "${REGISTRY_MANIFEST_CLI}" "$@"
fi

if command -v registry-manifest >/dev/null 2>&1; then
  exec registry-manifest "$@"
fi

if [[ -f "${metadata_repo}/Cargo.toml" ]]; then
  cd "${metadata_repo}"
  exec cargo run --quiet -p registry-manifest-cli -- "$@"
fi

echo "registry-manifest CLI not found; installing ${git_url} at ${git_tag}" >&2
cargo install --locked --git "${git_url}" --tag "${git_tag}" registry-manifest-cli

exec "${CARGO_HOME:-${HOME}/.cargo}/bin/registry-manifest" "$@"
