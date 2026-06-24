#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
metadata_repo="${REGISTRY_MANIFEST_REPO:-"${repo_root}/../registry-manifest"}"
git_url="${REGISTRY_MANIFEST_GIT_URL:-https://github.com/jeremi/registry-manifest}"
git_rev="${REGISTRY_MANIFEST_GIT_REV:-77125ec04f50157749a257eab3661ef82e613ce3}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"

if [[ ! "${git_rev}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "REGISTRY_MANIFEST_GIT_REV must be a 40-character lowercase commit SHA" >&2
  exit 2
fi

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

echo "registry-manifest CLI not found; installing ${git_url} at commit ${git_rev}" >&2
cargo install --locked --git "${git_url}" --rev "${git_rev}" registry-manifest-cli

exec "${CARGO_HOME:-${HOME}/.cargo}/bin/registry-manifest" "$@"
