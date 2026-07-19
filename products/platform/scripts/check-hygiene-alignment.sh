#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="${1:-$(cd "${script_dir}/../../.." && pwd)}"
platform_root="${2:-${repo_root}/products/platform}"
template_root="${platform_root}/templates"

compare() {
  local actual="$1"
  local expected="$2"
  local label="$3"

  cmp -s "$actual" "$expected" || {
    echo "$label differs from ${expected#"${repo_root}/"}" >&2
    exit 1
  }
}

for file in clippy.toml rustfmt.toml; do
  compare \
    "${repo_root}/${file}" \
    "${template_root}/${file}" \
    "${file}"
  compare \
    "${repo_root}/crates/registry-relay/${file}" \
    "${template_root}/${file}" \
    "crates/registry-relay/${file}"
  compare \
    "${platform_root}/${file}" \
    "${template_root}/${file}" \
    "products/platform/${file}"
done

# Dependency policy is workspace-specific in the monorepo. Keep the reusable
# platform copy aligned with its published template, while the root, Relay,
# Manifest, and Notary policies remain free to describe their actual graphs.
compare \
  "${platform_root}/deny.toml" \
  "${template_root}/deny.toml" \
  "products/platform/deny.toml"

echo "shared Rust hygiene files are aligned"
