#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${repo_root}/target/contract-kernel"

run() {
  echo "==> registry-manifest: $*"
  "$@"
}

slug() {
  printf '%s' "$1" | tr '/ :' '---' | tr -cd '[:alnum:]_.-'
}

cd "${repo_root}"
run cargo fmt --all -- --check
run cargo clippy --workspace --all-targets -- -D warnings
run cargo test --workspace
run cargo run -p registry-manifest-cli -- validate-profiles profiles

mkdir -p "${out_dir}"
for manifest in "$@"; do
  if [[ ! -f "${manifest}" ]]; then
    echo "registry-manifest contract check failed: manifest not found: ${manifest}" >&2
    exit 2
  fi
  name="$(slug "${manifest}")"
  run cargo run -p registry-manifest-cli -- validate "${manifest}"
  run cargo run -p registry-manifest-cli -- publish "${manifest}" --out "${out_dir}/${name}"
done

