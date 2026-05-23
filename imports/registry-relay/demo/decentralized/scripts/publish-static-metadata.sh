#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${demo_dir}/../.." && pwd)"

manifest="${1:-"${demo_dir}/config/static-metadata/metadata.yaml"}"
out_dir="${2:-"${demo_dir}/static-metadata/metadata"}"

if [[ ! -f "${manifest}" ]]; then
  echo "static metadata manifest not found: ${manifest}" >&2
  exit 1
fi

rm -rf "${out_dir}"
mkdir -p "${out_dir}"

"${repo_root}/scripts/run_registry_manifest_cli.sh" publish "${manifest}" --out "${out_dir}"

if [[ ! -f "${out_dir}/index.json" ]]; then
  echo "registry-manifest publish did not produce ${out_dir}/index.json" >&2
  exit 1
fi

echo "published static metadata bundle to ${out_dir}"
