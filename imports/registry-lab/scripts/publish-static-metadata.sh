#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"

manifest="${1:-"${demo_dir}/config/static-metadata/metadata.yaml"}"
out_dir="${2:-"${demo_dir}/static-metadata/metadata"}"
public_root="$(dirname "${out_dir}")"

if [[ ! -f "${manifest}" ]]; then
  echo "static metadata manifest not found: ${manifest}" >&2
  exit 1
fi

rm -rf "${out_dir}" "${public_root}/.well-known"
mkdir -p "${out_dir}"

manifest_repo="$("${script_dir}/check-service-first-deps.sh" manifest-path)"
(cd "${manifest_repo}" && cargo run --quiet -p registry-manifest-cli -- publish "${manifest}" --out "${out_dir}")

if [[ ! -f "${out_dir}/index.json" ]]; then
  echo "registry-manifest publish did not produce ${out_dir}/index.json" >&2
  exit 1
fi

well_known="${public_root}/.well-known/registry-manifest.json"
if [[ ! -f "${well_known}" ]]; then
  echo "registry-manifest publish did not produce ${well_known}" >&2
  exit 1
fi

api_catalog="${public_root}/.well-known/api-catalog"
if [[ ! -f "${api_catalog}" ]]; then
  echo "registry-manifest publish did not produce ${api_catalog}" >&2
  exit 1
fi

if [[ -f "${out_dir}/dcat.bregdcat-ap.jsonld" ]]; then
  mkdir -p "${out_dir}/dcat"
  cp "${out_dir}/dcat.bregdcat-ap.jsonld" "${out_dir}/dcat/bregdcat-ap"
fi

echo "published static metadata bundle to ${out_dir}"
