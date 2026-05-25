#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"

manifest="${1:-"${demo_dir}/config/static-metadata/metadata.yaml"}"
out_dir="${2:-"${demo_dir}/static-metadata/metadata"}"

if [[ ! -f "${manifest}" ]]; then
  echo "static metadata manifest not found: ${manifest}" >&2
  exit 1
fi

rm -rf "${out_dir}"
mkdir -p "${out_dir}"

manifest_repo="$("${script_dir}/check-service-first-deps.sh" manifest-path)"
(cd "${manifest_repo}" && cargo run --quiet -p registry-manifest-cli -- publish "${manifest}" --out "${out_dir}")

if [[ ! -f "${out_dir}/index.json" ]]; then
  echo "registry-manifest publish did not produce ${out_dir}/index.json" >&2
  exit 1
fi

if [[ -f "${out_dir}/cpsv-ap.jsonld" ]]; then
  cp "${out_dir}/cpsv-ap.jsonld" "${out_dir}/cpsv-ap"
  python3 - "${out_dir}/index.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
index = json.loads(path.read_text(encoding="utf-8"))
catalogues = index.setdefault("service_catalogues", [])
for catalogue in catalogues:
    if catalogue.get("id") == "cpsv-ap":
        catalogue["url"] = "/metadata/cpsv-ap"
        break
else:
    catalogues.append(
        {
            "id": "cpsv-ap",
            "version": "3.2.0",
            "url": "/metadata/cpsv-ap",
        }
    )
path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

if [[ -f "${out_dir}/dcat.bregdcat-ap.jsonld" ]]; then
  mkdir -p "${out_dir}/dcat"
  cp "${out_dir}/dcat.bregdcat-ap.jsonld" "${out_dir}/dcat/bregdcat-ap"
fi

echo "published static metadata bundle to ${out_dir}"
