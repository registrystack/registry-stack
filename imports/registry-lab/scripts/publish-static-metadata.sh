#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"

manifest="${1:-"${demo_dir}/config/static-metadata/metadata.yaml"}"
out_dir="${2:-"${demo_dir}/static-metadata/metadata"}"
public_root="$(dirname "${out_dir}")"
env_file="${REGISTRY_LAB_ENV_FILE:-"${demo_dir}/.env"}"

if [[ ! -f "${manifest}" ]]; then
  echo "static metadata manifest not found: ${manifest}" >&2
  exit 1
fi

rm -rf "${out_dir}" "${public_root}/.well-known"
mkdir -p "${out_dir}"

manifest_repo="$("${script_dir}/check-service-first-deps.sh" manifest-path)"
(cd "${manifest_repo}" && cargo run --quiet -p registry-manifest-cli -- publish "${manifest}" --out "${out_dir}" --site-root "${public_root}")

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

python3 - "${out_dir}/policies.jsonld" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(0)

body = json.loads(path.read_text(encoding="utf-8"))
graph = body.setdefault("@graph", [])
agri_policy_id = "#policy-agricultural_registry-offer"
controls_id = "#policy-nagdi-agriculture-governance-controls"
controls = {
    "@id": controls_id,
    "@type": "odrl:Policy",
    "dcterms:title": "NAgDI agricultural governance controls",
    "registry_manifest:lawfulBasis": [
        "program_rule",
        "public_task",
        "permit_condition",
    ],
    "registry_manifest:allowedPurposes": [
        "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
        "https://demo.example.gov/purpose/nagdi/livestock-movement-permit-review",
        "https://demo.example.gov/purpose/nagdi/agricultural-market-sizing",
    ],
    "registry_manifest:allowedRecipientTypes": [
        "government_program",
        "extension_authority",
        "animal_health_authority",
        "licensed_service_provider",
        "planning_unit",
    ],
    "registry_manifest:allowedDisclosureModes": [
        "predicate",
        "redacted_result",
        "aggregate",
    ],
    "registry_manifest:retentionDays": {
        "climate_smart_input_support": 365,
        "livestock_movement_permit_review": 730,
        "agricultural_market_sizing": 90,
    },
    "registry_manifest:minimumCellCount": 5,
    "registry_manifest:geographyFloor": "district",
    "registry_manifest:suppressionPolicy": "suppress_cells_below_minimum_or_below_geography_floor",
    "registry_manifest:rareCategorySuppression": True,
    "registry_manifest:onwardSharingAllowed": False,
    "registry_manifest:automatedDecisionAllowed": False,
    "registry_manifest:auditRequired": True,
    "registry_manifest:appealOrReviewRoute": "https://demo.example.gov/services/nagdi/review",
}
graph[:] = [item for item in graph if item.get("@id") != controls_id]
graph.append(controls)
for item in graph:
    if item.get("@id") == agri_policy_id:
        item["registry_manifest:governanceControls"] = {"@id": controls_id}
        break
path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 - "${env_file}" "${public_root}/federation/benefits-jwks.json" "${public_root}/federation/default-benefits-jwks.json" "${public_root}/.well-known/jwks.json" <<'PY'
import json
import shlex
import sys
from pathlib import Path

env_path = Path(sys.argv[1])
agri_out_path = Path(sys.argv[2])
default_out_path = Path(sys.argv[3])
static_metadata_out_path = Path(sys.argv[4])
values = {}
if env_path.exists():
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if value[:1] in ("'", '"'):
            try:
                parts = shlex.split(value, comments=False, posix=True)
            except ValueError:
                parts = []
            if len(parts) == 1:
                value = parts[0]
        values[key] = value

def write_public_jwks(env_name, kid, out_path):
    raw_jwk = values.get(env_name)
    if not raw_jwk:
        raise SystemExit(f"{env_name} missing; run scripts/generate-demo-secrets.py first")
    jwk = json.loads(raw_jwk)
    public_jwk = {
        "kty": jwk["kty"],
        "crv": jwk["crv"],
        "x": jwk["x"],
        "alg": "EdDSA",
        "kid": kid,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"keys": [public_jwk]}, indent=2, sort_keys=True) + "\n", encoding="utf-8")

write_public_jwks(
    "AGRI_FEDERATION_CLIENT_JWK",
    "did:web:nagdi-benefits.demo.example.gov#federation-client-1",
    agri_out_path,
)
write_public_jwks(
    "DEFAULT_FEDERATION_CLIENT_JWK",
    "did:web:benefits.demo.example.gov#federation-client-1",
    default_out_path,
)
write_public_jwks(
    "STATIC_METADATA_FEDERATION_JWK",
    "did:web:static-metadata.demo.example.gov#federation-metadata-1",
    static_metadata_out_path,
)
PY

echo "published static metadata bundle to ${out_dir}"
