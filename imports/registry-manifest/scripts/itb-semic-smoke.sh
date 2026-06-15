#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${1:-profiles/example-civil-registration/fixtures/metadata.yaml}"
out_dir="${ITB_SEMIC_OUT_DIR:-target/itb-semic-smoke/example-civil-registration}"
report_dir="${ITB_SEMIC_REPORT_DIR:-target/itb-semic-smoke/reports}"
run_remote="${ITB_SEMIC_REMOTE:-0}"
json_validator_url="${ITB_JSON_VALIDATOR_URL:-}"
json_schema_url="${ITB_JSON_SCHEMA_2020_12_URL:-https://json-schema.org/draft/2020-12/schema}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 127
  fi
}

post_shacl() {
  local artifact="$1"
  local endpoint="$2"
  local validation_type="$3"
  local report="$4"

  local content
  content="$(jq -Rs . <"${artifact}")"
  jq -n \
    --argjson content "${content}" \
    --arg validationType "${validation_type}" \
    '{
      contentToValidate: $content,
      contentSyntax: "application/ld+json",
      embeddingMethod: "STRING",
      reportSyntax: "application/json",
      validationType: $validationType
    }' \
    > "${report}.request.json"

  curl -sS \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    --data-binary @"${report}.request.json" \
    "${endpoint}" \
    > "${report}"
}

post_json_schema() {
  local artifact="$1"
  local endpoint="$2"
  local schema_file="$3"
  local report="$4"

  local content
  local schema
  content="$(jq -Rs . <"${artifact}")"
  schema="$(jq -Rs . <"${schema_file}")"
  jq -n \
    --argjson content "${content}" \
    --argjson schema "${schema}" \
    '{
      contentToValidate: $content,
      embeddingMethod: "STRING",
      externalSchemas: [
        {
          schema: $schema,
          embeddingMethod: "STRING"
        }
      ],
      locationAsPointer: true,
      reportSyntax: "application/json"
    }' \
    > "${report}.request.json"

  curl -sS \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    --data-binary @"${report}.request.json" \
    "${endpoint}" \
    > "${report}"
}

assert_no_errors() {
  local report="$1"
  local errors
  errors="$(jq -r '.counters.nrOfErrors // 0' "${report}")"
  if [[ "${errors}" != "0" ]]; then
    echo "ITB/SEMIC report has ${errors} error(s): ${report}" >&2
    jq '.reports' "${report}" >&2
    exit 1
  fi
}

cd "${repo_root}"
need cargo
need jq

echo "==> registry-manifest: validate ${manifest}"
cargo run -p registry-manifest-cli -- validate "${manifest}"

echo "==> registry-manifest: publish ${out_dir}"
cargo run -p registry-manifest-cli -- publish "${manifest}" --out "${out_dir}"

if [[ -z "${json_validator_url}" && "${run_remote}" != "1" ]]; then
  echo "remote ITB/SEMIC validators skipped; rerun with ITB_SEMIC_REMOTE=1"
  echo "ITB JSON validator skipped; set ITB_JSON_VALIDATOR_URL to enable it"
  echo "published artifacts: ${out_dir}"
  exit 0
fi

need curl
mkdir -p "${report_dir}"
reports=()

if [[ -n "${json_validator_url}" ]]; then
  json_schema_file="${report_dir}/json-schema-2020-12.json"
  curl -sS -L -o "${json_schema_file}" "${json_schema_url}"

  while IFS= read -r schema_artifact; do
    relative_artifact="${schema_artifact#"${out_dir}/"}"
    report_name="$(printf '%s' "${relative_artifact}" | tr '/.' '--')"
    report="${report_dir}/${report_name}.json"
    post_json_schema \
      "${schema_artifact}" \
      "${json_validator_url}" \
      "${json_schema_file}" \
      "${report}"
    assert_no_errors "${report}"
    reports+=("${report}")
  done < <(find "${out_dir}/schema" -name schema.json -type f | sort)
fi

if [[ "${run_remote}" == "1" ]]; then
  post_shacl \
    "${out_dir}/dcat.jsonld" \
    "https://www.itb.ec.europa.eu/shacl/dcat-ap/api/validate" \
    "dcatap.3_0_1_base0" \
    "${report_dir}/dcat-ap.json"
  assert_no_errors "${report_dir}/dcat-ap.json"
  reports+=("${report_dir}/dcat-ap.json")

  post_shacl \
    "${out_dir}/dcat.bregdcat-ap.jsonld" \
    "https://www.itb.ec.europa.eu/shacl/bregdcat-ap/api/validate" \
    "bregdcatap.2_0_0" \
    "${report_dir}/bregdcat-ap-2.0.0.json"
  assert_no_errors "${report_dir}/bregdcat-ap-2.0.0.json"
  reports+=("${report_dir}/bregdcat-ap-2.0.0.json")

  post_shacl \
    "${out_dir}/dcat.bregdcat-ap.jsonld" \
    "https://www.itb.ec.europa.eu/shacl/bregdcat-ap/api/validate" \
    "bregdcatap.2_1_0" \
    "${report_dir}/bregdcat-ap-2.1.0.json"
  assert_no_errors "${report_dir}/bregdcat-ap-2.1.0.json"
  reports+=("${report_dir}/bregdcat-ap-2.1.0.json")
fi

jq -r '
  [
    input_filename,
    (.overview.profileID // "unknown-profile"),
    (.result // "unknown-result"),
    (.counters.nrOfErrors // 0),
    (.counters.nrOfWarnings // 0)
  ] | @tsv
' "${reports[@]}"
