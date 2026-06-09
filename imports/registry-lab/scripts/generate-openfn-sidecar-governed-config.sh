#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
notary_root="${REGISTRY_NOTARY_SOURCE_DIR:-${repo_root}/../registry-notary}"
jobs_root="${REGISTRY_LAB_OPENFN_JOBS_ROOT:-/tmp/registry-lab-openfn-jobs}"
manifest="${repo_root}/config/coolify/openfn/openfn-dhis2-sidecar.yaml.template"
governed_dir="${repo_root}/config/coolify/openfn/governed"
target="${governed_dir}/openfn-dhis2-sidecar-runtime.json"
metadata_dir="${governed_dir}/tuf/metadata"
targets_dir="${governed_dir}/tuf/targets"
datastore_dir="${repo_root}/output/openfn-sidecar-tuf-datastore"
report="${governed_dir}/openfn-dhis2-sidecar-runtime.report.json"
bootstrap="${repo_root}/config/coolify/openfn/openfn-dhis2-sidecar.bootstrap.yaml"
notary_config="${repo_root}/config/coolify/notary/dhis2-health-notary.yaml"
previous_hash="sha256:0000000000000000000000000000000000000000000000000000000000000000"
signer_kid="8ec3a843a0f9328c863cac4046ab1cacbbc67888476ac7acf73d9bcd9a223ada"

if [[ ! -d "${notary_root}" ]]; then
  echo "registry-notary checkout not found at ${notary_root}" >&2
  exit 1
fi

tough_data="$(
  find "${CARGO_HOME:-${HOME}/.cargo}/registry/src" \
    -path '*/tough-0.22.0/tests/data/simple-rsa/root.json' \
    -print -quit 2>/dev/null | sed 's#/simple-rsa/root.json$##'
)"
if [[ -z "${tough_data}" ]]; then
  echo "tough 0.22.0 test data not found in Cargo cache; run a Cargo build first" >&2
  exit 1
fi

rm -rf "${governed_dir}" "${datastore_dir}"
mkdir -p "${jobs_root}" "${metadata_dir}" "${targets_dir}" "${datastore_dir}"
find "${jobs_root}" -mindepth 1 -delete
cp -a "${repo_root}/config/openfn/jobs/." "${jobs_root}/"

cargo run -q \
  --manifest-path "${notary_root}/Cargo.toml" \
  -p registry-notary-openfn-sidecar \
  --bin registry-notary-openfn-sidecar \
  -- config render-target \
  --manifest "${manifest}" \
  --jobs-root "${jobs_root}" \
  --output "${target}"

cargo run -q \
  --manifest-path "${notary_root}/Cargo.toml" \
  -p registry-notary-openfn-sidecar \
  --bin registry-notary-openfn-sidecar \
  -- config create-local-tuf-repo \
  --target "${target}" \
  --target-name openfn-dhis2-sidecar-runtime.json \
  --root-path "${tough_data}/simple-rsa/root.json" \
  --signing-key-path "${tough_data}/snakeoil.pem" \
  --metadata-dir "${metadata_dir}" \
  --targets-dir "${targets_dir}" \
  --product registry-notary-openfn-sidecar \
  --instance-id hosted-dhis2-openfn-sidecar \
  --environment hosted-lab \
  --stream-id dhis2-openfn-sidecar-runtime \
  --bundle-id registry-lab-hosted-dhis2-openfn-sidecar-2026-06-09 \
  --sequence 1 \
  --previous-config-hash "${previous_hash}" \
  --change-class openfn_sidecar_runtime \
  --change-class openfn_sidecar_workflow_bundle \
  --change-class openfn_sidecar_source_binding \
  --declared-signer-kid "${signer_kid}" >/dev/null

cargo run -q \
  --manifest-path "${notary_root}/Cargo.toml" \
  -p registry-notary-openfn-sidecar \
  --bin registry-notary-openfn-sidecar \
  -- config verify-bundle \
  --product registry-notary-openfn-sidecar \
  --instance-id hosted-dhis2-openfn-sidecar \
  --environment hosted-lab \
  --stream-id dhis2-openfn-sidecar-runtime \
  --root-path "${metadata_dir}/1.root.json" \
  --metadata-dir "${metadata_dir}" \
  --targets-dir "${targets_dir}" \
  --datastore-dir "${datastore_dir}" \
  --target-name openfn-dhis2-sidecar-runtime.json > "${report}"

python3 - "$bootstrap" "$notary_config" "$report" <<'PY'
import json
import sys
from pathlib import Path

bootstrap = Path(sys.argv[1])
notary_config = Path(sys.argv[2])
report = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
config_hash = report["config_hash"]
root_hash = report["tuf"]["root_sha256"]

bootstrap_text = "\n".join(
    f"      tuf_root_sha256: {root_hash}"
    if line.strip().startswith("tuf_root_sha256:")
    else line
    for line in bootstrap.read_text(encoding="utf-8").splitlines()
) + "\n"
bootstrap.write_text(bootstrap_text, encoding="utf-8")

notary_text = notary_config.read_text(encoding="utf-8")
block = [
    "      expected_sidecar:",
    "        product: registry-notary-openfn-sidecar",
    "        instance_id: hosted-dhis2-openfn-sidecar",
    "        environment: hosted-lab",
    "        stream_id: dhis2-openfn-sidecar-runtime",
    f"        config_hash: {config_hash}",
    "        require_expression_hashes_verified: true",
    "        require_runtime_verified: true",
    "        require_smoke_verified: true",
]
out = []
in_connection = False
skip_expected = False
inserted = False
for line in notary_text.splitlines():
    if line == "    dhis2_openfn:":
        in_connection = True
        skip_expected = False
        out.append(line)
        continue
    if in_connection and line.startswith("    ") and not line.startswith("      "):
        in_connection = False
        skip_expected = False
    if in_connection and line == "      expected_sidecar:":
        skip_expected = True
        continue
    if skip_expected:
        if line.startswith("        "):
            continue
        skip_expected = False
    out.append(line)
    if in_connection and line == "      token_env: OPENFN_SIDECAR_TOKEN_RAW":
        out.extend(block)
        inserted = True
if not inserted:
    raise SystemExit("could not update dhis2_openfn expected_sidecar block")
notary_config.write_text("\n".join(out) + "\n", encoding="utf-8")

print(config_hash)
PY
