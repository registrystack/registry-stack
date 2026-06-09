#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
notary_root="${REGISTRY_NOTARY_SOURCE_DIR:-${repo_root}/../registry-notary}"
jobs_root="${REGISTRY_LAB_OPENFN_JOBS_ROOT:-/tmp/registry-lab-openfn-jobs}"
manifest="${repo_root}/config/coolify/openfn/openfn-dhis2-sidecar.yaml.template"
governed_dir="${repo_root}/config/coolify/openfn/governed"
tuf_fixture_dir="${repo_root}/config/coolify/openfn/tuf-demo-fixtures"
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

if [[ ! -f "${tuf_fixture_dir}/simple-rsa/root.json" || ! -f "${tuf_fixture_dir}/snakeoil.pem" ]]; then
  echo "OpenFn sidecar demo TUF fixtures not found at ${tuf_fixture_dir}" >&2
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
  --root-path "${tuf_fixture_dir}/simple-rsa/root.json" \
  --signing-key-path "${tuf_fixture_dir}/snakeoil.pem" \
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

def update_yaml(path: Path, updates: dict[str, object]) -> None:
    import subprocess

    script = r'''
require "json"
require "yaml"

path = ARGV.fetch(0)
updates = JSON.parse(ARGV.fetch(1))
data = YAML.load_file(path)
abort("#{path} did not load as a YAML mapping") unless data.is_a?(Hash)

def fetch_child(node, key, dotted_path)
  if node.is_a?(Array)
    index = Integer(key)
    child = node[index]
  elsif node.is_a?(Hash)
    child = node[key]
  else
    abort("expected YAML collection before #{dotted_path}")
  end
  abort("missing YAML path #{dotted_path}") if child.nil?
  child
rescue ArgumentError
  abort("expected list index in YAML path #{dotted_path}")
end

updates.each do |dotted_path, value|
  keys = dotted_path.split(".")
  leaf = keys.pop
  parent = data
  keys.each_with_index do |key, index|
    parent = fetch_child(parent, key, keys[0..index].join("."))
  end
  if parent.is_a?(Array)
    index = Integer(leaf)
    next if parent[index] == value
    parent[index] = value
  elsif parent.is_a?(Hash)
    next if parent[leaf] == value
    parent[leaf] = value
  else
    abort("expected YAML collection before #{dotted_path}")
  end
  @changed = true
end

exit 0 unless @changed
File.write(path, "# SPDX-License-Identifier: Apache-2.0\n\n" + YAML.dump(data).sub(/\A---\n/, ""))
'''
    subprocess.run(
        ["ruby", "-e", script, str(path), json.dumps(updates)],
        check=True,
    )


update_yaml(
    bootstrap,
    {
        "config_trust.accepted_roots.0.tuf_root_sha256": root_hash,
    },
)
update_yaml(
    notary_config,
    {
        "evidence.source_connections.dhis2_openfn.expected_sidecar": {
            "product": "registry-notary-openfn-sidecar",
            "instance_id": "hosted-dhis2-openfn-sidecar",
            "environment": "hosted-lab",
            "stream_id": "dhis2-openfn-sidecar-runtime",
            "config_hash": config_hash,
            "require_expression_hashes_verified": True,
            "require_runtime_verified": True,
            "require_smoke_verified": True,
        },
    },
)

print(config_hash)
PY
