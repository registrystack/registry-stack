#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
notary_root="${REGISTRY_NOTARY_SOURCE_DIR:-${repo_root}/../registry-notary}"
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
previous_hash="${PREVIOUS_HASH:-sha256:5dedb55ab547c38aeca1a7fab32c2f3d037e3a3f59527d324e39acc7a66a9262}"
sequence="${SEQUENCE:-4}"
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
mkdir -p "${metadata_dir}" "${targets_dir}" "${datastore_dir}"

cargo run -q \
  --manifest-path "${notary_root}/Cargo.toml" \
  -p registry-notary-source-adapter-sidecar \
  --bin registry-notary-source-adapter-sidecar \
  -- config render-target \
  --manifest "${manifest}" \
  --output "${target}"

cargo run -q \
  --manifest-path "${notary_root}/Cargo.toml" \
  -p registry-notary-source-adapter-sidecar \
  --bin registry-notary-source-adapter-sidecar \
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
  --sequence "${sequence}" \
  --previous-config-hash "${previous_hash}" \
  --change-class openfn_sidecar_runtime \
  --change-class openfn_sidecar_workflow_bundle \
  --change-class openfn_sidecar_source_binding \
  --declared-signer-kid "${signer_kid}" >/dev/null

cargo run -q \
  --manifest-path "${notary_root}/Cargo.toml" \
  -p registry-notary-source-adapter-sidecar \
  --bin registry-notary-source-adapter-sidecar \
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
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)

    def indent_of(line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    def yaml_key(line: str) -> str | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("- "):
            return None
        if ":" not in stripped:
            return None
        return stripped.split(":", 1)[0].strip("'\"")

    def find_path(dotted_path: str) -> int:
        parent_indent = -1
        search_from = 0
        for part in dotted_path.split("."):
            if part.isdigit():
                wanted_index = int(part)
                found_index = -1
                for index in range(search_from, len(lines)):
                    line = lines[index]
                    stripped = line.strip()
                    indent = indent_of(line)
                    if indent <= parent_indent and stripped:
                        break
                    if indent > parent_indent and stripped.startswith("- "):
                        found_index += 1
                        if found_index == wanted_index:
                            parent_indent = indent
                            search_from = index + 1
                            break
                else:
                    raise SystemExit(f"could not find YAML list index {dotted_path} in {path}")
                if found_index != wanted_index:
                    raise SystemExit(f"could not find YAML list index {dotted_path} in {path}")
                continue

            for index in range(search_from, len(lines)):
                line = lines[index]
                stripped = line.strip()
                indent = indent_of(line)
                if indent <= parent_indent and stripped:
                    break
                if indent > parent_indent and yaml_key(line) == part:
                    parent_indent = indent
                    search_from = index + 1
                    break
            else:
                raise SystemExit(f"could not find YAML path {dotted_path} in {path}")

        return search_from - 1

    for dotted_path, value in updates.items():
        line_index = find_path(dotted_path)
        key = dotted_path.rsplit(".", 1)[-1]
        indent = " " * indent_of(lines[line_index])
        newline = "\n" if lines[line_index].endswith("\n") else ""
        lines[line_index] = f"{indent}{key}: {value}{newline}"
    path.write_text("".join(lines), encoding="utf-8")


update_yaml(
    bootstrap,
    {
        "config_trust.accepted_roots.0.tuf_root_sha256": root_hash,
    },
)
update_yaml(
    notary_config,
    {
        "evidence.source_connections.dhis2_openfn.expected_sidecar.config_hash": config_hash,
    },
)

print(config_hash)
PY
