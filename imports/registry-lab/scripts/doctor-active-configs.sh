#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab_root="$(cd "${script_dir}/.." && pwd)"
cd "${lab_root}"

relay_bin="${REGISTRY_RELAY_BIN:-registry-relay}"
notary_bin="${REGISTRY_NOTARY_BIN:-registry-notary}"
profile="${REGISTRY_LAB_DOCTOR_PROFILE:-local}"
env_file="${REGISTRY_LAB_DOCTOR_ENV_FILE:-.env}"
out_dir="${REGISTRY_LAB_DOCTOR_OUTPUT_DIR:-output/config-doctor}"
summary_path="${out_dir}/summary.json"

if [[ -n "${env_file}" && ! -f "${env_file}" ]]; then
  env_file=""
fi

relay_configs=()
while IFS= read -r line; do
  relay_configs+=("${line}")
done < <(
  find config/relay config/coolify/relay \
    -maxdepth 1 \
    -type f \
    -name '*.yaml' \
    ! -name '*.metadata.yaml' \
    -print 2>/dev/null |
    sort
)
notary_configs=()
while IFS= read -r line; do
  notary_configs+=("${line}")
done < <(
  find config/notary config/coolify/notary \
    -maxdepth 1 \
    -type f \
    -name '*.yaml' \
    -print 2>/dev/null |
    sort
)

fail() {
  printf 'FAILED: %s\n' "$1" >&2
  exit 1
}

slug() {
  printf '%s' "$1" | tr '/.' '--' | tr -c 'A-Za-z0-9_-' '-'
}

run_product_doctor() {
  local product="$1"
  local binary="$2"
  local config="$3"
  local report="$4"
  local stderr_path="$5"
  local -a args=(doctor --config "${config}" --format json --profile "${profile}")
  if [[ -n "${env_file}" ]]; then
    args+=(--env-file "${env_file}")
  fi

  set +e
  "${binary}" "${args[@]}" >"${report}" 2>"${stderr_path}"
  local status="$?"
  set -e

  python3 - "$product" "$config" "$status" "$report" <<'PY'
import json
import sys

product, config, process_status, report_path = sys.argv[1:5]
if process_status != "0":
    print(
        f"{product} {config}: doctor process failed with exit code {process_status}",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    with open(report_path, "r", encoding="utf-8") as handle:
        report = json.load(handle)
except Exception as exc:
    print(f"{product} {config}: doctor did not emit JSON: {exc}", file=sys.stderr)
    sys.exit(1)

schema = report.get("schema_version")
if schema != "registry.config.diagnostic_report.v1":
    print(
        f"{product} {config}: unsupported diagnostic schema {schema!r}",
        file=sys.stderr,
    )
    sys.exit(1)

status = report.get("status")
if status == "error":
    print(
        f"{product} {config}: doctor failed with report status {status}",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"{product} {config}: {status}")
PY
}

mkdir -p "${out_dir}/relay" "${out_dir}/notary"

failures=0
for config in "${relay_configs[@]}"; do
  name="$(slug "${config}")"
  report="${out_dir}/relay/${name}.json"
  stderr_path="${out_dir}/relay/${name}.stderr.txt"
  if ! run_product_doctor "registry-relay" "${relay_bin}" "${config}" "${report}" "${stderr_path}"; then
    failures=$((failures + 1))
  fi
done

for config in "${notary_configs[@]}"; do
  name="$(slug "${config}")"
  report="${out_dir}/notary/${name}.json"
  stderr_path="${out_dir}/notary/${name}.stderr.txt"
  if ! run_product_doctor "registry-notary" "${notary_bin}" "${config}" "${report}" "${stderr_path}"; then
    failures=$((failures + 1))
  fi
done

python3 - "$summary_path" "$profile" "${#relay_configs[@]}" "${#notary_configs[@]}" "$failures" <<'PY'
import json
import os
import sys

summary_path, profile, relay_count, notary_count, failures = sys.argv[1:6]
summary = {
    "schema_version": "registry.lab.config_doctor_summary.v1",
    "profile": profile,
    "relay_config_count": int(relay_count),
    "notary_config_count": int(notary_count),
    "failure_count": int(failures),
}
os.makedirs(os.path.dirname(summary_path), exist_ok=True)
with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2)
    handle.write("\n")
PY

if [[ "${#relay_configs[@]}" -eq 0 ]]; then
  fail "no active Relay configs found"
fi
if [[ "${#notary_configs[@]}" -eq 0 ]]; then
  fail "no active Notary configs found"
fi
if [[ "${failures}" -ne 0 ]]; then
  fail "${failures} active config doctor check(s) failed; see ${out_dir}"
fi

printf 'Active config doctor summary: %s\n' "${summary_path}"
