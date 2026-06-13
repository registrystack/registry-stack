#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab_root="$(cd "${script_dir}/.." && pwd)"
cd "${lab_root}"

compose_files=(-f compose.yaml -f compose.lab2.yaml)
profile="${LAB2_DOCTOR_PROFILE:-hosted_lab}"
strict="${LAB2_DOCTOR_STRICT:-0}"
evidence_dir="${LAB2_DOCTOR_EVIDENCE_DIR:-output/lab2/evidence/doctor}"

fail() {
  echo "FAILED: $1" >&2
  exit 1
}

require_runtime_config() {
  test -f output/lab2/runtime-config/civil-registry-relay.yaml || fail "missing output/lab2/runtime-config/civil-registry-relay.yaml; run just lab2-generate"
  test -f output/lab2/runtime-config/civil-notary.yaml || fail "missing output/lab2/runtime-config/civil-notary.yaml; run just lab2-generate"
}

require_service() {
  local service="$1"
  local container_id
  container_id="$(docker compose "${compose_files[@]}" ps -q "${service}")"
  [[ -n "${container_id}" ]] || fail "${service} is not running; run just lab2-up"
}

run_doctor() {
  local service="$1"
  local out="$2"
  local err="$3"
  shift 3
  set +e
  docker compose "${compose_files[@]}" exec -T "${service}" "$@" > "${out}" 2> "${err}"
  local status="$?"
  set -e
  printf '%s\n' "${status}"
}

require_runtime_config
require_service lab2-civil-registry-relay
require_service lab2-civil-notary
mkdir -p "${evidence_dir}"

relay_out="${evidence_dir}/relay-doctor-${profile}.json"
relay_err="${evidence_dir}/relay-doctor-${profile}.stderr.txt"
notary_out="${evidence_dir}/notary-doctor-${profile}.json"
notary_err="${evidence_dir}/notary-doctor-${profile}.stderr.txt"

relay_status="$(run_doctor \
  lab2-civil-registry-relay \
  "${relay_out}" \
  "${relay_err}" \
  registry-relay \
  doctor \
  --config /etc/registry-relay/civil-registry-relay.yaml \
  --format json \
  --profile "${profile}")"

notary_status="$(run_doctor \
  lab2-civil-notary \
  "${notary_out}" \
  "${notary_err}" \
  registry-notary \
  --config /etc/registry-notary/civil-notary.yaml \
  doctor \
  --format json \
  --profile "${profile}")"

summary="${evidence_dir}/summary-${profile}.json"
summary_args=(
  --profile "${profile}"
  --relay-status "${relay_status}"
  --relay-report "${relay_out}"
  --notary-status "${notary_status}"
  --notary-report "${notary_out}"
  --summary "${summary}"
)
if [[ "${strict}" == "1" ]]; then
  summary_args+=(--strict)
fi
python3 scripts/lab2_doctor_summary.py "${summary_args[@]}"

echo "Lab 2 doctor profile report: ${summary}"
