#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

scan_root="output/lab2"
evidence_root="${scan_root}/evidence"
text_report="${evidence_root}/secret-scan.txt"
json_report="${evidence_root}/secret-scan.json"
mkdir -p "${evidence_root}"

if [[ ! -d "${scan_root}" ]]; then
  echo "missing ${scan_root}; run just lab2-generate first" >&2
  exit 1
fi

tmp_values="$(mktemp)"
trap 'rm -f "${tmp_values}"' EXIT
: > "${tmp_values}"

load_env_file() {
  local env_file="$1"
  [[ -f "${env_file}" ]] || return 0
  while IFS='=' read -r key value; do
    [[ "${key}" =~ ^[A-Z0-9_]+$ ]] || continue
    case "${key}" in
      *_RAW|*_TOKEN|*_BEARER|*_AUDIT_HASH_SECRET|*_JWK|*_SECRET|CLAIM_VERIFICATION_BINDING_KEY|COOLIFY_*|REGISTRY_*PASSWORD*)
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
        if [[ ${#value} -ge 12 ]]; then
          printf '%s\t%s\n' "${key}" "${value}" >> "${tmp_values}"
        fi
        ;;
    esac
  done < "${env_file}"
}

load_env_file ".env"
load_env_file ".env.local"

while IFS='=' read -r key value; do
  [[ "${key}" =~ ^[A-Z0-9_]+$ ]] || continue
  case "${key}" in
    *_RAW|*_TOKEN|*_BEARER|*_AUDIT_HASH_SECRET|*_JWK|*_SECRET|CLAIM_VERIFICATION_BINDING_KEY|COOLIFY_*|REGISTRY_*PASSWORD*)
      if [[ ${#value} -ge 12 ]]; then
        printf '%s\t%s\n' "${key}" "${value}" >> "${tmp_values}"
      fi
      ;;
  esac
done < <(env)

scan_paths=(
  "${scan_root}/runtime-config"
  "${scan_root}/bundles"
  "${scan_root}/evidence"
  "${scan_root}/manifest.json"
  "${scan_root}/tuf-repo"
)

fail_scan() {
  local reason="$1"
  printf 'Lab 2 secret scan\nFAILED: %s\n' "${reason}" > "${text_report}"
  printf '{"status":"failed","reason":%s}\n' "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${reason}")" > "${json_report}"
  cat "${text_report}" >&2
  exit 1
}

grep_scan() {
  local mode="$1"
  local pattern="$2"
  local path="$3"
  if [[ -d "${path}" ]]; then
    find "${path}" -type f ! -name 'secret-scan.txt' ! -name 'secret-scan.json' -exec grep "${mode}" -- "${pattern}" {} + >/dev/null
  else
    grep "${mode}" -- "${pattern}" "${path}" >/dev/null
  fi
}

while IFS=$'\t' read -r key value; do
  [[ -n "${key:-}" && -n "${value:-}" ]] || continue
  for path in "${scan_paths[@]}"; do
    [[ -e "${path}" ]] || continue
    if grep_scan -F "${value}" "${path}"; then
      fail_scan "secret value leaked: ${key} in ${path}"
    fi
  done
done < "${tmp_values}"

for path in "${scan_paths[@]}"; do
  [[ -e "${path}" ]] || continue
  if grep_scan -E '"d"[[:space:]]*:' "${path}"; then
    fail_scan "private JWK member leaked in ${path}"
  fi
  if grep_scan -E 'BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY)' "${path}"; then
    fail_scan "PEM private key marker leaked in ${path}"
  fi
  if grep_scan -E 'Bearer [A-Za-z0-9._~+/-]{16,}' "${path}"; then
    fail_scan "bearer token pattern leaked in ${path}"
  fi
  if grep_scan -F 'EXERCISE-ONLY-BREAK-GLASS' "${path}"; then
    fail_scan "break-glass reason leaked in ${path}"
  fi
done

python3 - <<'PY' "${scan_root}/manifest.json" "${json_report}"
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
if not manifest_path.exists():
    raise SystemExit("missing manifest.json")

manifest = json.loads(manifest_path.read_text())
secret_artifacts = [
    artifact["path"]
    for artifact in manifest.get("artifacts", [])
    if artifact.get("secret_classification") == "secret"
]
public_artifacts = [
    artifact["path"]
    for artifact in manifest.get("artifacts", [])
    if artifact.get("secret_classification") == "public"
]
report_path.write_text(json.dumps({
    "status": "ok",
    "checked_paths": [
        "output/lab2/runtime-config",
        "output/lab2/bundles",
        "output/lab2/evidence",
        "output/lab2/manifest.json",
        "output/lab2/tuf-repo",
    ],
    "secret_artifacts": secret_artifacts,
    "public_artifacts": public_artifacts,
}, indent=2) + "\n")
PY

{
  echo "Lab 2 secret scan"
  echo "secret scan OK"
  echo "JSON report: ${json_report}"
} > "${text_report}"
cat "${text_report}"
