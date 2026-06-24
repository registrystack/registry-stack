#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
platform_dir="${REGISTRY_PLATFORM_SOURCE_DIR:-${lab_root}/../registry-platform}"
manifest_dir="${REGISTRY_MANIFEST_REPO:-${lab_root}/vendor/registry-manifest}"
relay_dir="${REGISTRY_RELAY_SOURCE_DIR:-${lab_root}/../registry-relay}"
notary_dir="${REGISTRY_NOTARY_SOURCE_DIR:-${lab_root}/../registry-notary}"

require_repo() {
  local name="$1"
  local dir="$2"
  if [[ ! -f "${dir}/Cargo.toml" ]]; then
    echo "commons-check failed: ${name} checkout not found at ${dir}" >&2
    exit 2
  fi
}

run_in_dir() {
  local dir="$1"
  shift
  echo "==> commons-check: (cd ${dir} && $*)"
  (cd "${dir}" && "$@")
}

require_repo "registry-platform" "${platform_dir}"
require_repo "registry-manifest" "${manifest_dir}"
require_repo "registry-relay" "${relay_dir}"
require_repo "registry-notary" "${notary_dir}"

run_in_dir "${platform_dir}" cargo test --workspace --all-features
run_in_dir "${manifest_dir}" scripts/check-contract-kernel.sh "${lab_root}/config/static-metadata/metadata.yaml" "${lab_root}"/config/relay/*.metadata.yaml
run_in_dir "${relay_dir}" env REGISTRY_PLATFORM_SOURCE_DIR="${platform_dir}" scripts/check-platform-compat.sh
run_in_dir "${notary_dir}" env REGISTRY_PLATFORM_SOURCE_DIR="${platform_dir}" scripts/check-platform-compat.sh

tmp_dir="$(mktemp -d)"
created_env_file=0
cleanup() {
  if [[ "${created_env_file}" == "1" ]]; then
    rm -f "${lab_root}/.env"
  fi
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

demo_issuer_jwk='{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}'
export CLAIM_VERIFICATION_BINDING_KEY="${CLAIM_VERIFICATION_BINDING_KEY:-hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
export REGISTRY_RELAY_AUDIT_HASH_SECRET="${REGISTRY_RELAY_AUDIT_HASH_SECRET:-commons-check-registry-relay-audit-secret-32b}"
export REGISTRY_NOTARY_AUDIT_HASH_SECRET="${REGISTRY_NOTARY_AUDIT_HASH_SECRET:-commons-check-registry-notary-audit-secret-32}"
export REGISTRY_NOTARY_ISSUER_JWK="${REGISTRY_NOTARY_ISSUER_JWK:-${demo_issuer_jwk}}"

if [[ ! -e "${lab_root}/.env" ]]; then
  created_env_file=1
  {
    printf 'CLAIM_VERIFICATION_BINDING_KEY=%q\n' "${CLAIM_VERIFICATION_BINDING_KEY}"
    printf 'REGISTRY_RELAY_AUDIT_HASH_SECRET=%q\n' "${REGISTRY_RELAY_AUDIT_HASH_SECRET}"
    printf 'REGISTRY_NOTARY_AUDIT_HASH_SECRET=%q\n' "${REGISTRY_NOTARY_AUDIT_HASH_SECRET}"
    printf 'REGISTRY_NOTARY_ISSUER_JWK=%q\n' "${REGISTRY_NOTARY_ISSUER_JWK}"
  } >"${lab_root}/.env"
fi

run_in_dir "${lab_root}" env REGISTRY_RELAY_SOURCE_DIR="${relay_dir}" REGISTRY_PLATFORM_SOURCE_DIR="${platform_dir}" REGISTRY_LAB_ZITADEL_ENV_FILE="${tmp_dir}/zitadel.env" scripts/check-relay-zitadel.sh
run_in_dir "${lab_root}" env REGISTRY_NOTARY_SOURCE_DIR="${notary_dir}" REGISTRY_PLATFORM_SOURCE_DIR="${platform_dir}" scripts/check-notary-redis.sh
