#!/usr/bin/env bash
set -euo pipefail

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stack_root="${REGISTRY_STACK_SOURCE_DIR:-${lab_root}/..}"
platform_dir="${REGISTRY_PLATFORM_SOURCE_DIR:-${stack_root}}"
manifest_dir="${REGISTRY_MANIFEST_REPO:-${stack_root}}"
relay_dir="${REGISTRY_RELAY_SOURCE_DIR:-${stack_root}/crates/registry-relay}"
notary_dir="${REGISTRY_NOTARY_SOURCE_DIR:-${stack_root}}"
notary_ci_dir="${REGISTRY_NOTARY_CI_DIR:-}"
if [[ -z "${notary_ci_dir}" ]]; then
  if [[ -f "${notary_dir}/products/notary/justfile" ]]; then
    notary_ci_dir="${notary_dir}/products/notary"
  else
    notary_ci_dir="${notary_dir}"
  fi
fi

require_repo() {
  local name="$1"
  local dir="$2"
  if [[ ! -f "${dir}/Cargo.toml" ]]; then
    echo "commons-check failed: ${name} checkout not found at ${dir}" >&2
    exit 2
  fi
}

require_path() {
  local name="$1"
  local path="$2"
  if [[ ! -e "${path}" ]]; then
    echo "commons-check failed: ${name} not found at ${path}" >&2
    exit 2
  fi
}

run_in_dir() {
  local dir="$1"
  shift
  echo "==> commons-check: (cd ${dir} && $*)"
  (cd "${dir}" && "$@")
}

slug() {
  printf '%s' "$1" | tr '/ :' '---' | tr -cd '[:alnum:]_.-'
}

run_platform_checks() {
  if [[ -f "${platform_dir}/crates/registry-platform-authcommon/Cargo.toml" ]]; then
    run_in_dir "${platform_dir}" cargo test --locked --all-features \
      -p registry-platform-audit \
      -p registry-platform-authcommon \
      -p registry-platform-cache \
      -p registry-platform-config \
      -p registry-platform-crypto \
      -p registry-platform-httpsec \
      -p registry-platform-httputil \
      -p registry-platform-oid4vci \
      -p registry-platform-oidc \
      -p registry-platform-ops \
      -p registry-platform-pdp \
      -p registry-platform-replay \
      -p registry-platform-sdjwt \
      -p registry-platform-sts \
      -p registry-platform-testing
  else
    run_in_dir "${platform_dir}" cargo test --workspace --all-features
  fi
}

run_manifest_checks() {
  if [[ -f "${manifest_dir}/crates/registry-manifest-cli/Cargo.toml" ]]; then
    local out_root="${manifest_dir}/target/commons-check/contract-kernel"
    local profiles_dir="products/manifest/profiles"
    if [[ ! -d "${manifest_dir}/${profiles_dir}" ]]; then
      profiles_dir="profiles"
    fi
    run_in_dir "${manifest_dir}" cargo test --locked -p registry-manifest-core -p registry-manifest-cli
    run_in_dir "${manifest_dir}" cargo run --locked -p registry-manifest-cli -- validate-profiles "${profiles_dir}"
    mkdir -p "${out_root}"
    for manifest in "${lab_root}/config/static-metadata/metadata.yaml" "${lab_root}"/config/relay/*.metadata.yaml; do
      local name
      name="$(slug "${manifest}")"
      run_in_dir "${manifest_dir}" cargo run --locked -p registry-manifest-cli -- validate "${manifest}"
      run_in_dir "${manifest_dir}" cargo run --locked -p registry-manifest-cli -- publish "${manifest}" --out "${out_root}/${name}"
    done
  else
    run_in_dir "${manifest_dir}" scripts/check-contract-kernel.sh "${lab_root}/config/static-metadata/metadata.yaml" "${lab_root}"/config/relay/*.metadata.yaml
  fi
}

require_repo "registry-platform" "${platform_dir}"
require_repo "registry-manifest" "${manifest_dir}"
require_repo "registry-relay" "${relay_dir}"
require_repo "registry-notary" "${notary_dir}"
require_path "registry-notary ci justfile" "${notary_ci_dir}/justfile"

run_platform_checks
run_manifest_checks
run_in_dir "${relay_dir}" just ci-preflight
run_in_dir "${notary_ci_dir}" just ci-preflight

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
