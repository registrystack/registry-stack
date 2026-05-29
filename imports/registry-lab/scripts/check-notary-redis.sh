#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"

platform_src="${REGISTRY_PLATFORM_SOURCE_DIR:-}"
if [[ -z "${platform_src}" ]]; then
  platform_src="${demo_dir}/../registry-platform"
  [[ -f "${platform_src}/Cargo.toml" ]] || platform_src="${demo_dir}/vendor/registry-platform"
fi

notary_src="${REGISTRY_NOTARY_SOURCE_DIR:-}"
if [[ -z "${notary_src}" ]]; then
  notary_src="${demo_dir}/../registry-notary"
  [[ -f "${notary_src}/Cargo.toml" ]] || notary_src="${demo_dir}/vendor/registry-notary"
fi
redis_port="${REGISTRY_LAB_REDIS_PORT:-63799}"
redis_url="${REGISTRY_PLATFORM_REDIS_TEST_URL:-"redis://127.0.0.1:${redis_port}/"}"

if [[ ! -f "${platform_src}/Cargo.toml" ]]; then
  echo "Registry Platform checkout not found at ${platform_src}; set REGISTRY_PLATFORM_SOURCE_DIR." >&2
  exit 1
fi

if [[ ! -f "${notary_src}/Cargo.toml" ]]; then
  echo "Registry Notary checkout not found at ${notary_src}; set REGISTRY_NOTARY_SOURCE_DIR." >&2
  exit 1
fi

docker compose -f "${compose_file}" up -d redis

for _ in $(seq 1 30); do
  if docker compose -f "${compose_file}" exec -T redis redis-cli ping >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker compose -f "${compose_file}" exec -T redis redis-cli ping >/dev/null 2>&1; then
  docker compose -f "${compose_file}" logs --no-color redis >&2 || true
  echo "Redis did not become ready." >&2
  exit 1
fi

(
  cd "${platform_src}"
  REGISTRY_PLATFORM_REDIS_TEST_URL="${redis_url}" \
    cargo test -p registry-platform-replay --features redis redis_replay_store_round_trips_when_env_is_set --lib
)

(
  cd "${notary_src}"
  REGISTRY_PLATFORM_REDIS_TEST_URL="${redis_url}" \
  REGISTRY_NOTARY_REDIS_URL="${redis_url}" \
    cargo test -p registry-notary-server redis_store_records_reads_updates_and_checks_readiness_when_env_is_set --lib
)

echo "notary Redis checks OK"
