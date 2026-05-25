#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
relay_dir="${REGISTRY_RELAY_SOURCE_DIR:-"${demo_dir}/vendor/registry-relay"}"
postgres_port="${REGISTRY_LAB_POSTGRES_PORT:-54329}"

wait_postgres() {
  local deadline="${POSTGRES_WAIT_SECONDS:-90}"
  local start
  start="$(date +%s)"
  while (( $(date +%s) - start < deadline )); do
    if docker compose -f "${compose_file}" exec -T postgres pg_isready -U postgres -d registry_lab >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Postgres did not become ready within ${deadline}s" >&2
  return 1
}

cd "${demo_dir}"
docker compose -f "${compose_file}" up -d postgres
wait_postgres

export DATA_GATE_POSTGRES_TEST_URL="${DATA_GATE_POSTGRES_TEST_URL:-postgres://postgres:postgres@127.0.0.1:${postgres_port}/registry_lab?sslmode=disable}"

cd "${relay_dir}"
cargo test --test postgres_snapshot -- --ignored --test-threads=1
