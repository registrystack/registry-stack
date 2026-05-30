#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
demo_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${demo_dir}/compose.yaml"
relay_dir="${REGISTRY_RELAY_SOURCE_DIR:-"${demo_dir}/vendor/registry-relay"}"
output_dir="${demo_dir}/output"
env_file="${REGISTRY_LAB_ZITADEL_ENV_FILE:-"${output_dir}/zitadel.env"}"

wait_zitadel_init() {
  local deadline="${ZITADEL_WAIT_SECONDS:-180}"
  local start
  start="$(date +%s)"
  while (( $(date +%s) - start < deadline )); do
    local cid
    cid="$(docker compose -f "${compose_file}" ps -a -q zitadel-init 2>/dev/null || true)"
    if [[ -n "${cid}" ]]; then
      local state
      state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "${cid}")"
      if [[ "${state}" == "exited 0" ]]; then
        return 0
      fi
      if [[ "${state}" == exited\ * && "${state}" != "exited 0" ]]; then
        docker compose -f "${compose_file}" logs --no-color zitadel-init >&2 || true
        echo "Zitadel init failed (${state})" >&2
        return 1
      fi
    fi
    sleep 2
  done
  docker compose -f "${compose_file}" logs --no-color zitadel-init >&2 || true
  echo "Zitadel init did not complete within ${deadline}s" >&2
  return 1
}

cd "${demo_dir}"
docker compose -f "${compose_file}" up -d zitadel-init
wait_zitadel_init
mkdir -p "$(dirname "${env_file}")"
docker compose -f "${compose_file}" cp zitadel-init:/seed/zitadel.env "${env_file}" >/dev/null

set -a
# shellcheck disable=SC1090
. "${env_file}"
set +a

cd "${relay_dir}"
cargo test --test oidc_zitadel -- --ignored --nocapture
