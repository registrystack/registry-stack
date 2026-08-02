#!/usr/bin/env bash
# Start a throwaway Mint and Evidence deployment on loopback, run the delegation
# walkthrough against them, then tear everything down.
#
# Nothing here is the demonstration. `walkthrough.py` is.
set -euo pipefail

demo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace="$(cd "${demo_dir}/../../.." && pwd)"
run_dir="${demo_dir}/.run"
log_dir="${run_dir}/logs"

# The source's bearer token. Generated per run, exported to the two processes
# that need it, and never printed or passed as an argument.
DEMO_SOURCE_TOKEN="$(openssl rand -hex 24)"
export DEMO_SOURCE_TOKEN

pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
  local port="$1" name="$2"
  for _ in $(seq 1 100); do
    if nc -z 127.0.0.1 "${port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  printf 'error: %s never listened on port %s\n' "${name}" "${port}" >&2
  printf 'see %s/%s.log\n' "${log_dir}" "${name}" >&2
  return 1
}

printf '== building mint and evidence\n'
cargo build --locked --manifest-path "${workspace}/Cargo.toml" \
  -p registry-mint -p registry-evidence --bins >/dev/null

printf '== provisioning a throwaway deployment in %s\n' "${run_dir}"
uv run --quiet "${demo_dir}/support/provision.py" "${run_dir}" "${demo_dir}/evidence-bundle" \
  >/dev/null
mkdir -p "${log_dir}"

printf '== starting the stand-in registry source, Mint, its TLS front, and Evidence\n'
uv run --quiet "${demo_dir}/support/mock_source.py" 8092 >"${log_dir}/source.log" 2>&1 &
pids+=("$!")

"${workspace}/target/debug/mint" serve --config "${run_dir}/mint/mint.yaml" \
  >"${log_dir}/mint.log" 2>&1 &
pids+=("$!")
wait_for_port 8090 mint

uv run --quiet "${demo_dir}/support/tls_front.py" 8443 8090 \
  "${run_dir}/tls.pem" "${run_dir}/tls.key" >"${log_dir}/tls.log" 2>&1 &
pids+=("$!")

# Evidence fetches Mint's key set over HTTPS. SSL_CERT_FILE is how the demo's
# private CA becomes trusted for this process, and only this process.
SSL_CERT_FILE="${run_dir}/ca.pem" \
  "${workspace}/target/debug/evidence" --runtime "${run_dir}/evidence/runtime.yaml" serve \
  >"${log_dir}/evidence.log" 2>&1 &
pids+=("$!")

wait_for_port 8092 source
wait_for_port 8443 tls
wait_for_port 8080 evidence

printf '\n'
uv run --quiet "${demo_dir}/walkthrough.py" "${run_dir}"
