#!/usr/bin/env bash
# A scripted local run of the citizen journey: MCP tool calls through the
# breg-mcp binary, submission on the breg-review binary's page, the review
# authority's approval, and the registry's apply, until the gateway reports
# the application as applied. README.md in this directory describes what each
# party is and which one is a stub.
#
# With BREG_TEST_DATABASE_URL set, the run creates a fresh database on that
# PostgreSQL 17 server and drops it at the end. Without it, the run starts a
# disposable postgres:17 container on a loopback port and removes it at exit.
set -euo pipefail

acceptance_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "$acceptance_root/../../../.." && pwd)
target_root=${CARGO_TARGET_DIR:-$repository_root/target}
# shellcheck source-path=SCRIPTDIR source=../../../../scripts/cargo-runtime-library-path.sh
. "$repository_root/scripts/cargo-runtime-library-path.sh"

work=$(mktemp -d "${TMPDIR:-/tmp}/citizen-local-run.XXXXXX")
container=""

finish() {
  local status=$?
  if [[ -n "$container" ]]; then
    if ! docker rm -f "$container" >/dev/null; then
      printf 'could not remove the container %s; remove it by hand\n' "$container" >&2
      status=1
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    rm -rf -- "$work"
  else
    printf 'the run failed; the binaries'\'' logs and configuration stay in %s\n' "$work" >&2
  fi
  exit "$status"
}
trap finish EXIT

start_postgres() {
  local password port attempt
  password=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  container="citizen-local-run-$$"
  # The password reaches the container through an owner-only file, never a
  # command line.
  printf 'POSTGRES_PASSWORD=%s\n' "$password" >"$work/postgres.env"
  chmod 600 "$work/postgres.env"
  docker run --detach --name "$container" --env-file "$work/postgres.env" \
    --publish 127.0.0.1::5432 postgres:17 >/dev/null
  rm -f -- "$work/postgres.env"
  port=$(docker port "$container" 5432/tcp)
  port=${port##*:}
  for attempt in $(seq 1 60); do
    if docker exec "$container" pg_isready --host 127.0.0.1 --username postgres >/dev/null 2>&1; then
      BREG_TEST_DATABASE_URL="postgresql://postgres:$password@127.0.0.1:$port/postgres"
      export BREG_TEST_DATABASE_URL
      printf 'postgres: a disposable postgres:17 container is ready on 127.0.0.1:%s\n' "$port"
      return 0
    fi
    sleep 1
  done
  printf 'postgres: the container was not ready after %s attempts\n' "$attempt" >&2
  return 1
}

if [[ -z "${BREG_TEST_DATABASE_URL:-}" ]]; then
  start_postgres
else
  printf 'postgres: using the server BREG_TEST_DATABASE_URL names\n'
fi

printf 'build: breg-mcp, breg-review, and the local run driver\n'
registry_cargo_build "$repository_root" --locked \
  -p registry-breg-mcp -p registry-breg-review --bins
registry_cargo_build "$repository_root" --locked \
  -p registry-breg-mcp --features postgres-test --example citizen_local_run

"$target_root/debug/examples/citizen_local_run" \
  "$target_root/debug/breg-mcp" \
  "$target_root/debug/breg-review" \
  "$work"
