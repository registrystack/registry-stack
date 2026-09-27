#!/usr/bin/env bash
set -euo pipefail

# Starts a disposable TLS-only PostGIS container for this checkout, configured
# the way the breg-contracts CI job configures its service, and prints the
# export lines the TLS proof and the adopter workflow read:
#
#   eval "$(products/breg/scripts/local-postgres-tls.sh)"
#   products/breg/scripts/test-postgres-tls.sh
#   products/breg/scripts/test-adopter-workflow.sh
#
# Re-running reuses the container and reissues its certificate. --stop removes
# the container. Everything except the export lines goes to stderr.

# Same image as the breg-contracts service in .github/workflows/ci.yml.
image='postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6'

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
checkout_name=$(basename -- "$repo_root" | tr -c 'A-Za-z0-9_.-\n' '-')
container="breg-pg-tls-${checkout_name}"
tls_dir="$repo_root/target/breg-postgres-tls"

case "${1:-}" in
  "") ;;
  --stop)
    docker rm -f "$container" >/dev/null 2>&1 || true
    printf '%s\n' "Removed $container." >&2
    exit 0
    ;;
  *)
    printf '%s\n' 'usage: local-postgres-tls.sh [--stop]' >&2
    exit 2
    ;;
esac

for tool in docker openssl pg_isready psql; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "$tool is required on PATH (pg_isready and psql come with the PostgreSQL client tools)." >&2
    exit 2
  fi
done

if [[ -z "$(docker ps -q --filter "name=^${container}$")" ]]; then
  docker rm -f "$container" >/dev/null 2>&1 || true
  printf '%s\n' "Starting $container." >&2
  docker run -d --name "$container" \
    -e POSTGRES_DB=breg -e POSTGRES_PASSWORD=breg_test -e POSTGRES_USER=breg \
    -p 127.0.0.1::5432 --platform linux/amd64 "$image" >/dev/null
  # The PostGIS image starts PostgreSQL twice during initialization, so the
  # first readiness is not the real server.
  for attempt in {1..120}; do
    ready_count=$(docker logs "$container" 2>&1 | grep -c 'database system is ready to accept connections' || true)
    if [[ "$ready_count" -ge 2 ]] && docker exec "$container" psql -q -U breg -d breg -c 'select 1' >/dev/null 2>&1; then
      break
    fi
    if [[ "$attempt" == 120 ]]; then
      printf '%s\n' "$container did not finish initializing; see docker logs $container." >&2
      exit 1
    fi
    sleep 1
  done
fi

container_id=$(docker inspect -f '{{.Id}}' "$container")
port=$(docker port "$container" 5432/tcp | head -n 1)
port=${port##*:}
# The server certificate names localhost; 127.0.0.1 is the hostname-mismatch case.
database_url="postgresql://breg:breg_test@localhost:${port}/breg"
mismatch_url="postgresql://breg:breg_test@127.0.0.1:${port}/breg"
mkdir -p "$tls_dir"
ca_pem="$tls_dir/ca.pem"

BREG_TEST_TLS_SETUP_ONLY=1 \
  BREG_TEST_TLS_POSTGRES_CONTAINER_ID="$container_id" \
  BREG_TEST_TLS_DATABASE_URL="$database_url" \
  BREG_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL="$mismatch_url" \
  BREG_TEST_TLS_DATABASE_HOST=localhost \
  BREG_TEST_TLS_CA_PEM_PATH="$ca_pem" \
  "$script_dir/test-postgres-tls.sh" >&2

printf '%s\n' "$container accepts TLS connections only, on localhost:${port}." >&2
cat <<EXPORTS
export BREG_TEST_DATABASE_URL='$database_url'
export BREG_TEST_TLS_DATABASE_URL='$database_url'
export BREG_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL='$mismatch_url'
export BREG_TEST_TLS_DATABASE_HOST='localhost'
export BREG_TEST_TLS_POSTGRES_CONTAINER_ID='$container_id'
export BREG_TEST_TLS_CA_PEM_PATH='$ca_pem'
EXPORTS
