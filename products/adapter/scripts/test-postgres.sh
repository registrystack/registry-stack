#!/usr/bin/env bash
set -euo pipefail

: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to an external worktree Cargo target.}"

# The Adapter PostgreSQL gate: runs the adapter crates' PostgreSQL-gated
# suites. Without ADAPTER_TEST_DATABASE_URL this script starts its own
# disposable loopback PostgreSQL 17 container, proves it answers queries,
# and removes it on the way out; with the variable set it uses that server
# as given and touches nothing outside this process.

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
cd "$repo_root"

# Same image as the CI postgres services in .github/workflows/ci.yml.
image='docker.io/library/postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'
db_user=adapter
db_password=adapter_test
db_name=adapter

container=
cleanup() {
	# Best effort for a container this run started; the failure that led
	# here is the one worth seeing, and a container that is already gone
	# needs no removal.
	if [[ -n "$container" ]] && [[ -n "$(docker ps -aq --filter "name=^${container}$")" ]]; then
		docker rm -f "$container" >/dev/null
		printf '%s\n' "Removed $container." >&2
	fi
}

if [[ -z "${ADAPTER_TEST_DATABASE_URL:-}" ]]; then
	if ! command -v docker >/dev/null 2>&1; then
		printf '%s\n' 'docker is required on PATH to start the test database (or set ADAPTER_TEST_DATABASE_URL).' >&2
		exit 2
	fi
	trap cleanup EXIT
	checkout_hash=$(printf '%s' "$repo_root" | openssl dgst -sha256 -r | cut -c1-8)
	container="adapter-pg-test-${checkout_hash}-$$"
	printf '%s\n' "Starting $container (loopback PostgreSQL 17)." >&2
	docker run -d --name "$container" \
		-e POSTGRES_USER="$db_user" -e POSTGRES_PASSWORD="$db_password" -e POSTGRES_DB="$db_name" \
		-p 127.0.0.1::5432 "$image" >/dev/null
	for attempt in {1..60}; do
		if docker exec "$container" pg_isready -h 127.0.0.1 -U "$db_user" -d "$db_name" >/dev/null 2>&1; then
			break
		fi
		if [[ "$attempt" == 60 ]]; then
			printf '%s\n' "$container never accepted connections; see docker logs $container." >&2
			exit 1
		fi
		sleep 1
	done
	# The image's temporary initialization server accepts Unix sockets;
	# probe the final TCP listener and prove it really answers a query.
	if ! answered=$(docker exec "$container" psql -h 127.0.0.1 -v ON_ERROR_STOP=1 -qAt -U "$db_user" -d "$db_name" -c 'select 1'); then
		printf '%s\n' "$container refused the connectivity probe; see docker logs $container." >&2
		exit 1
	fi
	if [[ "$answered" != 1 ]]; then
		printf '%s\n' "$container answered '$answered' to the connectivity probe instead of 1." >&2
		exit 1
	fi
	port=$(docker port "$container" 5432/tcp | head -n 1)
	port=${port##*:}
	export ADAPTER_TEST_DATABASE_URL="postgresql://${db_user}:${db_password}@localhost:${port}/${db_name}"
	printf '%s\n' "$container is serving ${db_name} on localhost:${port}." >&2
else
	printf '%s\n' 'Using ADAPTER_TEST_DATABASE_URL from the environment.' >&2
fi

# Native source-shape acceptance invokes the matching authoring CLI as well as
# the feature-enabled runtime. Build the CLI first: building default-feature
# binaries during native tests can replace the runtime they are executing.
PATH="$HOME/.cargo/bin:$PATH" cargo build --locked -p registry-adapterctl
export ADAPTERCTL_BIN="${CARGO_TARGET_DIR}/debug/adapterctl"

# The postgres-test feature gates the suites that need the database, so a
# plain cargo test run never silently skips them.
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter --features postgres-test

# The governed-ingestion job sources (CONCEPT 17), each behind its own
# default-off feature: the file source lane, the postgres source lane,
# and the live postgres suite, whose read-only authority, statement
# bound, and bounded fetch prove themselves against this same server
# through the engine's host-supplied client seam.
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter --features job-file
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter --features job-file,job-postgres
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter --features job-file,job-postgres,postgres-test --test camel_sql
