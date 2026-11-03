#!/usr/bin/env bash
set -euo pipefail

: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to an external worktree Cargo target.}"

# The ingestion-job host's PostgreSQL gate: runs registry-adapter-job's
# postgres-test suites, the item-table edges the in-process tests cannot
# reach (the lease, the crash replay, the refusal run, the position
# rules, the no-payload invariant). Without ADAPTER_TEST_DATABASE_URL
# this script starts its own disposable loopback PostgreSQL 17 container,
# proves it answers queries, and removes it on the way out; with the
# variable set it uses that server as given. The SFTP CLI acceptance uses
# the same database. RabbitMQ acceptance always owns disposable broker
# containers, including when the PostgreSQL server was supplied externally.

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
cd "$repo_root"

# Same image as the CI postgres services in .github/workflows/ci.yml.
image='docker.io/library/postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'
db_user=adapter
db_password=adapter_test
db_name=adapter

container_id=
container_name=
cleanup() {
	local status=$?
	trap - EXIT
	if [[ -n "$container_id" ]]; then
		if docker rm -fv "$container_id" >/dev/null; then
			printf '%s\n' "Removed owned PostgreSQL fixture ${container_id:0:12}." >&2
		else
			printf '%s\n' "Failed to remove owned PostgreSQL fixture ${container_id:0:12}." >&2
			if [[ "$status" == 0 ]]; then
				status=1
			fi
		fi
	fi
	exit "$status"
}

if ! command -v docker >/dev/null 2>&1; then
	printf '%s\n' 'docker is required on PATH for the owned RabbitMQ fixtures and the default PostgreSQL fixture.' >&2
	exit 2
fi

if [[ -z "${ADAPTER_TEST_DATABASE_URL:-}" ]]; then
	trap cleanup EXIT
	checkout_hash=$(printf '%s' "$repo_root" | openssl dgst -sha256 -r | cut -c1-8)
	container_name="adapter-job-pg-test-${checkout_hash}-$$"
	if [[ -n "$(docker ps -aq --filter "name=^${container_name}$")" ]]; then
		printf '%s\n' "$container_name already exists; refusing to reuse it." >&2
		exit 1
	fi
	printf '%s\n' "Starting $container_name (loopback PostgreSQL 17)." >&2
	created_container_id=
	if created_container_id=$(docker run -d --name "$container_name" \
		-e POSTGRES_USER="$db_user" -e POSTGRES_PASSWORD="$db_password" -e POSTGRES_DB="$db_name" \
		-p 127.0.0.1::5432 "$image"); then
		if [[ ! "$created_container_id" =~ ^[0-9a-f]{64}$ ]]; then
			printf '%s\n' 'Docker returned an invalid container ID for the PostgreSQL fixture.' >&2
			exit 1
		fi
		container_id=$created_container_id
	else
		printf '%s\n' 'Docker could not create the PostgreSQL fixture.' >&2
		exit 1
	fi
	for attempt in {1..60}; do
		if docker exec "$container_id" pg_isready -h 127.0.0.1 -U "$db_user" -d "$db_name" >/dev/null 2>&1; then
			break
		fi
		if [[ "$attempt" == 60 ]]; then
			printf '%s\n' "The owned PostgreSQL fixture ${container_id:0:12} never accepted connections." >&2
			exit 1
		fi
		sleep 1
	done
	# The image's temporary initialization server accepts Unix sockets;
	# probe the final TCP listener and prove it really answers a query.
	if ! answered=$(docker exec "$container_id" psql -h 127.0.0.1 -v ON_ERROR_STOP=1 -qAt -U "$db_user" -d "$db_name" -c 'select 1'); then
		printf '%s\n' "The owned PostgreSQL fixture ${container_id:0:12} refused the connectivity probe." >&2
		exit 1
	fi
	if [[ "$answered" != 1 ]]; then
		printf '%s\n' "The owned PostgreSQL fixture ${container_id:0:12} returned an unexpected connectivity-probe answer." >&2
		exit 1
	fi
	port=$(docker port "$container_id" 5432/tcp | head -n 1)
	port=${port##*:}
	export ADAPTER_TEST_DATABASE_URL="postgresql://${db_user}:${db_password}@localhost:${port}/${db_name}"
	printf '%s\n' "The owned PostgreSQL fixture ${container_id:0:12} is serving ${db_name} on localhost:${port}." >&2
else
	printf '%s\n' 'Using ADAPTER_TEST_DATABASE_URL from the environment.' >&2
fi

# This proof owns a separate TLS-only database even when the caller supplied
# ADAPTER_TEST_DATABASE_URL. The cancellation request uses the production TLS
# connector, so a plaintext source test is not an equivalent substitute.
"$repo_root/products/adapter/scripts/test-postgres-source-tls.sh"

# The postgres-test feature gates the suites that need the database, so a
# plain cargo test run never silently skips them. The suite shares one
# job row, whose lease serializes real passes; the tests run serially so
# a pass under test never leases against another test's expectations.
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features postgres-test -- --test-threads=1

# The signed destination suite exercises byte-stable retries across the
# store's PostgreSQL timestamp precision, including a lost admission answer.
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features postgres-test,signed-coordinator-event --test signed_coordinator_event_postgres -- --test-threads=1

# The host-level file proof binds row-decoder identity before source I/O and
# refuses legacy or changed selectors without calling the destination.
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features job-file,postgres-test,signed-coordinator-event --test job_file_host -- --test-threads=1

# Hook ingress only wakes the real CLI pass. This target proves authenticated
# socket admission and source re-read against the durable store; request bodies
# never become destination data.
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features job-hook,postgres-test --test hook_ingress_postgres -- --test-threads=1

# Exercise the actual job CLI across read-only SFTP, the durable item store and
# the destination receiver using the same disposable database authority.
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features job-sftp,postgres-test,signed-coordinator-event --test sftp_cli_host -- --test-threads=1

# Each broker target owns its loopback RabbitMQ fixtures. Serial execution
# keeps process-global TLS providers and synthetic credential environments
# isolated; the pass suite uses the PostgreSQL fixture above as well.
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features job-rabbitmq,rabbitmq-test-plaintext --test rabbitmq_source -- --test-threads=1
PATH="$HOME/.cargo/bin:$PATH" cargo test --locked -p registry-adapter-job --features job-rabbitmq,rabbitmq-test-plaintext,postgres-test,signed-coordinator-event --test rabbitmq_pass -- --test-threads=1

# Build BReg and Coordinator together from this checkout, then run the
# ignored job-destination proofs through the real product binaries and this
# disposable PostgreSQL authority. The Python runner selects the exact Cargo
# artifacts, so an ambient or previously frozen binary cannot enter the proof.
python3 products/adapter/scripts/test-connector-native.py --suite job-destinations
