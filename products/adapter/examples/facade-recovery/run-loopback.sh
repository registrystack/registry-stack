#!/usr/bin/env bash
set -euo pipefail

script_dir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
repository=$(git -C "$script_dir" rev-parse --show-toplevel)
postgres_image='docker.io/library/postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'
container="adapter-facade-recovery-${PPID}-$$"
container_id=

: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to a target directory outside the repository.}"

cleanup() {
	local script_status=$?
	trap - EXIT
	if [[ -n "$container_id" ]] && ! docker rm -f -v "$container_id" >/dev/null; then
		printf 'Failed to remove owned PostgreSQL container %s.\n' "$container_id" >&2
		if [[ "$script_status" == 0 ]]; then
			script_status=1
		fi
	fi
	exit "$script_status"
}
trap cleanup EXIT

container_id=$(docker run --detach --name "$container" \
	--env POSTGRES_USER=adapter \
	--env POSTGRES_PASSWORD=adapter_test \
	--env POSTGRES_DB=adapter \
	--publish 127.0.0.1::5432 "$postgres_image")

for attempt in {1..60}; do
	if docker exec "$container_id" pg_isready \
		-h 127.0.0.1 -U adapter -d adapter >/dev/null 2>&1; then
		break
	fi
	if [[ "$attempt" == 60 ]]; then
		printf '%s\n' 'PostgreSQL did not become ready.' >&2
		exit 1
	fi
	sleep 1
done

port=$(docker port "$container_id" 5432/tcp)
port=${port##*:}
export ADAPTER_TEST_DATABASE_URL="postgresql://adapter:adapter_test@127.0.0.1:${port}/adapter"

CARGO_TARGET_DIR="$CARGO_TARGET_DIR" \
	CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
	CARGO_INCREMENTAL=0 \
	CARGO_PROFILE_DEV_DEBUG=0 \
	CARGO_PROFILE_TEST_DEBUG=0 \
	PATH="$HOME/.cargo/bin:$PATH" \
	cargo test --locked --manifest-path "$repository/Cargo.toml" \
	-p registry-adapter --features postgres-test \
	--test postgres_async_status_link \
	a_public_facade_recovery_starter_runs_the_live_retry_contract \
	-- --exact --nocapture
