#!/usr/bin/env bash
set -euo pipefail

: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to an external worktree Cargo target.}"

# A dedicated verified-TLS PostgreSQL fixture for the source cancellation
# boundary. It never reuses ADAPTER_TEST_DATABASE_URL: the public job gate must
# prove the production TLS cancellation transport even when its other suites
# use a caller-supplied plaintext database. Loopback proves that TLS branch;
# it is not evidence for ordinary private-network egress admission.

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
image='docker.io/library/postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'
db_user=adapter_tls
db_password=adapter_tls_test
db_name=adapter_tls
container_id=
# Set once this run is about to create the named container, so cleanup can
# remove it by name when docker run returns something other than an ID.
owned_name=
tls_dir=

cleanup() {
	local status=$?
	trap - EXIT
	local target=$container_id label=${container_id:0:12}
	if [[ -z "$target" && -n "$owned_name" && -n "$(docker ps -aq --filter "name=^${owned_name}$")" ]]; then
		target=$owned_name
		label=$owned_name
	fi
	if [[ -n "$target" ]]; then
		if docker rm -fv "$target" >/dev/null; then
			printf '%s\n' "Removed owned PostgreSQL TLS fixture $label." >&2
		else
			printf '%s\n' "Failed to remove owned PostgreSQL TLS fixture $label." >&2
			if [[ "$status" == 0 ]]; then
				status=1
			fi
		fi
	fi
	if [[ -n "$tls_dir" && -d "$tls_dir" ]]; then
		rm -f -- \
			"$tls_dir/trusted-ca.key" \
			"$tls_dir/trusted-ca.pem" \
			"$tls_dir/trusted-ca.srl" \
			"$tls_dir/server.key" \
			"$tls_dir/server.csr" \
			"$tls_dir/server.ext" \
			"$tls_dir/server.crt"
		if ! rmdir -- "$tls_dir"; then
			printf '%s\n' 'Failed to remove the PostgreSQL TLS fixture certificate directory.' >&2
			if [[ "$status" == 0 ]]; then
				status=1
			fi
		fi
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

for tool in docker openssl; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		printf '%s\n' "$tool is required on PATH for the PostgreSQL source TLS proof." >&2
		exit 2
	fi
done

tls_dir=$(mktemp -d "${TMPDIR:-/tmp}/adapter-postgres-source-tls.XXXXXX")
umask 077
openssl req -x509 -new -nodes -newkey rsa:2048 -sha256 -days 2 \
	-subj '/CN=Registry Adapter PostgreSQL source TLS test CA' \
	-keyout "$tls_dir/trusted-ca.key" -out "$tls_dir/trusted-ca.pem" >/dev/null 2>&1
openssl req -new -nodes -newkey rsa:2048 \
	-subj '/CN=localhost' \
	-keyout "$tls_dir/server.key" -out "$tls_dir/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost' >"$tls_dir/server.ext"
openssl x509 -req -sha256 -days 2 \
	-in "$tls_dir/server.csr" \
	-CA "$tls_dir/trusted-ca.pem" \
	-CAkey "$tls_dir/trusted-ca.key" \
	-CAcreateserial \
	-extfile "$tls_dir/server.ext" \
	-out "$tls_dir/server.crt" >/dev/null 2>&1
chmod 600 "$tls_dir"/*.key
chmod 644 "$tls_dir"/*.pem "$tls_dir"/*.crt

checkout_hash=$(printf '%s' "$repo_root" | openssl dgst -sha256 -r | cut -c1-8)
container_name="adapter-job-pg-tls-${checkout_hash}-$$"
if [[ -n "$(docker ps -aq --filter "name=^${container_name}$")" ]]; then
	printf '%s\n' "$container_name already exists; refusing to reuse it." >&2
	exit 1
fi
printf '%s\n' "Starting $container_name (verified-TLS PostgreSQL 17)." >&2
owned_name=$container_name
created_container_id=
if created_container_id=$(docker run -d --name "$container_name" \
	-e POSTGRES_USER="$db_user" -e POSTGRES_PASSWORD="$db_password" -e POSTGRES_DB="$db_name" \
	-p 127.0.0.1::5432 "$image"); then
	if [[ ! "$created_container_id" =~ ^[0-9a-f]{64}$ ]]; then
		printf '%s\n' 'Docker returned an invalid container ID for the PostgreSQL TLS fixture.' >&2
		exit 1
	fi
	container_id=$created_container_id
else
	printf '%s\n' 'Docker could not create the PostgreSQL TLS fixture.' >&2
	exit 1
fi

for attempt in {1..60}; do
	if docker exec "$container_id" pg_isready -h 127.0.0.1 -U "$db_user" -d "$db_name" >/dev/null 2>&1; then
		break
	fi
	if [[ "$attempt" == 60 ]]; then
		printf '%s\n' "The owned PostgreSQL TLS fixture ${container_id:0:12} never became ready." >&2
		exit 1
	fi
	sleep 1
done

postgres_data_directory=$(docker exec "$container_id" sh -c 'printf %s "$PGDATA"')
if [[ ! "$postgres_data_directory" =~ ^/var/lib/postgresql/[A-Za-z0-9_./-]+$ || "$postgres_data_directory" == *..* ]]; then
	printf '%s\n' 'The PostgreSQL TLS fixture reported an unsafe PGDATA path.' >&2
	exit 1
fi
docker cp "$tls_dir/server.crt" "$container_id:$postgres_data_directory/server.crt"
docker cp "$tls_dir/server.key" "$container_id:$postgres_data_directory/server.key"
docker cp "$tls_dir/trusted-ca.pem" "$container_id:$postgres_data_directory/fixture-ca.pem"
docker exec --user root "$container_id" sh -eu -c '
	chown postgres:postgres "$1/server.crt" "$1/server.key" "$1/fixture-ca.pem"
	chmod 644 "$1/server.crt" "$1/fixture-ca.pem"
	chmod 600 "$1/server.key"
	printf "\nssl = on\nssl_cert_file = '\''server.crt'\''\nssl_key_file = '\''server.key'\''\n" >> "$1/postgresql.conf"
	sed -i "s/^host /hostssl /" "$1/pg_hba.conf"
' sh "$postgres_data_directory"
docker exec --user postgres "$container_id" \
	pg_ctl -D "$postgres_data_directory" reload >/dev/null

for attempt in {1..30}; do
	tls_answer=
	if tls_answer=$(docker exec -e PGPASSWORD="$db_password" "$container_id" \
		psql -qAt -v ON_ERROR_STOP=1 \
		"host=localhost dbname=$db_name user=$db_user sslmode=verify-full sslrootcert=$postgres_data_directory/fixture-ca.pem" \
		-c 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()' 2>/dev/null) &&
		[[ "$tls_answer" == t ]]; then
		break
	fi
	if [[ "$attempt" == 30 ]]; then
		printf '%s\n' 'The PostgreSQL source TLS fixture did not accept a verified TLS connection.' >&2
		exit 1
	fi
	sleep 1
done

port=$(docker port "$container_id" 5432/tcp | head -n 1)
port=${port##*:}
export ADAPTER_POSTGRES_TLS_TEST_HOST=localhost
export ADAPTER_POSTGRES_TLS_TEST_PORT="$port"
export ADAPTER_POSTGRES_TLS_TEST_DATABASE="$db_name"
export ADAPTER_POSTGRES_TLS_TEST_USER="$db_user"
export ADAPTER_POSTGRES_TLS_TEST_PASSWORD="$db_password"
export ADAPTER_POSTGRES_TLS_TEST_CA_BUNDLE_FILE="$tls_dir/trusted-ca.pem"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_BUILD_JOBS=2

PATH="$HOME/.cargo/bin:$PATH" cargo test --locked \
	-p registry-adapter-job \
	--features postgres-tls-test \
	--lib \
	postgres_source::tests::tls_cancelled_read_is_detached_before_same_pool_creates_fresh_backend \
	-- --exact --nocapture
