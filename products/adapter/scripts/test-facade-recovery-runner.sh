#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
runner="$repo_root/products/adapter/examples/facade-recovery/run-loopback.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/adapter-facade-recovery-runner.XXXXXX")
mock_bin="$test_root/bin"
calls="$test_root/docker-calls"
stdout="$test_root/stdout"
stderr="$test_root/stderr"
container_id=0000000000000000000000000000000000000000000000000000000000000001

cleanup_test() {
	rm -f "$mock_bin/docker" "$mock_bin/git" "$calls" "$stdout" "$stderr"
	rmdir "$mock_bin" "$test_root"
}
trap cleanup_test EXIT

mkdir -p "$mock_bin"

cat >"$mock_bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$MOCK_REPOSITORY"
EOF

cat >"$mock_bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$DOCKER_CALLS"
case "$1" in
	run)
		if [[ "$MOCK_DOCKER_SCENARIO" == collision ]]; then
			printf '%s\n' 'name is already in use' >&2
			exit 125
		fi
		printf '%s\n' "$MOCK_CONTAINER_ID"
		;;
	exec)
		exit 0
		;;
	port)
		printf '%s\n' '127.0.0.1:54321'
		;;
	rm)
		if [[ "$MOCK_DOCKER_SCENARIO" == cleanup-failure ]]; then
			printf '%s\n' 'synthetic cleanup failure' >&2
			exit 1
		fi
		;;
	*)
		printf 'unexpected docker command: %s\n' "$*" >&2
		exit 2
		;;
esac
EOF

chmod 755 "$mock_bin/docker" "$mock_bin/git"

cargo() {
	return 0
}
export -f cargo

run_runner() {
	PATH="$mock_bin:$PATH" \
		CARGO_TARGET_DIR="$test_root/target" \
		MOCK_REPOSITORY="$repo_root" \
		MOCK_CONTAINER_ID="$container_id" \
		MOCK_DOCKER_SCENARIO="$1" \
		DOCKER_CALLS="$calls" \
		"$runner" >"$stdout" 2>"$stderr"
}

: >"$calls"
collision_status=0
run_runner collision || collision_status=$?
if [[ "$collision_status" != 125 ]]; then
	printf 'collision exited %s instead of 125\n' "$collision_status" >&2
	exit 1
fi
if grep -Eq '^rm ' "$calls"; then
	printf '%s\n' 'a failed create attempted to remove a container it did not own' >&2
	exit 1
fi

: >"$calls"
cleanup_status=0
run_runner cleanup-failure || cleanup_status=$?
if [[ "$cleanup_status" != 1 ]]; then
	printf 'cleanup failure exited %s instead of 1\n' "$cleanup_status" >&2
	exit 1
fi
if ! grep -Fqx "rm -f -v $container_id" "$calls"; then
	printf '%s\n' 'cleanup did not remove owned anonymous volumes using the returned container ID' >&2
	exit 1
fi
if ! grep -Fq 'Failed to remove owned PostgreSQL container' "$stderr"; then
	printf '%s\n' 'cleanup failure was not reported' >&2
	exit 1
fi

printf '%s\n' 'facade recovery runner ownership checks passed'
