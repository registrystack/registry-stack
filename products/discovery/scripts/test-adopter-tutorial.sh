#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
target_dir="${DISCOVERY_TUTORIAL_TARGET_DIR:-$repository/target/discovery-tutorial-source}"
profile="${DISCOVERY_TUTORIAL_CARGO_PROFILE:-ci}"
work_root=$(mktemp -d "${TMPDIR:-/tmp}/discovery-adopter-tutorial.XXXXXX")
publication_pid=""
discovery_pid=""

cleanup() {
	local exit_code=$?
	set +e
	if [[ -n "$discovery_pid" ]]; then
		kill "$discovery_pid" 2>/dev/null
		wait "$discovery_pid" 2>/dev/null
	fi
	if [[ -n "$publication_pid" ]]; then
		kill "$publication_pid" 2>/dev/null
		wait "$publication_pid" 2>/dev/null
	fi
	chmod -R u+w "$work_root" 2>/dev/null
	rm -rf "$work_root"
	if ((exit_code == 0)); then
		printf '%s\n' '[cleanup] local services stopped; temporary project removed'
		printf '%s\n' 'Registry Discovery adopter tutorial: PASS'
	else
		printf 'Registry Discovery adopter tutorial: FAIL (exit %d)\n' "$exit_code" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for tool in cargo curl node npm python3; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		printf 'required tool not on PATH: %s\n' "$tool" >&2
		exit 1
	fi
done

case "$profile" in
ci | release) ;;
*)
	printf 'unsupported Cargo profile: %s (expected ci or release)\n' "$profile" >&2
	exit 1
	;;
esac

profile_dir="$profile"
if [[ -z "${DISCOVERY_BIN:-}" || -z "${DISCOVERYCTL_BIN:-}" ]]; then
	printf '%s\n' '[checkout] building discovery and discoveryctl from locked source'
	(
		cd "$repository"
		CARGO_BUILD_RUSTC_WRAPPER='' CARGO_INCREMENTAL=0 \
			CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
			CARGO_TARGET_DIR="$target_dir" \
			cargo build --quiet --locked --profile "$profile" \
				-p registry-discovery -p registry-discoveryctl
	)
	DISCOVERY_BIN="$target_dir/$profile_dir/discovery"
	DISCOVERYCTL_BIN="$target_dir/$profile_dir/discoveryctl"
fi

for binary in "$DISCOVERY_BIN" "$DISCOVERYCTL_BIN"; do
	if [[ "$binary" != /* || ! -x "$binary" ]]; then
		printf 'tutorial binary is not an executable absolute path: %s\n' "$binary" >&2
		exit 1
	fi
done

python3 - "$repository/products/discovery/fixtures/descriptions" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys

root = Path(sys.argv[1])
expected = {
    "evidence.jsonld": "fc96f3a8cb0d82239425ea5712dceca975a5899e5528616648174da661fae905",
    "relay.jsonld": "5a34fa469803b7c28b3d5e7134a42398e326a2f173aacae9090d29787bc8f4d7",
}
for name, digest in expected.items():
    actual = sha256((root / name).read_bytes()).hexdigest()
    if actual != digest:
        raise SystemExit(f"publication digest mismatch for {name}: {actual}")
    print(f"[provider] {name} sha256={actual}")
PY

cp -R "$repository/products/discovery/tutorial/project/." "$work_root/"

check_output=$("$DISCOVERYCTL_BIN" check --project "$work_root" --allow-loopback)
if [[ "$check_output" != "valid origins=2 mappings=1" ]]; then
	printf 'unexpected discoveryctl check output: %s\n' "$check_output" >&2
	exit 1
fi
printf '[operator] offline check: %s\n' "$check_output"

python3 "$repository/products/discovery/tutorial/publication_server.py" \
	--descriptions "$repository/products/discovery/fixtures/descriptions" \
	>"$work_root/publication.log" 2>&1 &
publication_pid=$!

for _ in {1..50}; do
	if curl --fail --silent --output /dev/null "http://127.0.0.1:38090/evidence.jsonld"; then
		break
	fi
	if ! kill -0 "$publication_pid" 2>/dev/null; then
		printf '%s\n' 'the tutorial publication server stopped before readiness' >&2
		sed -n '1,80p' "$work_root/publication.log" >&2
		exit 1
	fi
	sleep 0.1
done
if ! curl --fail --silent --output /dev/null "http://127.0.0.1:38090/relay.jsonld"; then
	printf '%s\n' 'the tutorial publication server did not become ready' >&2
	exit 1
fi

build_output=$("$DISCOVERYCTL_BIN" build \
	--project "$work_root" \
	--output "$work_root/discovery-index.json" \
	--allow-loopback)
if [[ ! "$build_output" =~ ^built\ catalogRevision=sha256:[0-9a-f]{64}\ mappingRevision=sha256:[0-9a-f]{64}$ ]]; then
	printf 'unexpected discoveryctl build output: %s\n' "$build_output" >&2
	exit 1
fi
printf '[operator] explicit build: %s\n' "$build_output"

"$DISCOVERY_BIN" --runtime "$work_root/runtime.yaml" \
	>"$work_root/discovery.log" 2>&1 &
discovery_pid=$!

ready=""
for _ in {1..50}; do
	if ready=$(curl --fail --silent "http://127.0.0.1:38080/ready"); then
		break
	fi
	if ! kill -0 "$discovery_pid" 2>/dev/null; then
		printf '%s\n' 'Discovery stopped before readiness' >&2
		sed -n '1,80p' "$work_root/discovery.log" >&2
		exit 1
	fi
	sleep 0.1
done
if [[ "$ready" != '{"status":"ready"}' ]]; then
	printf 'unexpected readiness response: %s\n' "$ready" >&2
	exit 1
fi
printf '[operator] readiness: %s\n' "$ready"

curl --fail --silent \
	-H 'Content-Type: application/json' \
	--data '{"requirementId":"urn:example:requirement:adult-status","jurisdiction":"urn:example:jurisdiction"}' \
	"http://127.0.0.1:38080/v1/evidence-types/resolve" \
	>"$work_root/resolution.json"
curl --fail --silent --get \
	--data-urlencode 'serviceKind=evidence' \
	--data-urlencode 'evidenceType=urn:example:evidence-type:adult-status' \
	"http://127.0.0.1:38080/v1/services" \
	>"$work_root/evidence-search.json"
curl --fail --silent --get \
	--data-urlencode 'serviceKind=relay' \
	--data-urlencode 'semanticClass=urn:example:class:person' \
	--data-urlencode 'operationFamily=urn:example:operation:lookup' \
	"http://127.0.0.1:38080/v1/services" \
	>"$work_root/relay-search.json"

python3 "$repository/products/discovery/tutorial/verify_outputs.py" \
	--resolution "$work_root/resolution.json" \
	--evidence-search "$work_root/evidence-search.json" \
	--relay-search "$work_root/relay-search.json" \
	--output "$work_root/selections.json" \
	| while IFS= read -r line; do printf '[consumer] %s\n' "$line"; done

native_log="$work_root/native-journey.log"
if ! (
	cd "$repository"
	CARGO_BUILD_RUSTC_WRAPPER='' CARGO_INCREMENTAL=0 \
		CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
		CARGO_TARGET_DIR="$target_dir" \
		cargo test --quiet --locked --profile "$profile" \
			-p registry-discovery-client --test native_journey \
			complete_evidence_and_relay_journeys_build_select_trust_and_invoke_natively \
			-- --exact
) >"$native_log" 2>&1; then
	printf '%s\n' 'the native Evidence and Relay handoff journey failed' >&2
	sed -n '1,160p' "$native_log" >&2
	exit 1
fi
printf '%s\n' '[handoff] adopter-owned Evidence trust accepted; native assertion verified'
printf '%s\n' '[handoff] adopter-owned Relay trust accepted; native list response verified'

node_log="$work_root/node-handoff.log"
if ! (
	cd "$repository/crates/registry-discovery-client-node"
	npm ci --ignore-scripts --no-audit --no-fund
	CARGO_BUILD_RUSTC_WRAPPER='' CARGO_INCREMENTAL=0 \
		CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
		npm run build:debug
	npm test
) >"$node_log" 2>&1; then
	printf '%s\n' 'the Node.js structural validation, acceptance, and renewal tests failed' >&2
	sed -n '1,200p' "$node_log" >&2
	exit 1
fi

python_log="$work_root/python-handoff.log"
if ! (
	cd "$repository/crates/registry-discovery-client-py"
	CARGO_BUILD_RUSTC_WRAPPER='' CARGO_INCREMENTAL=0 \
		CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
		python3 -m unittest discover -s tests/python -v
) >"$python_log" 2>&1; then
	printf '%s\n' 'the Python structural validation, acceptance, and renewal tests failed' >&2
	sed -n '1,200p' "$python_log" >&2
	exit 1
fi
