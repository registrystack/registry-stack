#!/usr/bin/env bash
set -euo pipefail

site_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
repository=$(cd "$site_root/../.." && pwd)
tutorial="$site_root/src/content/docs/tutorials/publish-and-consume-discovery-index.mdx"
product_runner="$repository/products/discovery/scripts/test-adopter-tutorial.sh"
expected_shell_fences=5
dry_run=0

case "${1:-}" in
"") ;;
--dry-run) dry_run=1 ;;
*)
	printf 'unknown argument: %s (expected --dry-run)\n' "$1" >&2
	exit 2
	;;
esac

for path in "$tutorial" "$product_runner"; do
	if [[ ! -f "$path" ]]; then
		printf 'required Discovery tutorial input not found: %s\n' "$path" >&2
		exit 1
	fi
done

shell_fences=$(awk '/^```sh[[:space:]]*$/ { count += 1 } END { print count + 0 }' "$tutorial")
if ((shell_fences != expected_shell_fences)); then
	printf 'Discovery tutorial drift: expected %d shell fences, found %d\n' \
		"$expected_shell_fences" "$shell_fences" >&2
	exit 1
fi

required_literals=(
	'persona:'
	'  - assertion provider'
	'  - data publisher'
	'  - operator'
	'  - consumer or verifier'
	'products/discovery/tutorial/project/origins.yaml'
	'products/discovery/tutorial/project/mappings/adult-status.yaml'
	'bash products/discovery/scripts/test-adopter-tutorial.sh'
	'[operator] offline check: valid origins=2 mappings=1'
	'[operator] readiness: {"status":"ready"}'
	'[consumer] resolved evidenceType=urn:example:evidence-type:adult-status alternatives=1'
	'[handoff] adopter-owned Evidence trust accepted; native assertion verified'
	'[handoff] adopter-owned Relay trust accepted; native list response verified'
	'[cleanup] local services stopped; temporary project removed'
	'Tier-C evidence:'
)
for literal in "${required_literals[@]}"; do
	if ! rg --fixed-strings --quiet "$literal" "$tutorial"; then
		printf 'Discovery tutorial drift: missing literal: %s\n' "$literal" >&2
		exit 1
	fi
done

printf 'Discovery tutorial dry-run: %d shell fences and required role/output literals present\n' \
	"$shell_fences"
if ((dry_run)); then
	exit 0
fi

transcript=$(mktemp "${TMPDIR:-/tmp}/discovery-tutorial-transcript.XXXXXX")
cleanup() {
	rm -f "$transcript"
}
trap cleanup EXIT

if ! (cd "$repository" && bash "$product_runner") | tee "$transcript"; then
	printf '%s\n' 'Discovery tutorial execution failed' >&2
	exit 1
fi

expected_output=(
	'[provider] evidence.jsonld sha256=fc96f3a8cb0d82239425ea5712dceca975a5899e5528616648174da661fae905'
	'[provider] relay.jsonld sha256=5a34fa469803b7c28b3d5e7134a42398e326a2f173aacae9090d29787bc8f4d7'
	'[operator] offline check: valid origins=2 mappings=1'
	'[operator] explicit build: built catalogRevision=sha256:b4b7195f36691c245bf49a88a248049ed899c0c41dbf1a87a386571c0dbfba0f mappingRevision=sha256:332004ca3920c498539180946e8f2637e9998ba7e49cd98f31e19d6f818857ac'
	'[operator] readiness: {"status":"ready"}'
	'[consumer] resolved evidenceType=urn:example:evidence-type:adult-status alternatives=1'
	'[consumer] selected evidence recordId=urn:registrystack:discovery:record:sha256:676659c10ce5cc9d353f4fd2816673c7947e612151efbbe1cc4d42372d9be9d5'
	'[consumer] selected relay recordId=urn:registrystack:discovery:record:sha256:aa220c11f493c266bc22adf5dc7ca82fb7a83842e6e887dc0e8e5680f4f84244'
	'[handoff] adopter-owned Evidence trust accepted; native assertion verified'
	'[handoff] adopter-owned Relay trust accepted; native list response verified'
	'[cleanup] local services stopped; temporary project removed'
	'Registry Discovery adopter tutorial: PASS'
)
for expected in "${expected_output[@]}"; do
	if ! rg --fixed-strings --quiet "$expected" "$transcript"; then
		printf 'Discovery tutorial output missing: %s\n' "$expected" >&2
		exit 1
	fi
done

printf '%s\n' 'Discovery tutorial reader gate: PASS'
