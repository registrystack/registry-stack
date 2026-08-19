#!/usr/bin/env bash
#
# Run the Discovery adopter tutorial's journey and check what it did.
#
# What this gate is for: proving the adopter journey the page documents still
# runs end to end, and that its transcript still shows the behaviour a
# successful exit does not already prove. Content-addressed revisions that are
# still reproducible, a consumer that still resolves and selects, handoffs that
# still verify against adopter-owned trust.
#
# What this gate is NOT for: policing what the page says. It pins no fence
# count and no page wording. Prose, roles, headings, output blocks and the
# order they appear in are free to change without touching this file. The one
# thing the page owes this gate is naming the same command the gate runs,
# because unlike the Evidence tutorial gate this one does not replay the page's
# own fences: it runs the product's adopter runner directly, and if the page
# stopped pointing at that runner the two would drift apart in silence.
#
# If you find yourself adding an array of strings the page must contain, stop.
# That is the pinning this file deliberately does not do.
set -euo pipefail

site_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
repository=$(cd "$site_root/../.." && pwd)
tutorial="${DISCOVERY_TUTORIAL_PAGE:-$site_root/src/content/docs/tutorials/publish-and-consume-discovery-index.mdx}"
product_runner="$repository/products/discovery/scripts/test-adopter-tutorial.sh"
# The command the page hands the reader, which is the command this gate runs.
documented_command='bash products/discovery/scripts/test-adopter-tutorial.sh'
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

if ! grep -Fq -- "$documented_command" "$tutorial"; then
	printf 'Discovery tutorial drift: the page no longer documents the command this gate runs\n' >&2
	printf 'This gate runs the product adopter runner directly rather than replaying the page,\n' >&2
	printf 'so the page must still hand the reader: %s\n' "$documented_command" >&2
	exit 1
fi

shell_fences=$(awk '/^```sh[[:space:]]*$/ { count += 1 } END { print count + 0 }' "$tutorial")
printf 'Discovery tutorial dry-run: %d shell fences, running the documented adopter runner\n' \
	"$shell_fences"
if ((dry_run)); then
	printf '%s\n' 'Discovery tutorial reader gate: dry run only'
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

# Behaviour the runner's own exit status does not prove. The published
# documents are content addressed, so their digests and the revisions built
# from them are the assertion that the journey is still reproducible, and the
# consumer and handoff lines are the assertion that something was actually
# resolved, selected and verified rather than skipped. One test decides
# membership here: would this regress silently, without the runner exiting
# non-zero? Do not add anything the page merely says.
expected_output=(
	'[provider] evidence.jsonld sha256=fc96f3a8cb0d82239425ea5712dceca975a5899e5528616648174da661fae905'
	'[provider] relay.jsonld sha256=5a34fa469803b7c28b3d5e7134a42398e326a2f173aacae9090d29787bc8f4d7'
	'[operator] offline check: valid origins=2 mappings=1'
	'[operator] explicit build: built catalogRevision=sha256:b4b7195f36691c245bf49a88a248049ed899c0c41dbf1a87a386571c0dbfba0f mappingRevision=sha256:332004ca3920c498539180946e8f2637e9998ba7e49cd98f31e19d6f818857ac'
	'[consumer] resolved evidenceType=urn:example:evidence-type:adult-status alternatives=1'
	'[consumer] selected evidence recordId=urn:registrystack:discovery:record:sha256:676659c10ce5cc9d353f4fd2816673c7947e612151efbbe1cc4d42372d9be9d5'
	'[consumer] selected relay recordId=urn:registrystack:discovery:record:sha256:aa220c11f493c266bc22adf5dc7ca82fb7a83842e6e887dc0e8e5680f4f84244'
	'[handoff] adopter-owned Evidence trust accepted; native assertion verified'
	'[handoff] adopter-owned Relay trust accepted; native list response verified'
	'[cleanup] local services stopped; temporary project removed'
)
for expected in "${expected_output[@]}"; do
	if ! grep -Fq -- "$expected" "$transcript"; then
		printf 'Discovery tutorial output missing: %s\n' "$expected" >&2
		exit 1
	fi
done

printf '%s\n' 'Discovery tutorial reader gate: PASS'
