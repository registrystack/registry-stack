#!/usr/bin/env bash
#
# Execute the current Evidence tutorials from a fresh reader directory.
#
# What this gate is for: proving that the commands the tutorials document still
# run, and that a short list of behaviours a successful exit does not already
# prove still holds. A refusal that still refuses, tampering that is still
# caught, an audit entry that still records the disclosure it should.
#
# What this gate is NOT for: policing what a page says. It pins no fence count,
# no command string and no documented output. Prose, the text around a
# heading, output blocks and command wording are free to change without touching
# this file, and a writer may add or remove a command block under a heading the
# journey already runs with no change here at all. If you find yourself adding
# an array of strings a page must contain, stop: that is the pinning this file
# deliberately does not do, and it is what made these tutorials unreadable for
# a human reader once already.
#
# This gate builds the Evidence toolset from the checked-out source unless
# EVIDENCE_BIN, EVIDENCECTL_BIN, EVIDENCE_OID4VCI_BIN and MINT_BIN select exact
# candidate or released bytes, then replays each registered tutorial's own
# shell fences in its own reader directory. Every tutorial creates the files it
# needs from its documented commands, so what CI runs is what a reader copies.
#
# Usage:
#   scripts/check-evidence-tutorials.sh                 replay every tutorial
#   scripts/check-evidence-tutorials.sh --dry-run       resolve the journeys only
#   scripts/check-evidence-tutorials.sh --only <slug>   one tutorial and its prerequisites
#
# Registering a tutorial means adding its slug to EVIDENCE_TUTORIALS and a
# branch to load_spec. Each spec holds two things:
#
#   SPEC_STEPS    the reader journey, in order. It need not follow document
#                 order: a tutorial that leaves one terminal in an earlier
#                 directory is replayed by running its later fence first.
#                 Fences are addressed by the heading they sit under, never by
#                 position, so inserting a command block cannot silently move a
#                 step onto the wrong command.
#                   run:<Heading>              execute every sh fence under
#                                              that heading, in document order
#                   run:<Heading>|<n>          execute the nth sh fence under
#                                              that heading
#                   run-fails:<Heading>|<n>    execute one sh fence the page
#                                              documents as refused, and
#                                              require a non-zero exit
#                   background:<Heading>|<n>   run a one-line sh fence the page
#                                              leaves running in a second
#                                              terminal
#                   stop-background            stop the most recently started
#                                              background fence, where the page
#                                              says to press Ctrl+C
#                   save:H|lang|occ|target     write a documented non-shell
#                                              fence to the file the reader is
#                                              told to create
#                   edit:H|lang|occ|H2|lang2|occ2|target
#                                              apply a documented before/after
#                                              fence pair to an existing file
#                   wait-http:URL              block until that URL answers
#                   python-client              install the Python client from
#                                              this checkout, standing in for
#                                              the documented clone and build
#                   fhir-mock                  start the sanitized local FHIR
#                                              mock this gate carries
#                   track-pid:PATH             adopt a PID a fence wrote, so
#                                              cleanup reaches it
#                 The |<n> suffix is optional wherever a heading holds a single
#                 sh fence. Skipping is implicit: a fence under no listed
#                 heading is simply not run, and the summary names it so a
#                 reviewer can see the unverified surface.
#
#   SPEC_ASSERTS  behaviours the replay transcript must still show. One test
#                 decides membership: would this regress silently, without any
#                 command exiting non-zero? Startup chatter, "created", "ready"
#                 and "prepared" lines fail that test, because the next command
#                 would have failed without them. Do not grow this back into a
#                 transcript pin.
#
# Renaming a heading breaks the steps that name it, by name, in --dry-run.
# That is the trade, and it is a good one: a renamed heading is a structural
# edit to the journey, it fails loudly rather than replaying the wrong command,
# and it is exactly when the journey is worth walking again.
#
# Configuration:
#   EVIDENCE_BIN / EVIDENCECTL_BIN /      run these exact binaries instead of
#   EVIDENCE_OID4VCI_BIN / MINT_BIN       building from source
#   EVIDENCE_OID4VCI_INTEROP_TEST_BIN     run this prebuilt sanitized flow test
#   EVIDENCE_CLIENT_PY_LIB                import this prebuilt Python client
#                                         module instead of building one
#   EVIDENCE_TUTORIAL_CARGO_PROFILE       ci (default) or release
#   EVIDENCE_TUTORIAL_DOCS_ROOT           tutorial directory override (tests)

set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$SITE_ROOT/../.." && pwd)"
# A fence helper written against the replay userland's floor: it locates a
# fence by heading, language and occurrence and applies it to a file, using
# only the shell and coreutils the container carries.
FENCE="$SITE_ROOT/scripts/evidence-tutorial-fence.sh"
FHIR_TUTORIAL_MOCK="$SITE_ROOT/scripts/fixtures/fhir-tutorial-mock.py"
DOCS_ROOT="${EVIDENCE_TUTORIAL_DOCS_ROOT:-$SITE_ROOT/src/content/docs/tutorials}"
BUILD_PROFILE="${EVIDENCE_TUTORIAL_CARGO_PROFILE:-ci}"
TARGET_DIR="$REPO_ROOT/target/evidence-tutorial-source"

# ---------------------------------------------------------------------------
# Registered tutorials
# ---------------------------------------------------------------------------

EVIDENCE_TUTORIALS=(
	first-evidence-assertion
	request-evidence-as-sd-jwt-vc
	run-oid4vci-interoperability-checks
	request-evidence-from-an-application
	return-a-governed-value
	assert-a-role-bound-relationship
	refuse-unsafe-evidence-requests
	verify-an-assertion-as-a-consumer
	control-who-can-request-evidence
	issue-fhir-evidence-as-vcs
)

# Every other page under DOCS_ROOT, and the reason it is not replayed here.
# check_tutorial_coverage below fails by name on a page in neither list, which
# is the gap that let broken DHIS2 tutorial commands ship once already.
EXCLUDED_EVIDENCE_TUTORIALS=(
	build-and-deploy-evidence-project                # drift-checked by evidence-production-build-docs.test.mjs; needs a production build environment
	connect-an-institution-source                    # how-to against the reader's own OpenAPI source; no fixed scenario this gate can replay
	connect-a-sqlite-extract                         # starter is covered by evidencectl scaffold and fixture tests; production half needs an operator-mounted extract
	first-run-with-solmara-lab                       # historical; the Solmara Lab stack is replayed by check-tutorial.sh, not here
	first-breg                            # Base Registry Engine journey; product CI runs quickstart/run.sh --smoke, reader execution checks the documented steps
	query-a-spatial-registry-from-qgis               # Base Registry Engine spatial journey; product CI runs the spatial smoke, while QGIS needs a desktop reader run
	integrate-evidence-candidate-with-docker-compose # drift-checked by evidence-production-build-docs.test.mjs; needs Docker Compose
	issue-a-birth-certificate-vc-from-opencrvs       # needs the public OpenCRVS Farajaland demo; live and opt-in, not replayed in CI
	issue-evidence-access-tokens-with-registry-mint  # drift-checked by evidence-production-build-docs.test.mjs; needs a Registry Mint deployment
	issue-immunization-evidence-from-dhis2           # needs the public DHIS2 demo; live and opt-in, not replayed in CI
	manage-evidence-verifier-trust                   # how-to against the reader's own deployment; no fixed scenario this gate can replay
	move-evidence-to-production-signing              # drift-checked by evidence-production-build-docs.test.mjs; needs a Transit signer
	prove-an-evidence-project                        # how-to against the reader's own project; no fixed scenario this gate can replay
	publish-and-consume-discovery-index               # Discovery journey; replayed by check-discovery-tutorial.sh with native Evidence and Relay handoffs
	publish-governed-sqlite-registry                 # Relay V2 journey; replayed by the Relay product and real-process acceptance gates
	query-relay-client                               # Relay client journey; depends on a released wheel and the Relay publishing prerequisite
	request-a-holder-bound-credential                # draft: true, hidden from the sidebar; no verified wallet flow exists to replay
	review-registry-changes                         # Base Registry Engine journey; verify page commands in reader mode, outside the Evidence runner
	rotate-evidence-signing-keys                     # drift-checked by evidence-production-build-docs.test.mjs; needs a deployed signing key
	verify-a-registered-parent-with-opencrvs         # needs the public OpenCRVS Farajaland demo; live and opt-in, not replayed in CI
)

in_list() {
	local needle="$1"
	shift
	local item
	for item in "$@"; do
		[[ "$item" == "$needle" ]] && return 0
	done
	return 1
}

# Assert that every page under DOCS_ROOT is either registered for replay or
# named in EXCLUDED_EVIDENCE_TUTORIALS with a reason. A page in neither list
# is a coverage gap: nothing would ever replay it or explain why not.
check_tutorial_coverage() {
	local file slug
	local -a unregistered=()
	for slug in "${EXCLUDED_EVIDENCE_TUTORIALS[@]}"; do
		if in_list "$slug" "${EVIDENCE_TUTORIALS[@]}"; then
			printf 'coverage error in %s: %s is both registered in EVIDENCE_TUTORIALS and excluded in EXCLUDED_EVIDENCE_TUTORIALS\n' \
				"${BASH_SOURCE[0]}" "$slug" >&2
			exit 2
		fi
		if [[ ! -f "$DOCS_ROOT/$slug.mdx" ]]; then
			printf 'coverage error in %s: %s.mdx in EXCLUDED_EVIDENCE_TUTORIALS does not exist under %s\n' \
				"${BASH_SOURCE[0]}" "$slug" "$DOCS_ROOT" >&2
			exit 2
		fi
	done
	for file in "$DOCS_ROOT"/*.mdx; do
		[[ -e "$file" ]] || continue
		slug="$(basename "$file" .mdx)"
		if ! in_list "$slug" "${EVIDENCE_TUTORIALS[@]}" && ! in_list "$slug" "${EXCLUDED_EVIDENCE_TUTORIALS[@]}"; then
			unregistered+=("$slug")
		fi
	done
	if ((${#unregistered[@]} > 0)); then
		printf 'tutorial coverage gap: the following pages are neither registered in EVIDENCE_TUTORIALS nor excluded in EXCLUDED_EVIDENCE_TUTORIALS:\n' >&2
		for slug in "${unregistered[@]}"; do
			printf '  %s.mdx\n' "$slug" >&2
		done
		printf 'add each to EVIDENCE_TUTORIALS (with a load_spec branch) or to EXCLUDED_EVIDENCE_TUTORIALS with a reason, in %s\n' \
			"${BASH_SOURCE[0]}" >&2
		exit 1
	fi
}

check_tutorial_coverage

load_spec() {
	SPEC_STEPS=()
	SPEC_ASSERTS=()

	case "$1" in
	first-evidence-assertion)
		SPEC_STEPS=(
			"run:Preview a synthetic source|1"
			"save:Preview a synthetic source|yaml|1|tutorial-source.openapi.yaml"
			"background:Preview a synthetic source|2"
			"wait-http:http://127.0.0.1:4010/people/person-123"
			"run:Preview a synthetic source|3"
			"stop-background"
			"run:Create the Evidence Gateway project"
			"run:Keep exact cases for the tutorial|1"
			"save:Create the Evidence Gateway project|yaml|1|questions/adult-status.yaml"
			"save:Create the Evidence Gateway project|rhai|1|derivations/adult-status.rhai"
			"save:Keep exact cases for the tutorial|yaml|1|mocks/source.yaml"
			"save:Keep exact cases for the tutorial|json|1|mocks/cases/person-123.json"
			"save:Keep exact cases for the tutorial|json|2|mocks/cases/person-456.json"
			"save:Keep exact cases for the tutorial|json|3|mocks/cases/person-789.json"
			"run:Keep exact cases for the tutorial|2"
			"background:Keep exact cases for the tutorial|3"
			"wait-http:http://127.0.0.1:4010/people/person-123"
			"run:Keep exact cases for the tutorial|4"
			"run:Request an assertion"
			"run:Verify before reading"
			"run:Try the SD-JWT VC serialization"
			"run:Stop the local services"
			"run:Inspect the audit entry"
			"run:Clean up"
		)
		# The assertion was verified, the audit recorded who asked and why, and
		# exactly one field was released. Nothing else here regresses in
		# silence: a mock that did not start or a project that was not created
		# ends the journey at the next command.
		SPEC_ASSERTS=(
			"VERIFIED"
			"ACCESS AUTHORIZED adult-status age-check requester="
			"DISCLOSURE RELEASED is_adult"
		)
		;;
	request-evidence-as-sd-jwt-vc)
		SPEC_STEPS=(
			"background:Restart the source mock|1"
			"wait-http:http://127.0.0.1:4010/people/person-123"
			"run:Restart the source mock|2"
			"run:Request a scalar credential"
			"run:Inspect the compact structure after verification"
			"run:Inspect issuer discovery"
			"run:Prove tampering is refused|1"
			"run-fails:Prove tampering is refused|2"
			"save:Model independently disclosed fields|yaml|1|schemas/adult-assessment.yaml"
			"save:Model independently disclosed fields|yaml|2|questions/adult-assessment.yaml"
			"save:Model independently disclosed fields|rhai|1|derivations/adult-assessment.rhai"
			"run:Model independently disclosed fields"
			"run:Clean up"
		)
		# The disclosure names are what a holder actually hands over, and the
		# fences that print them exit zero whatever the credential carries, so a
		# credential that started disclosing more would pass unnoticed.
		SPEC_ASSERTS=(
			"disclosure: urn:registrystack:evidence:local:concept:adult-status:is_adult"
			"evidencectl: Evidence response verification failed"
			"disclosure: criterion"
			"disclosure: isAdult"
			"ACCESS AUTHORIZED adult-assessment age-assessment-review requester="
			"DISCLOSURE RELEASED adult_assessment"
		)
		;;
	run-oid4vci-interoperability-checks)
		SPEC_STEPS=(
			"run:Copy the complete configuration"
			"save:Copy the complete configuration|yaml|1|.tutorial/oid4vci-adopter/oid4vci.yaml"
			"run:Replay the sanitized profile"
			"run:Clean up"
		)
		# The sanitized runner prints one line per phase and exits non-zero on
		# any of them, so the phases hold themselves up. What they cannot hold
		# up is having run at all: a filter that selects no test leaves the
		# runner exiting zero with nothing done. One end-to-end line proves the
		# wallet flow ran; the rest would be a transcript pin.
		SPEC_ASSERTS=(
			"PRESENTATION VERIFIED: public wallet flow returned holder-bound Evidence"
		)
		;;
	return-a-governed-value)
		SPEC_STEPS=(
			"background:Restart the source mock"
			"wait-http:http://127.0.0.1:4010/people/person-123"
			"run:Add the age-bracket question"
			"save:Add the age-bracket question|yaml|1|questions/age-bracket.yaml"
			"save:Add the age-bracket question|rhai|1|derivations/age-bracket.rhai"
			"run:Start the updated project"
			"run:Request and verify the bracket"
			"run:Inspect the audit and clean up"
		)
		SPEC_ASSERTS=(
			"VERIFIED"
			"ACCESS AUTHORIZED age-bracket service-path-selection requester="
			"DISCLOSURE RELEASED age_bracket"
		)
		;;
	control-who-can-request-evidence)
		SPEC_STEPS=(
			"background:Restart the source mock|1"
			"wait-http:http://127.0.0.1:4010/people/person-123"
			"run:Restart the source mock|2"
			"run:Define two access policies"
			"run:Register the first local application"
			"run:Start the protected service"
			"run:Make an allowed request"
			"run:Add an application without restarting"
			"run:Use the application assigned the policy"
			"run:Try a question the application was not granted"
			"run:Revoke an application|1"
			"run-fails:Revoke an application|2"
			"run:Inspect the final audit operation"
			"run:Clean up"
		)
		# This tutorial teaches refusal, so the refusals are what must hold.
		# The unauthorized request's curl carries no --fail-with-body, so it
		# exits zero on a 403 and a boundary that started answering 200 would
		# leave the journey green. The revocation step requires a non-zero
		# exit; the message is what proves it was refused because the
		# client was revoked rather than for some unrelated reason.
		SPEC_ASSERTS=(
			"VERIFIED"
			"HTTP 403"
			'"code": "evidence.denied"'
			"evidencectl: unknown or revoked active client age-checker"
			"ACCESS REFUSED requester="
			"reason=not_authorized"
		)
		;;
	assert-a-role-bound-relationship)
		SPEC_STEPS=(
			"run:Start a relationship registry|1"
			"save:Start a relationship registry|python|1|registry.py"
			"background:Start a relationship registry|2"
			"wait-http:http://127.0.0.1:8002/openapi.json"
			"run:Create the Evidence Gateway project"
			"save:Create the Evidence Gateway project|yaml|1|questions/parent-relationship.yaml"
			"save:Create the Evidence Gateway project|rhai|1|derivations/parent-relationship.rhai"
			"run:Start the project"
			"run:Bind both subjects to the request"
			"run:Inspect the audit and clean up"
		)
		SPEC_ASSERTS=(
			"VERIFIED"
			"ACCESS AUTHORIZED parent-relationship relationship-check requester="
			"DISCLOSURE RELEASED relationship_confirmed"
		)
		;;
	refuse-unsafe-evidence-requests)
		SPEC_STEPS=(
			"background:Restart the local boundary|1"
			"wait-http:http://127.0.0.1:4010/people/person-123"
			"run:Restart the local boundary|2"
			"run:Prepare one authorized request"
			"run:Change the purpose after preparation"
			"run:Obtain and verify the authorized response"
			"run:Change the signed response|1"
			"run-fails:Change the signed response|2"
			"run:Clean up"
		)
		# The whole page is these three outcomes: the altered request was
		# refused, the untouched one verified, and the altered response was
		# caught. The refusal curl exits zero on a 403, so only the printed
		# status separates a boundary that refused from one that answered.
		SPEC_ASSERTS=(
			"HTTP 403"
			"VERIFIED"
			"evidencectl: Evidence response verification failed"
		)
		;;
	verify-an-assertion-as-a-consumer)
		SPEC_STEPS=(
			"run:Start with three separate inputs"
			"run:Re-verify the recorded decision"
		)
		# `evidence verify` exits non-zero on both `authentic: no` and
		# `currently-valid: no`, so the verdict holds itself up. The disclosed
		# value does not: verification succeeds whatever the assertion says, and
		# a consumer reading the wrong answer is the failure that matters.
		SPEC_ASSERTS=(
			'"value": true'
		)
		;;
	request-evidence-from-an-application)
		SPEC_STEPS=(
			# The registry runs in the terminal the reader never moved out of
			# the first tutorial's directory, so it starts before the `cd` the
			# page opens with rather than where the page prints it.
			"background:Start the local services|1"
			"wait-http:http://127.0.0.1:4010/people/person-123"
			"run:Give the application its own identity"
			"run:Pin the keys your application trusts"
			# Stands in for the two fences under "Build the Python client", the
			# documented clone and build of the released client.
			"python-client"
			"run:Start the local services|2"
			"run-fails:Start the local services|3"
			"run:Read the definitions once"
			"run:Pin the procedure"
			"save:Write the relying procedure|python|1|age_check.py"
			"run:Run it"
			"run-fails:Refuse before reading"
			"run:Stop the local services"
		)
		# What the relying application actually did. Both refusals already
		# exit non-zero, so what is held here is the reason: an unnamed caller
		# refused for want of a registered client, and an unverifiable response
		# refused before anything was read. The two answers prove the right
		# subject was resolved rather than a constant returned, the pinning line
		# proves the subject binding is still recorded, and the assurance
		# profile is the trust level a relying party reads off the deployment.
		SPEC_ASSERTS=(
			"evidencectl: the active project requires a registered client selected with --client"
			'"assuranceProfile": "local"'
			"person-123 is_adult=True"
			"person-456 is_adult=False"
			"pinned binding recorded in subject-bindings.json"
			"unverifiable response, nothing read (policy)"
		)
		;;
	issue-fhir-evidence-as-vcs)
		SPEC_STEPS=(
			"run:Select live synthetic records|1"
			"save:Select live synthetic records|python|1|discover-fhir-records.py"
			"fhir-mock"
			"run:Select live synthetic records|2"
			"save:Run a live FHIR read-through adapter|python|1|fhir-read-through.py"
			"run:Run a live FHIR read-through adapter"
			"track-pid:fhir-read-through.pid"
			"save:Describe the exact FHIR reads|yaml|1|fhir-smart-r4.openapi.yaml"
			"run:Describe the exact FHIR reads"
			"save:Author the patient coverage question|yaml|1|questions/fhir-coverage-status.yaml"
			"save:Author the patient coverage question|rhai|1|derivations/fhir-coverage-status.rhai"
			"save:Author the healthcare-establishment question|yaml|1|questions/fhir-healthcare-establishment.yaml"
			"save:Author the healthcare-establishment question|rhai|1|derivations/fhir-healthcare-establishment.rhai"
			"run:Start the project"
			"run:Request the patient coverage credential"
			"run:Request the healthcare-establishment credential"
			"run:Inspect the audit and clean up"
		)
		SPEC_ASSERTS=(
			"VERIFIED"
			"ACCESS AUTHORIZED fhir-healthcare-establishment healthcare-establishment-verification requester="
			"DISCLOSURE RELEASED healthcare_provider_record_active"
		)
		;;
	*)
		printf '%s is not a registered Evidence tutorial\n' "$1" >&2
		exit 2
		;;
	esac
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

DRY_RUN=0
ONLY=""
while (($# > 0)); do
	case "$1" in
	--dry-run)
		DRY_RUN=1
		shift
		;;
	--only)
		if (($# < 2)); then
			printf -- '--only needs a tutorial slug\n' >&2
			exit 2
		fi
		ONLY="$2"
		shift 2
		;;
	*)
		printf 'unknown argument: %s (expected --dry-run or --only <slug>)\n' "$1" >&2
		exit 2
		;;
	esac
done

if [[ -n "$ONLY" ]]; then
	# load_spec exits on an unregistered slug, which is the check we want here.
	load_spec "$ONLY"
	# Every follow-up begins from the project first-evidence-assertion builds.
	# A full run gets that from the list order; --only has to name it.
	case "$ONLY" in
	request-evidence-as-sd-jwt-vc | return-a-governed-value | \
		refuse-unsafe-evidence-requests | verify-an-assertion-as-a-consumer | \
		control-who-can-request-evidence | request-evidence-from-an-application)
		EVIDENCE_TUTORIALS=(first-evidence-assertion "$ONLY")
		;;
	*) EVIDENCE_TUTORIALS=("$ONLY") ;;
	esac
fi

WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/evidence-tutorial.XXXXXX")"
cleanup() {
	local exit_code=$?
	set +e
	chmod -R u+w "$WORK_ROOT" 2>/dev/null
	rm -rf "$WORK_ROOT"
	if ((exit_code == 0)); then
		printf 'Evidence tutorial gate: PASS\n'
	else
		printf 'Evidence tutorial gate: FAIL (exit %d)\n' "$exit_code" >&2
	fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

# ---------------------------------------------------------------------------
# Toolset under test
# ---------------------------------------------------------------------------

resolve_profile_dir() {
	case "$BUILD_PROFILE" in
	ci | release) printf '%s' "$BUILD_PROFILE" ;;
	*)
		printf 'unsupported tutorial Cargo profile: %s (expected ci or release)\n' \
			"$BUILD_PROFILE" >&2
		exit 1
		;;
	esac
}

SHIM_DIR="$WORK_ROOT/bin"

prepare_toolset() {
	if [[ -z "${EVIDENCE_BIN:-}" || -z "${EVIDENCECTL_BIN:-}" || \
		-z "${EVIDENCE_OID4VCI_BIN:-}" || -z "${MINT_BIN:-}" ]]; then
		local profile_dir
		profile_dir="$(resolve_profile_dir)"
		(cd "$REPO_ROOT" && CARGO_TARGET_DIR="$TARGET_DIR" \
			cargo build --locked --profile "$BUILD_PROFILE" \
			-p registry-evidence -p registry-evidencectl \
			-p registry-evidence-oid4vci -p registry-mint)
		EVIDENCE_BIN="$TARGET_DIR/$profile_dir/evidence"
		EVIDENCECTL_BIN="$TARGET_DIR/$profile_dir/evidencectl"
		EVIDENCE_OID4VCI_BIN="$TARGET_DIR/$profile_dir/evidence-oid4vci"
		MINT_BIN="$TARGET_DIR/$profile_dir/mint"
	fi
	export EVIDENCE_OID4VCI_BIN
	local bin
	for bin in "$EVIDENCE_BIN" "$EVIDENCECTL_BIN" "$EVIDENCE_OID4VCI_BIN" "$MINT_BIN"; do
		# Absoluteness first: the reader journey runs from its own directory and
		# reaches the binaries through symlinks, so a relative path resolves
		# against the wrong directory and would otherwise surface much later,
		# mid-journey, as "command not found".
		if [[ "$bin" != /* ]]; then
			printf 'toolset binary path must be absolute: %s\n' "$bin" >&2
			exit 1
		fi
		if [[ ! -x "$bin" ]]; then
			printf 'toolset binary not executable: %s\n' "$bin" >&2
			exit 1
		fi
	done

	# The tutorials call the binaries by name, so serve them from a shim dir.
	mkdir -p "$SHIM_DIR"
	ln -s "$EVIDENCE_BIN" "$SHIM_DIR/evidence"
	ln -s "$EVIDENCECTL_BIN" "$SHIM_DIR/evidencectl"
	ln -s "$EVIDENCE_OID4VCI_BIN" "$SHIM_DIR/evidence-oid4vci"
	ln -s "$MINT_BIN" "$SHIM_DIR/mint"
}

# The Python client extension module, built once for whichever tutorials import
# it.
#
# The documented build clones the repository at the installed runtime's release
# tag, which is the right instruction for a reader and the wrong one for this
# gate: it needs the network, and it would prove a released client rather than
# the one in this checkout. Building the same crate from here instead is what
# makes a client regression fail this gate on the commit that introduces it.
# The two documented fences it stands in for are reported as unexecuted, so
# their release tag and build flags stay a reviewer's call rather than this
# gate's.
# The module is built for the stable ABI, so one built outside this script
# imports under any CPython the replay userland carries, exactly as
# EVIDENCE_CLIENT_PY_LIB's siblings let CI mount prebuilt binaries.
PYTHON_CLIENT_LIB="${EVIDENCE_CLIENT_PY_LIB:-}"

prepare_python_client() {
	if [[ -n "$PYTHON_CLIENT_LIB" ]]; then
		if [[ "$PYTHON_CLIENT_LIB" != /* ]]; then
			printf 'Python client module path must be absolute: %s\n' \
				"$PYTHON_CLIENT_LIB" >&2
			exit 1
		fi
	else
		local profile_dir built
		profile_dir="$(resolve_profile_dir)"
		(cd "$REPO_ROOT" && CARGO_TARGET_DIR="$TARGET_DIR" \
			cargo build --locked --profile "$BUILD_PROFILE" \
			-p registry-evidence-client-py --lib \
			--features registry-evidence-client-py/extension-module)
		case "$(uname -s)" in
		Darwin) built="libregistry_evidence_client.dylib" ;;
		Linux) built="libregistry_evidence_client.so" ;;
		*)
			printf 'the Python Evidence client tutorial covers macOS and Linux, not %s\n' \
				"$(uname -s)" >&2
			exit 1
			;;
		esac
		PYTHON_CLIENT_LIB="$TARGET_DIR/$profile_dir/$built"
	fi
	if [[ ! -f "$PYTHON_CLIENT_LIB" ]]; then
		printf 'Python client module not built: %s\n' "$PYTHON_CLIENT_LIB" >&2
		exit 1
	fi
}

# ---------------------------------------------------------------------------
# Journey assembly
# ---------------------------------------------------------------------------

# Resolve a heading address to the sh fence numbers it names, in document
# order, space separated.
#
# An address is a heading, optionally followed by |<occurrence> to name one
# fence under it. Addressing by heading rather than by position is what lets a
# writer add or remove a command block without touching a spec, and it is what
# stops an inserted block from silently moving a later step onto the wrong
# command.
resolve_fences() {
	local slug="$1" address="$2" fence_dir="$3"
	local heading="$address" occurrence=""
	if [[ "$address" == *'|'* ]]; then
		heading="${address%%|*}"
		occurrence="${address##*|}"
		if [[ ! "$occurrence" =~ ^[1-9][0-9]*$ ]]; then
			printf 'tutorial spec error in %s: fence occurrence must be a positive integer: %s\n' \
				"$slug" "$address" >&2
			exit 2
		fi
	fi
	local matched
	matched="$(awk -F '\t' -v want="$heading" -v want_occurrence="$occurrence" '
		$3 != want { next }
		want_occurrence != "" && $2 != want_occurrence + 0 { next }
		{ printf "%s ", $1 }
	' "$fence_dir/index.tsv")"
	matched="${matched% }"
	if [[ -z "$matched" ]]; then
		printf 'tutorial drift in %s: no sh fence answers to "%s"\n' "$slug" "$address" >&2
		printf 'A step names a heading the page no longer carries, or an occurrence under it that no longer exists.\n' >&2
		printf 'Renaming a heading is a structural edit to the journey; walk it again, then name the new heading in %s.\n' \
			"${BASH_SOURCE[0]}" >&2
		printf 'The page currently holds these sh fences:\n' >&2
		awk -F '\t' '{ printf "  fence %s, occurrence %s under \"%s\"\n", $1, $2, $3 }' \
			"$fence_dir/index.tsv" >&2
		exit 1
	fi
	printf '%s\n' "$matched"
}

# Resolve a heading address that must name exactly one sh fence.
resolve_one_fence() {
	local slug="$1" address="$2" fence_dir="$3" step_kind="$4"
	local matched
	matched="$(resolve_fences "$slug" "$address" "$fence_dir")" || exit $?
	local -a numbers
	read -r -a numbers <<<"$matched"
	if ((${#numbers[@]} != 1)); then
		printf 'tutorial spec error in %s: a %s step runs one fence, but "%s" names %d; add |<occurrence>\n' \
			"$slug" "$step_kind" "$address" "${#numbers[@]}" >&2
		exit 2
	fi
	printf '%s\n' "${numbers[0]}"
}

# Emit the sh fences named by a run: step, in document order.
emit_run_step() {
	local slug="$1" address="$2" fence_dir="$3"
	local matched
	matched="$(resolve_fences "$slug" "$address" "$fence_dir")" || exit $?
	local -a numbers
	read -r -a numbers <<<"$matched"
	local number
	for number in "${numbers[@]}"; do
		printf '\nprintf "==> %s fence %s\\n"\n' "$slug" "$number"
		cat "$fence_dir/fence-$number.sh"
	done
}

# Emit one sh fence the tutorial documents as refused, and require it to fail.
#
# A refusal the tutorial teaches is as much a documented outcome as a success,
# so replaying it means asserting the non-zero exit rather than tolerating it:
# a fence that starts succeeding has stopped teaching what the page says.
#
# The fence runs on its own line rather than as an `if` condition, because bash
# suppresses errexit throughout a condition, subshells included, even one that
# sets it itself. A fence that refuses on its first command and then prints
# would run that print and report success, which is neither what the reader
# sees nor what the page documents. `set +e` around the run keeps the failure
# from ending the journey, and reinstates errexit for the steps after it.
emit_run_fails_step() {
	local slug="$1" address="$2" fence_dir="$3"
	local number
	number="$(resolve_one_fence "$slug" "$address" "$fence_dir" run-fails)" || exit $?
	printf '\nprintf "==> %s fence %s (documented refusal)\\n"\n' "$slug" "$number"
	printf 'set +e\n'
	printf '( set -e\n'
	cat "$fence_dir/fence-$number.sh"
	printf ')\nrefusal_status=$?\nset -e\n'
	printf 'if ((refusal_status == 0))\nthen\n'
	printf '  printf "tutorial drift in %s: fence %s succeeded, but the page documents a refusal\\n" >&2\n' \
		"$slug" "$number"
	printf '  exit 1\n'
	printf 'fi\n'
}

# Install the Python client the way the tutorial's clone-and-build fences do,
# from this checkout. The destination path and module name are the reader's.
emit_python_client_step() {
	local slug="$1"
	printf '\nprintf "==> %s install the Python client from this checkout\\n"\n' "$slug"
	printf 'mkdir -p python-module\n'
	printf 'cp %q python-module/registry_evidence_client.so\n' "$PYTHON_CLIENT_LIB"
}

# Emit a documented before/after fence pair applied to a file the reader edits.
#
# Both fences are read out of the tutorial here, while the journey is being
# assembled, so a pair the tutorial no longer carries fails by name before the
# reader's first command runs.
emit_edit_step() {
	local slug="$1" spec="$2" tutorial_file="$3" edit_dir="$4"
	local IFS='|'
	# shellcheck disable=SC2206  # deliberate split on the field separator
	local parts=($spec)
	if ((${#parts[@]} != 7)); then
		printf 'tutorial spec error in %s: edit step needs 7 fields, got %d: %s\n' \
			"$slug" "${#parts[@]}" "$spec" >&2
		exit 2
	fi
	EDIT_INDEX=$((EDIT_INDEX + 1))
	local before after
	before="$(printf '%s/edit-%02d-before' "$edit_dir" "$EDIT_INDEX")"
	after="$(printf '%s/edit-%02d-after' "$edit_dir" "$EDIT_INDEX")"
	if ! bash "$FENCE" write-fence "$tutorial_file" \
		"${parts[0]}" "${parts[1]}" "${parts[2]}" "$before" ||
		! bash "$FENCE" write-fence "$tutorial_file" \
			"${parts[3]}" "${parts[4]}" "${parts[5]}" "$after"; then
		printf 'tutorial drift in %s: edit step names a fence the tutorial no longer carries: %s\n' \
			"$slug" "$spec" >&2
		exit 1
	fi
	printf '\nprintf "==> %s edit %s\\n"\n' "$slug" "${parts[6]}"
	# shellcheck disable=SC2016  # FENCE expands in the emitted script
	printf 'bash "$FENCE" replace-block %q %q %q\n' "${parts[6]}" "$before" "$after"
}

# Save a documented non-shell fence as the file the reader is instructed to
# create. The maintained Markdown remains the single source of those bytes.
emit_save_step() {
	local slug="$1" spec="$2"
	local IFS='|'
	# shellcheck disable=SC2206  # deliberate split on the field separator
	local parts=($spec)
	if ((${#parts[@]} != 4)); then
		printf 'tutorial spec error in %s: save step needs 4 fields, got %d: %s\n' \
			"$slug" "${#parts[@]}" "$spec" >&2
		exit 2
	fi
	printf '\nprintf "==> %s save %s\\n"\n' "$slug" "${parts[3]}"
	# shellcheck disable=SC2016  # FENCE and TUTORIAL expand in the emitted script
	printf 'bash "$FENCE" write-fence "$TUTORIAL" %q %q %q %q\n' \
		"${parts[0]}" "${parts[1]}" "${parts[2]}" "${parts[3]}"
}

# A tutorial may ask the reader to leave one foreground command running in a
# second terminal. CI runs that exact one-line command in the background and
# retains its PID for cleanup.
emit_background_step() {
	local slug="$1" address="$2" fence_dir="$3"
	local number
	number="$(resolve_one_fence "$slug" "$address" "$fence_dir" background)" || exit $?
	local fence="$fence_dir/fence-$number.sh"
	if [[ "$(wc -l <"$fence")" -ne 1 ]]; then
		printf 'tutorial spec error in %s: a background step needs one sh line, but fence %s under "%s" holds more\n' \
			"$slug" "$number" "$address" >&2
		exit 2
	fi
	local command
	IFS= read -r command <"$fence"
	printf '\nprintf "==> %s fence %s (background)\\n"\n' "$slug" "$number"
	printf '%s &\n' "$command"
	printf 'BACKGROUND_PIDS+=("$!")\n'
}

# Stop the foreground command the page told the reader to leave running in
# another terminal. This models Ctrl+C without adding a shell fence that a
# reader would never type.
emit_stop_background_step() {
	local slug="$1"
	printf '\nprintf "==> %s stop the previous background fence\\n"\n' "$slug"
	printf 'if ((${#BACKGROUND_PIDS[@]} == 0)); then printf "tutorial spec error in %s: no background fence to stop\\n" >&2; exit 2; fi\n' "$slug"
	printf 'background_index=$((${#BACKGROUND_PIDS[@]} - 1))\n'
	printf 'background_pid="${BACKGROUND_PIDS[$background_index]}"\n'
	printf 'kill "$background_pid" >/dev/null 2>&1 || true\n'
	printf 'wait "$background_pid" >/dev/null 2>&1 || true\n'
	printf 'unset "BACKGROUND_PIDS[$background_index]"\n'
}

emit_wait_http_step() {
	local url="$1"
	printf '\nfor attempt in {1..50}; do\n'
	printf '  if curl -fs %q >/dev/null 2>&1; then break; fi\n' "$url"
	printf '  if [[ "$attempt" -eq 50 ]]; then printf "tutorial service did not become ready\\n" >&2; exit 1; fi\n'
	printf '  sleep 0.1\n'
	printf 'done\n'
}

emit_fhir_mock_step() {
	printf '\nprintf "==> start sanitized local FHIR mock\\n"\n'
	printf '%q >%q 2>&1 &\n' "$FHIR_TUTORIAL_MOCK" "$WORK_ROOT/fhir-tutorial-mock.log"
	printf 'BACKGROUND_PIDS+=("$!")\n'
	printf 'for attempt in {1..50}; do\n'
	printf '  if curl --noproxy "*" -fs http://127.0.0.1:8003/healthz >/dev/null 2>&1; then break; fi\n'
	printf '  if [[ "$attempt" -eq 50 ]]; then printf "sanitized FHIR mock did not become ready\\n" >&2; exit 1; fi\n'
	printf '  sleep 0.1\n'
	printf 'done\n'
}

emit_track_pid_step() {
	local path="$1"
	printf '\ntracked_pid="$(cat %q)"\n' "$path"
	printf 'if [[ ! "$tracked_pid" =~ ^[1-9][0-9]*$ ]]; then printf %q >&2; exit 1; fi\n' \
		"invalid tracked PID in $path\n"
	printf 'BACKGROUND_PIDS+=("$tracked_pid")\n'
}

emit_journey() {
	local slug="$1" fence_dir="$2" tutorial_file="$3"
	local edit_dir="$WORK_ROOT/edits/$slug"
	mkdir -p "$edit_dir"
	EDIT_INDEX=0
	printf 'set -euo pipefail\n'
	printf 'FENCE=%q\n' "$FENCE"
	printf 'TUTORIAL=%q\n' "$tutorial_file"
	printf 'BACKGROUND_PIDS=()\n'
	printf 'cleanup_journey() {\n'
	printf '  if [[ -S .evidence/dev/control.sock ]]; then evidencectl dev stop >/dev/null 2>&1 || true; fi\n'
	printf '  local pid\n'
	printf '  for pid in "${BACKGROUND_PIDS[@]}"; do kill "$pid" >/dev/null 2>&1 || true; wait "$pid" >/dev/null 2>&1 || true; done\n'
	printf '}\n'
	printf 'trap cleanup_journey EXIT\n'
	printf 'trap "exit 130" HUP INT TERM\n'
	local step
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*) emit_run_step "$slug" "${step#run:}" "$fence_dir" ;;
		run-fails:*) emit_run_fails_step "$slug" "${step#run-fails:}" "$fence_dir" ;;
		python-client) emit_python_client_step "$slug" ;;
		fhir-mock) emit_fhir_mock_step ;;
		track-pid:*) emit_track_pid_step "${step#track-pid:}" ;;
		edit:*) emit_edit_step "$slug" "${step#edit:}" "$tutorial_file" "$edit_dir" ;;
		save:*) emit_save_step "$slug" "${step#save:}" ;;
		background:*) emit_background_step "$slug" "${step#background:}" "$fence_dir" ;;
		stop-background) emit_stop_background_step "$slug" ;;
		wait-http:*) emit_wait_http_step "${step#wait-http:}" ;;
		*)
			printf 'tutorial spec error in %s: unknown step: %s\n' "$slug" "$step" >&2
			exit 2
			;;
		esac
	done
}

# Resolve every fence-addressing step into EXECUTED_FENCES, in step order.
#
# This runs before the replay and in --dry-run, so a heading a spec names but
# the page no longer carries fails by name in seconds, without a toolchain.
resolve_journey_fences() {
	local slug="$1" fence_dir="$2"
	EXECUTED_FENCES=()
	local step matched number
	local -a numbers
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*) matched="$(resolve_fences "$slug" "${step#run:}" "$fence_dir")" || exit $? ;;
		run-fails:*)
			matched="$(resolve_one_fence "$slug" "${step#run-fails:}" "$fence_dir" run-fails)" || exit $?
			;;
		background:*)
			matched="$(resolve_one_fence "$slug" "${step#background:}" "$fence_dir" background)" || exit $?
			;;
		*) continue ;;
		esac
		read -r -a numbers <<<"$matched"
		for number in "${numbers[@]}"; do
			if ! in_list "$number" ${EXECUTED_FENCES[@]+"${EXECUTED_FENCES[@]}"}; then
				EXECUTED_FENCES+=("$number")
			fi
		done
	done
}

# Name the sh fences the journey never runs.
#
# This is information for a reviewer, not a rule: an install one-liner or a
# recovery block a reader only reaches on a bad day is documented and
# unverified, and saying so is more use than pinning its text would be.
report_unexecuted_fences() {
	local slug="$1" fence_dir="$2"
	local number occurrence heading first_line
	while IFS=$'\t' read -r number occurrence heading; do
		if in_list "$number" ${EXECUTED_FENCES[@]+"${EXECUTED_FENCES[@]}"}; then
			continue
		fi
		first_line=""
		IFS= read -r first_line <"$fence_dir/fence-$number.sh" || true
		printf '  not executed: fence %s under "%s": %s\n' "$number" "$heading" "$first_line"
	done <"$fence_dir/index.tsv"
}

# Hold the behaviours a successful exit does not already prove.
#
# Read the SPEC_ASSERTS note in the header before adding an entry here. This
# holds outcomes, never the transcript: a page is free to reword everything
# around the line, and the line itself is only here because losing it would
# leave the journey green.
assert_transcript() {
	local slug="$1" run_log="$2"
	local expected
	for expected in ${SPEC_ASSERTS[@]+"${SPEC_ASSERTS[@]}"}; do
		if ! grep -F -q -- "$expected" "$run_log"; then
			printf 'tutorial behaviour drift in %s: the replay ran, but its transcript never showed "%s"\n' \
				"$slug" "$expected" >&2
			printf 'Every command exited zero, so this is the kind of regression only this assertion catches.\n' >&2
			exit 1
		fi
	done
}

# The sanitized OID4VCI runner may fall back to Cargo when CI has not supplied
# its prebuilt interoperability test. Keep that build in this gate's target
# directory without changing the documented Cargo behavior of other tutorials.
run_journey_script() {
	local slug="$1" reader_dir="$2" run_script="$3"
	if [[ "$slug" == "run-oid4vci-interoperability-checks" ]]; then
		(cd "$reader_dir" && PATH="$SHIM_DIR:$PATH" CARGO_TARGET_DIR="$TARGET_DIR" bash "$run_script")
	elif [[ "$slug" == "issue-fhir-evidence-as-vcs" ]]; then
		(
			unset CARGO_TARGET_DIR
			cd "$reader_dir"
			PATH="$SHIM_DIR:$PATH" \
				FHIR_TUTORIAL_TEST_BASE_URL="http://127.0.0.1:8003" \
				bash "$run_script"
		)
	else
		(
			unset CARGO_TARGET_DIR
			cd "$reader_dir"
			PATH="$SHIM_DIR:$PATH" bash "$run_script"
		)
	fi
}

# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

if ((DRY_RUN == 0)) && ((${#EVIDENCE_TUTORIALS[@]} > 0)); then
	prepare_toolset
fi

for slug in "${EVIDENCE_TUTORIALS[@]}"; do
	load_spec "$slug"
	tutorial_file="$DOCS_ROOT/$slug.mdx"
	if [[ ! -f "$tutorial_file" ]]; then
		printf 'Evidence tutorial not found: %s\n' "$tutorial_file" >&2
		exit 1
	fi

	# Extract every sh fence, in order, into numbered files, and index each one
	# by the heading it sits under and its occurrence there. Heading
	# attribution matches the fence helper the save and edit steps use, so one
	# address means the same thing everywhere in a spec: a level-2 heading opens
	# a section, and occurrences are counted per heading.
	fence_dir="$WORK_ROOT/fences/$slug"
	mkdir -p "$fence_dir"
	: >"$fence_dir/index.tsv"
	fence_count="$(awk -v outdir="$fence_dir" -v index_file="$fence_dir/index.tsv" '
		in_fence == 0 && /^##[ \t]+/ {
			heading = $0
			sub(/^##[ \t]+/, "", heading)
			sub(/[ \t]+$/, "", heading)
			next
		}
		in_fence == 0 && /^```[A-Za-z0-9_-]+$/ {
			in_fence = 1
			capture = ($0 == "```sh")
			if (capture) {
				count += 1
				occurrence[heading] += 1
				printf "%02d\t%d\t%s\n", count, occurrence[heading], heading > index_file
			}
			next
		}
		in_fence && /^```$/ { in_fence = 0; capture = 0; next }
		in_fence && capture { print > (outdir "/fence-" sprintf("%02d", count) ".sh") }
		END { print count + 0 }
	' "$tutorial_file")"

	resolve_journey_fences "$slug" "$fence_dir"

	printf '%s: %s sh fences, %s executed\n' \
		"$slug" "$fence_count" "${#EXECUTED_FENCES[@]}"
	report_unexecuted_fences "$slug" "$fence_dir"

	if ((DRY_RUN)); then
		continue
	fi

	# Replay the journey in one shell so `cd` persists exactly as a reader
	# experiences it, from a reader directory of this tutorial's own.
	case "$slug" in
	first-evidence-assertion)
		reader_dir="$WORK_ROOT/reader/evidence-start"
		;;
	run-oid4vci-interoperability-checks)
		# The runner remains sourced from the checkout, but the copied adopter
		# configuration belongs to a fresh writable reader directory. This also
		# proves the journey in CI, where the checkout is mounted read-only.
		reader_dir="$WORK_ROOT/reader/run-oid4vci-interoperability-checks"
		;;
	request-evidence-as-sd-jwt-vc)
		# This follow-up deliberately rewrites the starter project to explore a
		# structured VC. Give it a copy so the other follow-ups still begin from
		# the exact project produced by first-evidence-assertion.
		reader_dir="$WORK_ROOT/reader/request-evidence-as-sd-jwt-vc"
		cp -R "$WORK_ROOT/reader/evidence-start/first-evidence-assertion" "$reader_dir"
		;;
	request-evidence-from-an-application)
		# This follow-up gives the project its first access policy, which
		# retires the unnamed development caller the other follow-ups still
		# use, and writes a trusted key file one of them writes too. Both are
		# the reader's own project to change, so it gets a copy, and it takes
		# it here, before any follow-up has touched the starter project.
		reader_dir="$WORK_ROOT/reader/request-evidence-from-an-application"
		cp -R "$WORK_ROOT/reader/evidence-start/first-evidence-assertion" "$reader_dir"
		;;
	return-a-governed-value)
		reader_dir="$WORK_ROOT/reader/evidence-start/first-evidence-assertion"
		;;
	control-who-can-request-evidence)
		reader_dir="$WORK_ROOT/reader/evidence-start/first-evidence-assertion"
		;;
	refuse-unsafe-evidence-requests)
		reader_dir="$WORK_ROOT/reader/evidence-start/first-evidence-assertion"
		;;
	verify-an-assertion-as-a-consumer)
		reader_dir="$WORK_ROOT/reader/evidence-start/first-evidence-assertion"
		;;
	*) reader_dir="$WORK_ROOT/reader/$slug" ;;
	esac
	mkdir -p "$reader_dir"
	if [[ "$slug" == "run-oid4vci-interoperability-checks" ]]; then
		ln -s "$REPO_ROOT/products" "$reader_dir/products"
		ln -s "$REPO_ROOT/crates" "$reader_dir/crates"
		ln -s "$REPO_ROOT/Cargo.toml" "$reader_dir/Cargo.toml"
		ln -s "$REPO_ROOT/Cargo.lock" "$reader_dir/Cargo.lock"
	fi
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		if [[ "$step" == "python-client" ]]; then
			prepare_python_client
		fi
	done
	run_script="$WORK_ROOT/run-$slug.sh"
	emit_journey "$slug" "$fence_dir" "$tutorial_file" >"$run_script"

	run_log="$WORK_ROOT/run-$slug.log"
	if ! run_journey_script "$slug" "$reader_dir" "$run_script" 2>&1 |
		tee "$run_log"; then
		printf 'tutorial %s failed; the transcript ends just before this line\n' \
			"$slug" >&2
		exit 1
	fi

	assert_transcript "$slug" "$run_log"
done

if ((${#EVIDENCE_TUTORIALS[@]} == 1)); then
	printf 'Checked 1 tutorial.\n'
else
	printf 'Checked %d tutorials.\n' "${#EVIDENCE_TUTORIALS[@]}"
fi
