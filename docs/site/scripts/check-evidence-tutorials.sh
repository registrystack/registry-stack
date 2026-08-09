#!/usr/bin/env bash
#
# Execute the current Evidence tutorials from a fresh reader directory.
#
# This gate builds the Evidence toolset from the checked-out source unless
# EVIDENCE_BIN, EVIDENCECTL_BIN, EVIDENCE_OID4VCI_BIN and MINT_BIN select exact
# candidate or released bytes, then replays each registered tutorial's own
# shell fences in its own reader directory. Every tutorial creates the files it
# needs from its documented commands, so what CI runs is what a reader copies.
#
# Usage:
#   scripts/check-evidence-tutorials.sh                 replay every tutorial
#   scripts/check-evidence-tutorials.sh --dry-run       drift-check only
#   scripts/check-evidence-tutorials.sh --only <slug>   one tutorial and its prerequisites
#
# Registering a tutorial means adding its slug to EVIDENCE_TUTORIALS and a
# branch to load_spec. Each spec pins:
#   SPEC_FENCES     how many sh fences the tutorial holds; bump it when you
#                   intentionally add or remove a documented command block
#   SPEC_STEPS      the reader journey, in order, which need not follow fence
#                   order: a tutorial that leaves one terminal in an earlier
#                   directory is replayed by running its fence first
#                     run:N or run:N-M   execute those sh fences
#                     run-fails:N        execute one sh fence the tutorial
#                                        documents as refused, and require it
#                                        to exit non-zero
#                     edit:H|lang|occ|H2|lang2|occ2|target
#                                        apply a documented before/after fence
#                                        pair to an existing file
#                     save:H|lang|occ|target
#                                        write a documented non-shell fence to
#                                        the file the reader is told to create
#                     background:N       run a one-line sh fence the tutorial
#                                        leaves running in a second terminal
#                     wait-http:URL      block until that URL answers
#                     python-client      install the Python client from this
#                                        checkout, standing in for the
#                                        documented clone and build
#   SPEC_LITERALS   commands and outputs the tutorial must keep documenting
#   SPEC_OUTPUTS    lines the replay transcript must contain
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
)

# Every other page under DOCS_ROOT, and the reason it is not replayed here.
# check_tutorial_coverage below fails by name on a page in neither list, which
# is the gap that let broken DHIS2 tutorial commands ship once already.
EXCLUDED_EVIDENCE_TUTORIALS=(
	author-registry-project                          # registryctl tutorial, replayed by check-tutorial.sh's REGISTRYCTL_TUTORIALS
	build-and-deploy-evidence-project                # drift-checked by evidence-production-build-docs.test.mjs; needs a production build environment
	configure-project-api-key-authentication         # draft: true, hidden from the sidebar and redirected away
	configure-project-script-adapter                 # registryctl tutorial, replayed by check-tutorial.sh's REGISTRYCTL_TUTORIALS
	connect-an-institution-source                    # how-to against the reader's own OpenAPI source; no fixed scenario this gate can replay
	connect-a-sqlite-extract                         # starter is covered by evidencectl scaffold and fixture tests; production half needs an operator-mounted extract
	deploy-standalone-with-own-data                  # draft: true, hidden from the sidebar and redirected away
	first-run-with-solmara-lab                       # historical; the Solmara Lab stack is replayed by check-tutorial.sh, not here
	integrate-evidence-candidate-with-docker-compose # drift-checked by evidence-production-build-docs.test.mjs; needs Docker Compose
	issue-a-birth-certificate-vc-from-opencrvs       # needs the public OpenCRVS Farajaland demo; live and opt-in, not replayed in CI
	issue-evidence-access-tokens-with-registry-mint  # drift-checked by evidence-production-build-docs.test.mjs; needs a Registry Mint deployment
	issue-immunization-evidence-from-dhis2           # needs the public DHIS2 demo; live and opt-in, not replayed in CI
	manage-evidence-verifier-trust                   # how-to against the reader's own deployment; no fixed scenario this gate can replay
	move-evidence-to-production-signing              # drift-checked by evidence-production-build-docs.test.mjs; needs a Transit signer
	prove-an-evidence-project                        # how-to against the reader's own project; no fixed scenario this gate can replay
	publish-governed-sqlite-registry                 # Relay V2 journey; replayed by the Relay product and real-process acceptance gates
	publish-spreadsheet-secured-registry-api         # registryctl tutorial, replayed by check-tutorial.sh's REGISTRYCTL_TUTORIALS
	request-a-holder-bound-credential                # draft: true, hidden from the sidebar; no verified wallet flow exists to replay
	rotate-evidence-signing-keys                     # drift-checked by evidence-production-build-docs.test.mjs; needs a deployed signing key
	use-your-spreadsheet                             # registryctl tutorial, drift-checked by check-tutorial.sh
	verify-a-registered-parent-with-opencrvs         # needs the public OpenCRVS Farajaland demo; live and opt-in, not replayed in CI
	verify-opencrvs-claims                           # registryctl tutorial, replayed by check-tutorial.sh's REGISTRYCTL_TUTORIALS
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
	SPEC_FENCES=0
	SPEC_STEPS=()
	SPEC_LITERALS=()
	SPEC_OUTPUTS=()

	case "$1" in
	first-evidence-assertion)
		SPEC_FENCES=18
		SPEC_STEPS=(
			"run:2"
			"save:Start a small registry|python|1|registry.py"
			"background:3"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:4-5"
			"save:Create the Evidence Gateway project|yaml|1|questions/adult-status.yaml"
			"save:Create the Evidence Gateway project|rhai|1|derivations/adult-status.rhai"
			"run:6-17"
		)
		SPEC_LITERALS=(
			"releases/latest/download/evidencectl-install.sh | bash"
			"evidencectl new adult-status"
			"evidencectl request prepare adult-status"
			"--config .evidence/requests/first-assertion/authorization.curl"
			"evidencectl verify assertion.jws.json"
			"--format sd-jwt-vc"
			"--config .evidence/requests/first-vc/authorization.curl"
			"evidencectl verify assertion.sd-jwt"
			"evidencectl audit show --last-operation"
			"evidencectl dev clean"
		)
		SPEC_OUTPUTS=(
			"Created an editable OpenAPI authoring project in adult-status"
			"Evidence ready at http://127.0.0.1:8080"
			"Prepared request: .evidence/requests/first-assertion/request.json"
			"Prepared request: .evidence/requests/first-vc/request.json"
			"VERIFIED"
			"Local Evidence stopped"
			"ACCESS AUTHORIZED adult-status age-check requester="
			"DISCLOSURE RELEASED is_adult"
			"Removed stopped local Evidence state"
		)
		;;
	request-evidence-as-sd-jwt-vc)
		SPEC_FENCES=16
		SPEC_STEPS=(
			"background:1"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:2-10"
			"save:Model independently disclosed fields|yaml|1|schemas/adult-assessment.yaml"
			"save:Model independently disclosed fields|yaml|2|questions/adult-assessment.yaml"
			"save:Model independently disclosed fields|rhai|1|derivations/adult-assessment.rhai"
			"run:11-16"
		)
		SPEC_LITERALS=(
			"responseFormats: [signed-jws, sd-jwt-vc]"
			"--format sd-jwt-vc"
			"--header 'Accept: application/dc+sd-jwt'"
			"/.well-known/jwt-vc-issuer"
			"scalar-tampered.sd-jwt"
			"type: reviewed-structured-value"
			"sdJwtVc:"
			"evidencectl verify structured.sd-jwt"
		)
		SPEC_OUTPUTS=(
			"Evidence ready at http://127.0.0.1:8080"
			"Prepared request: .evidence/requests/scalar-vc/request.json"
			"disclosure: urn:registrystack:evidence:local:concept:adult-status:is_adult"
			"Tampered credential refused"
			"Prepared request: .evidence/requests/structured-vc/request.json"
			"disclosure: criterion"
			"disclosure: isAdult"
			"ACCESS AUTHORIZED adult-assessment age-assessment-review requester="
			"DISCLOSURE RELEASED adult_assessment"
			"Removed stopped local Evidence state"
		)
		;;
	run-oid4vci-interoperability-checks)
		SPEC_FENCES=4
		SPEC_STEPS=(
			"run:1"
			"save:Copy the complete configuration|yaml|1|.tutorial/oid4vci-adopter/oid4vci.yaml"
			"run:2"
			"run:4"
		)
		SPEC_LITERALS=(
			'actual `evidence-oid4vci` binary'
			'against the copied file, runs `inspect`'
			'probes `/health` and `/ready`'
			"EVIDENCE_OID4VCI_ADOPTER_ROOT=\"\$PWD/.tutorial/oid4vci-adopter\""
			"products/evidence/fixtures/interoperability/inji-oid4vci/profile.json"
			"products/evidence/scripts/compat/inji-oid4vci.sh"
			"PASS: sanitized Inji OID4VCI profile and Registry-side interoperability tests"
			"EVIDENCE_INJI_OID4VCI=1 products/evidence/scripts/compat/inji-oid4vci-upstream.sh"
			"PASS: pinned Inji OID4VCI source and client tests"
			"2fa12c3285b6523db340c3dd2333454b750b40a4"
			"f1d7ee2b14e996e18bfc7c40fbf89ec31b768951"
			"dbe60eef9a8c7b71ba58ee81cc7d0e5a92af7c7c"
		)
		SPEC_OUTPUTS=(
			"CONFIG COPIED: complete configuration has no untracked inputs"
			"CONFIG CHECKED: complete delivery configuration is valid"
			"METADATA INSPECTED: derived holder-bound batch ceiling is 4"
			"SERVICE READY: health and readiness are available on the delivery listener"
			"METRICS PRIVATE: metrics exist only on the separate loopback listener"
			"PRESENTATION VERIFIED: public wallet flow returned holder-bound Evidence"
			"CLEANUP COMPLETE: generated private material was removed"
			"PASS: sanitized Inji OID4VCI profile and Registry-side interoperability tests"
		)
		;;
	return-a-governed-value)
		SPEC_FENCES=10
		SPEC_STEPS=(
			"background:1"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:2"
			"save:Add the age-bracket question|yaml|1|questions/age-bracket.yaml"
			"save:Add the age-bracket question|rhai|1|derivations/age-bracket.rhai"
			"run:3-10"
		)
		SPEC_LITERALS=(
			"type: controlled-category"
			"values: [under-18, 18-to-24, 25-to-64, 65-or-older]"
			"evidencectl request prepare age-bracket"
			"--config .evidence/requests/age-bracket/authorization.curl"
			"evidencectl verify age-bracket.jws.json"
			"evidencectl audit show --last-operation"
			"evidencectl dev clean"
		)
		SPEC_OUTPUTS=(
			"Evidence ready at http://127.0.0.1:8080"
			"Prepared request: .evidence/requests/age-bracket/request.json"
			"VERIFIED"
			"Local Evidence stopped"
			"ACCESS AUTHORIZED age-bracket service-path-selection requester="
			"DISCLOSURE RELEASED age_bracket"
			"Removed stopped local Evidence state"
		)
		;;
	control-who-can-request-evidence)
		SPEC_FENCES=20
		SPEC_STEPS=(
			"background:1"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:2-20"
		)
		SPEC_LITERALS=(
			"evidencectl access policy add age-checks --question adult-status"
			"evidencectl access client add service-router"
			"--config .evidence/requests/age-checker-refused/authorization.curl"
			"--data-binary @.evidence/requests/age-checker-refused/request.json"
			"evidencectl access client revoke age-checker"
			"unexpected request preparation success"
			"ACCESS REFUSED requester=<pseudonym> reason=not_authorized"
		)
		SPEC_OUTPUTS=(
			"Evidence ready at http://127.0.0.1:8080"
			"Added access policy age-checks for adult-status."
			"Added client service-router with policy service-routing."
			"Prepared request: .evidence/requests/age-checker-refused/request.json"
			"Prepared request: .evidence/requests/service-router-allowed/request.json"
			"HTTP 403"
			'"code": "not_authorized"'
			"HTTP 200"
			"VERIFIED"
			"evidencectl: unknown or revoked active client age-checker"
			"Local Evidence stopped"
			"ACCESS REFUSED requester="
			"reason=not_authorized"
			"Removed stopped local Evidence state"
		)
		;;
	assert-a-role-bound-relationship)
		SPEC_FENCES=9
		SPEC_STEPS=(
			"run:1"
			"save:Start a relationship registry|python|1|registry.py"
			"background:2"
			"wait-http:http://127.0.0.1:8002/openapi.json"
			"run:3"
			"save:Create the Evidence Gateway project|yaml|1|questions/parent-relationship.yaml"
			"save:Create the Evidence Gateway project|rhai|1|derivations/parent-relationship.rhai"
			"run:4-9"
		)
		SPEC_LITERALS=(
			"subjects:"
			"--subject child:child_id=child-123"
			"--subject candidate-parent:candidate_id=parent-456"
			"--config .evidence/requests/parent-relationship/authorization.curl"
			"evidencectl verify parent-relationship.jws.json"
			"evidencectl dev clean"
		)
		SPEC_OUTPUTS=(
			"Created an editable OpenAPI authoring project in parent-relationship"
			"Evidence ready at http://127.0.0.1:8080"
			"Prepared request: .evidence/requests/parent-relationship/request.json"
			"VERIFIED"
			"Local Evidence stopped"
			"ACCESS AUTHORIZED parent-relationship relationship-check requester="
			"DISCLOSURE RELEASED relationship_confirmed"
			"Removed stopped local Evidence state"
		)
		;;
	refuse-unsafe-evidence-requests)
		SPEC_FENCES=11
		SPEC_STEPS=(
			"background:1"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:2-11"
		)
		SPEC_LITERALS=(
			'request["purpose"] = "age-check"'
			"--data-binary @unauthorized-request.json"
			"--write-out 'HTTP %{http_code}\\n'"
			"--data-binary @.evidence/requests/refusal-check/request.json"
			"evidencectl verify tampered-response.jws.json"
			"test ! -e tampered-response.verified.json"
		)
		SPEC_OUTPUTS=(
			"Evidence ready at http://127.0.0.1:8080"
			"Prepared request: .evidence/requests/refusal-check/request.json"
			"HTTP 403"
			"VERIFIED"
			"TAMPER REFUSED"
			"Local Evidence stopped"
		)
		;;
	verify-an-assertion-as-a-consumer)
		SPEC_FENCES=3
		SPEC_STEPS=("run:1-3")
		SPEC_LITERALS=(
			'context["trustedJwks"]'
			'context["verificationPolicy"]'
			".evidence/requests/first-assertion/verification.json"
			"--jws assertion.jws.json"
			"--jwks trusted-issuer-keys.json"
			"--policy verification-policy.json"
			'--at "$verified_at"'
		)
		SPEC_OUTPUTS=(
			"authentic: yes"
			"currently-valid: yes"
			'"value": true'
		)
		;;
	request-evidence-from-an-application)
		SPEC_FENCES=16
		SPEC_STEPS=(
			# The registry runs in the terminal the reader never moved out of
			# the first tutorial's directory, so it starts before fence 1's
			# `cd` rather than where the page prints it.
			"background:7"
			"wait-http:http://127.0.0.1:8000/openapi.json"
			"run:1-4"
			# Stands in for fences 5 and 6, the documented clone and build.
			"python-client"
			"run:8"
			"run-fails:9"
			"run:10-11"
			"save:Write the relying procedure|python|1|age_check.py"
			"run:12-14"
			"run-fails:15"
			"run:16"
		)
		SPEC_LITERALS=(
			"evidencectl access policy add app-age-checks --question adult-status"
			"evidencectl access client add age-check-app"
			"--generate-local-key"
			"evidencectl jwks --out trusted-issuer-keys.json secrets/signing-p256-public.jwk.json"
			'git clone --depth 1 --branch "v$installed"'
			"-p registry-evidence-client-py --lib"
			"--features registry-evidence-client-py/extension-module"
			'cp "../registry-stack/target/debug/$built" python-module/registry_evidence_client.so'
			'"private_key_jwt"'
			'Path(".evidence/clients/age-check-app/private.jwk").read_text()'
			"client.request_and_verify(client.prepare(spec))"
			"subject_expectations=expectations_for(person_id)"
		)
		SPEC_OUTPUTS=(
			"Registry listening on http://127.0.0.1:8000"
			"Added access policy app-age-checks for adult-status."
			"Added client age-check-app with policy app-age-checks."
			"evidenceAudience: urn:registrystack:evidence:local:client:age-check-app"
			"wrote trusted-issuer-keys.json"
			"Evidence ready at http://127.0.0.1:8080"
			"Mint ready at http://127.0.0.1:8081"
			"evidencectl: the active project requires a registered client selected with --client"
			'"assuranceProfile": "local"'
			'"response_format": "signed-jws"'
			"person-123 is_adult=True"
			"person-456 is_adult=False"
			"pinned binding recorded in subject-bindings.json"
			"unverifiable response, nothing read (policy)"
			"Local Evidence stopped"
			"Removed stopped local Evidence state"
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
# The documented commands stay pinned as SPEC_LITERALS, so an edit to them
# still has to be deliberate.
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

# Emit the sh fences named by a run: step, in order.
emit_run_step() {
	local slug="$1" range="$2" fence_dir="$3"
	local first="${range%%-*}"
	local last="${range##*-}"
	local i fence
	for ((i = first; i <= last; i++)); do
		fence="$(printf '%s/fence-%02d.sh' "$fence_dir" "$i")"
		if [[ ! -f "$fence" ]]; then
			printf 'tutorial spec error in %s: run step names sh fence %d, which does not exist\n' \
				"$slug" "$i" >&2
			exit 2
		fi
		printf '\nprintf "==> %s fence %02d\\n"\n' "$slug" "$i"
		cat "$fence"
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
	local slug="$1" number="$2" fence_dir="$3"
	local fence
	fence="$(printf '%s/fence-%02d.sh' "$fence_dir" "$number")"
	if [[ ! -f "$fence" ]]; then
		printf 'tutorial spec error in %s: run-fails step names sh fence %s, which does not exist\n' \
			"$slug" "$number" >&2
		exit 2
	fi
	printf '\nprintf "==> %s fence %02d (documented refusal)\\n"\n' "$slug" "$number"
	printf 'set +e\n'
	printf '( set -e\n'
	cat "$fence"
	printf ')\nrefusal_status=$?\nset -e\n'
	printf 'if ((refusal_status == 0))\nthen\n'
	printf '  printf "tutorial drift in %s: fence %02d succeeded, but the page documents a refusal\\n" >&2\n' \
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
	local slug="$1" number="$2" fence_dir="$3"
	local fence
	fence="$(printf '%s/fence-%02d.sh' "$fence_dir" "$number")"
	if [[ ! -f "$fence" ]] || [[ "$(wc -l <"$fence")" -ne 1 ]]; then
		printf 'tutorial spec error in %s: background step needs one sh line at fence %s\n' \
			"$slug" "$number" >&2
		exit 2
	fi
	local command
	IFS= read -r command <"$fence"
	printf '\nprintf "==> %s fence %02d (background)\\n"\n' "$slug" "$number"
	printf '%s &\n' "$command"
	printf 'BACKGROUND_PIDS+=("$!")\n'
}

emit_wait_http_step() {
	local url="$1"
	printf '\nfor attempt in {1..50}; do\n'
	printf '  if curl -fs %q >/dev/null 2>&1; then break; fi\n' "$url"
	printf '  if [[ "$attempt" -eq 50 ]]; then printf "tutorial service did not become ready\\n" >&2; exit 1; fi\n'
	printf '  sleep 0.1\n'
	printf 'done\n'
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
		edit:*) emit_edit_step "$slug" "${step#edit:}" "$tutorial_file" "$edit_dir" ;;
		save:*) emit_save_step "$slug" "${step#save:}" ;;
		background:*) emit_background_step "$slug" "${step#background:}" "$fence_dir" ;;
		wait-http:*) emit_wait_http_step "${step#wait-http:}" ;;
		*)
			printf 'tutorial spec error in %s: unknown step: %s\n' "$slug" "$step" >&2
			exit 2
			;;
		esac
	done
}

# How many sh fences a spec executes, for the summary line.
executed_fence_count() {
	local step range first last total=0
	for step in ${SPEC_STEPS[@]+"${SPEC_STEPS[@]}"}; do
		case "$step" in
		run:*)
			range="${step#run:}"
			first="${range%%-*}"
			last="${range##*-}"
			total=$((total + last - first + 1))
			;;
		run-fails:* | background:*) total=$((total + 1)) ;;
		esac
	done
	printf '%d' "$total"
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

	# Extract every sh fence, in order, into numbered files.
	fence_dir="$WORK_ROOT/fences/$slug"
	mkdir -p "$fence_dir"
	fence_count="$(awk -v outdir="$fence_dir" '
		/^```sh$/ { infence = 1; count += 1; next }
		infence && /^```$/ { infence = 0; next }
		infence { print > (outdir "/fence-" sprintf("%02d", count) ".sh") }
		END { print count + 0 }
	' "$tutorial_file")"

	if [[ "$fence_count" -ne "$SPEC_FENCES" ]]; then
		printf 'tutorial drift in %s: %s sh fences found, expected %s\n' \
			"$slug" "$fence_count" "$SPEC_FENCES" >&2
		printf 'Update SPEC_FENCES and SPEC_STEPS in %s when the change is intentional.\n' \
			"${BASH_SOURCE[0]}" >&2
		exit 1
	fi

	for literal in ${SPEC_LITERALS[@]+"${SPEC_LITERALS[@]}"}; do
		if ! grep -F -q -- "$literal" "$tutorial_file"; then
			printf 'tutorial drift in %s: required literal missing: %s\n' \
				"$slug" "$literal" >&2
			exit 1
		fi
	done

	printf '%s: %s sh fences, %s executed, %s required literals present\n' \
		"$slug" "$fence_count" "$(executed_fence_count)" "${#SPEC_LITERALS[@]}"

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
	if ! (cd "$reader_dir" && PATH="$SHIM_DIR:$PATH" CARGO_TARGET_DIR="$TARGET_DIR" bash "$run_script") 2>&1 |
		tee "$run_log"; then
		printf 'tutorial %s failed; the transcript ends just before this line\n' \
			"$slug" >&2
		exit 1
	fi

	for expected in ${SPEC_OUTPUTS[@]+"${SPEC_OUTPUTS[@]}"}; do
		if ! grep -F -q -- "$expected" "$run_log"; then
			printf 'tutorial output drift in %s: expected "%s" in the transcript\n' \
				"$slug" "$expected" >&2
			exit 1
		fi
	done
done

if ((${#EVIDENCE_TUTORIALS[@]} == 1)); then
	printf 'Checked 1 tutorial.\n'
else
	printf 'Checked %d tutorials.\n' "${#EVIDENCE_TUTORIALS[@]}"
fi
