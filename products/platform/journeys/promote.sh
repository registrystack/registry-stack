#!/usr/bin/env bash
# The promote acceptance journey: the files a development journey ended with,
# started as production.
#
# Steps, as the pass rule counts them: input, start-as-production, refusals,
# fix, start, call, same-contract. A cell is one product and stops at its first
# failing step. See README.md for the options, the two modes and the exit codes.
#
#   input                the development journey's run directory holds a
#                        finished cell for the product: a pass, or a cell
#                        that reached its first authenticated read (toT1) and
#                        stopped only at a step that cannot be walked by
#                        design, as an assisted cell does at hook. Otherwise the cell stops with
#                        journey.promote.no-input.
#   start-as-production  the same files, started with no development
#                        declaration. A refused start is an observation, not a
#                        failure: the step passes once the product either
#                        answered its readiness route or exited printing a
#                        diagnostic code.
#   refusals             the list of diagnostic codes from the product's
#                        production check and the list from the start. The two
#                        lists must be equal, or the run stops as a harness
#                        failure. An empty list stops the cell with
#                        journey.promote.nothing-refused. The count goes to
#                        refusalsMet in summary.json.
#   fix                  each refusal is fixed by the function fix_<code>. A
#                        code with no function is a harness failure that names
#                        it, so a new refusal is looked at and never recorded
#                        under a code the product did not print. Before the
#                        fixes the step fetches a token from the input's
#                        identity provider and keeps its claim names.
#   start                the fixed files, started. A refusal stops the cell
#                        with the product's code.
#   call                 the same token source and the same request as the
#                        development journey. A refusal stops the cell with
#                        http.<status>.<stage>.
#   same-contract        the request line, the headers other than the token
#                        and the token's claim names equal those the files gave
#                        before the fixes. The development journey saves no
#                        request, so the request is rebuilt from the same
#                        recipe and only the claim names are a real comparison.
#
# The input. --from RUN_DIR is a run directory of own-provider.sh that ended
# with --keep, under the same JOURNEY_CONTAINER_PREFIX. Without --from this run
# first runs own-provider.sh --keep into <out>-input. The runtime files hold absolute paths into that
# directory, so promote uses it in place and never copies it. The run takes
# over the kept containers and secrets, so its cleanup removes them. Without
# any finished cell, and with --from, the input is only read and no container is
# touched.
#
# What this script starts: no container of its own (a run without --from makes
# own-provider.sh start the two). One product process at a time, on the port the
# input's own-provider.json records. When the run ends it removes the input's
# containers and deletes its secrets/, through lib.sh's take-over.
#
# Run it from anywhere:
#   products/platform/journeys/promote.sh --bin-dir DIR [--from RUN_DIR]
#     [--product ID]... [--out DIR] [--expected FILE [--strict]]

set -euo pipefail

# shellcheck disable=SC1091 # lib.sh is checked on its own
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

journey_init promote --value-option from -- "$@"

journey_resolve_binaries "${JOURNEY_PRODUCTS[@]}"

# The input: --from RUN_DIR, or a run of own-provider.sh that this run makes
# with --keep, in a sibling of its own output directory so that the kept
# secrets are never inside the folder this run scans. A run this script made
# is always taken over, so a run in which no cell finishes still removes the
# containers the input left.
FROM=''
INPUT_JOURNEY=''
INPUT_MADE=0
prepare_input() {
	local option status=0
	local -a arguments=()
	journey_option_value from option
	if [[ -z "$option" ]]; then
		FROM=$JOURNEY_OUT-input
		for option in ${JOURNEY_SELECTED[@]+"${JOURNEY_SELECTED[@]}"}; do
			arguments+=(--product "$option")
		done
		"$JOURNEY_LIB_DIR/own-provider.sh" --keep --bin-dir "$JOURNEY_BIN_DIR" --out "$FROM" ${arguments[@]+"${arguments[@]}"} || status=$?
		# Exit 1 is the development journey's own answer on main: some cell
		# did not finish. Anything else is a harness or usage failure.
		[[ $status -le 1 ]] || journey_harness_failure "own-provider.sh, run as the input, exited with status $status; see its output above"
		INPUT_MADE=1
	else
		[[ -d "$option" ]] || journey_usage_error "--from $option is not a directory"
		FROM=$(CDPATH='' cd -- "$option" && pwd -P) || journey_usage_error "cannot resolve --from $option"
	fi
	[[ -f "$FROM/run.json" && -f "$FROM/summary.json" ]] ||
		journey_usage_error "$FROM holds no run.json and summary.json: it is not a journey run directory"
	INPUT_JOURNEY=$(jq -er '.journey' "$FROM/run.json") || journey_usage_error "cannot read the journey name in $FROM/run.json"
}

# The cell's product, its input and the facts the steps share.
CELL=''
PROJECT=''
RUNTIME_FILE=''
PORT=''
TOOL_BIN=''
SERVER_BIN=''
READY_PATH=/ready
STATE_FILE=''
TAKEN_OVER=0
SERVE_COMMAND=()
CHECK_COMMAND=()
START_CODES=''
CHECK_CODES=''

# field PRODUCT FIELD: a products.yaml field on stdout.
field() {
	local value
	journey_product_field "$1" "$2" value
	printf '%s' "$value"
}

# input_outcome PRODUCT VAR: whether the development journey finished the
# product: `finished`, else the outcome it recorded (fail, unreached) or
# `missing` when summary.json has no cell. A cell finished when it passed, or
# when it reached the first authenticated read (toT1) and then stopped only at a
# step the journey cannot walk by design, as an assisted cell does at the hook
# step. An assisted cell is accepted: the baseline input is an assisted run, and
# promote starts from the files the assists left.
input_outcome() {
	local value
	value=$(jq -r --arg product "$1" '[.cells[] | select(.product == $product)] | if length != 1 then "missing"
		elif .[0].outcome == "pass" or (.[0].outcome == "unreached" and .[0].toT1 != null) then "finished"
		else .[0].outcome end' "$FROM/summary.json") ||
		journey_harness_failure "cannot read the cell of $1 in $FROM/summary.json"
	printf -v "$2" '%s' "$value"
}

# take_over_input: the run becomes responsible for the kept containers and
# secrets of the input, once, before the first product is started.
take_over_input() {
	[[ $TAKEN_OVER -eq 0 ]] || return 0
	[[ -f "$FROM/kept" ]] ||
		journey_usage_error "$FROM has a finished cell but was not run with --keep, so its database and identity provider are gone; run $INPUT_JOURNEY with --keep"
	journey_require_docker
	journey_take_over_run "$FROM"
	TAKEN_OVER=1
}

# locate_input PRODUCT: PROJECT, RUNTIME_FILE and PORT of the input's files.
locate_input() {
	local product=$1
	case "$INPUT_JOURNEY" in
	own-provider) ;;
	*) journey_harness_failure "no input layout is written for journey $INPUT_JOURNEY; add one to locate_input in promote.sh" ;;
	esac
	PROJECT=$FROM/work/$product/$product
	case "$product" in
	evidence) RUNTIME_FILE=$PROJECT/local-target.yaml ;;
	render) RUNTIME_FILE=$FROM/work/render/runtime.yaml ;;
	*) RUNTIME_FILE=$PROJECT/runtime.yaml ;;
	esac
	[[ -f "$RUNTIME_FILE" ]] || journey_harness_failure "the input of $product holds no runtime file at $RUNTIME_FILE"
	PORT=$(jq -er '.productPort' "$FROM/own-provider.json") ||
		journey_harness_failure "cannot read productPort in $FROM/own-provider.json"
}

# recipe PRODUCT: the tool, the server, the readiness route, the command that
# starts the runtime and the production check, as the reader types them. A
# product without a recipe is a harness failure that names the gap.
recipe() {
	local product=$1 tool server help
	READY_PATH=/ready
	server=$(field "$product" binary)
	case "$product" in
	breg) tool=bregctl ;;
	casework) tool=caseworkctl ;;
	messaging) tool=messagingctl ;;
	scheduling) tool=schedulingctl ;;
	documents) tool=documentsctl ;;
	coordinator) tool=coordinatorctl ;;
	adapter) tool=adapterctl ;;
	evidence) tool=evidencectl ;;
	render) tool=registry-render ;;
	*) journey_harness_failure "no recipe is written for product $product; add one to recipe in promote.sh" ;;
	esac
	journey_bin "$tool" TOOL_BIN
	journey_bin "$server" SERVER_BIN
	case "$product" in
	breg | coordinator) SERVE_COMMAND=("$SERVER_BIN" --runtime-config "$RUNTIME_FILE") ;;
	casework | messaging | scheduling | documents) SERVE_COMMAND=("$SERVER_BIN" --runtime-config "$RUNTIME_FILE" serve) ;;
	render) SERVE_COMMAND=("$SERVER_BIN" serve --runtime-config "$RUNTIME_FILE") ;;
	*) journey_harness_failure "no start recipe is written for $product; add one to recipe in promote.sh" ;;
	esac
	[[ "$product" != scheduling ]] || READY_PATH=/readyz
	case "$product" in
	breg | casework | scheduling) CHECK_COMMAND=("$TOOL_BIN" --format json check "$PROJECT" --runtime-config "$RUNTIME_FILE") ;;
	messaging | documents) CHECK_COMMAND=("$TOOL_BIN" --format json check --runtime-config "$RUNTIME_FILE") ;;
	coordinator) CHECK_COMMAND=("$TOOL_BIN" --format json --runtime-config "$RUNTIME_FILE" check --project "$PROJECT") ;;
	render) CHECK_COMMAND=("$TOOL_BIN" check --runtime-config "$RUNTIME_FILE" --format json) ;;
	adapter)
		CHECK_COMMAND=("$TOOL_BIN" --format json check "$PROJECT/project.yaml"
			--profile "$JOURNEY_ROOT/products/adapter/profiles/breg-records/profile.yaml"
			--pack "$PROJECT/pack.yaml" --runtime "$RUNTIME_FILE")
		;;
	evidence) CHECK_COMMAND=("$TOOL_BIN" check "$PROJECT" --target "$RUNTIME_FILE" --format json) ;;
	esac
	# The production check is the same check with the tool's production flag,
	# for a tool that has one. A tool without it has no production check, so
	# its list is the plain check's.
	help=$("$TOOL_BIN" check --help 2>&1) || journey_harness_failure "cannot read the help of $tool check"
	if [[ "$help" == *--production* ]]; then
		CHECK_COMMAND+=(--production)
	fi
}

# diagnostic_codes FILE...: every diagnostic code a product printed in FILE, one
# per line, sorted and unique: the code nested in a diagnostic's message as
# error[code], else the diagnostic's own code, plus the code of a human
# error[code] line.
diagnostic_codes() {
	local file
	for file in "$@"; do
		[[ -s "$file" ]] || continue
		jq -r '(.diagnostics[]? | ((.message // "") | [match("error\\[([a-z0-9._-]+)\\]").captures[0].string] | first) // .code),
			(.error.code? // empty)' "$file" 2>/dev/null || true
		perl -ne 'print "$1\n" if /^error\[([a-z0-9._-]+)\]/' "$file"
	done | LC_ALL=C sort -u
}

# port_is_free PORT
port_is_free() {
	perl -MIO::Socket::INET -e '
		IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => $ARGV[0], Proto => "tcp", Listen => 1, ReuseAddr => 1)
		  or exit 1;' "$1"
}

# production_start: start the product with the input's files and no
# development declaration, wait for its readiness route or its exit, and write
# `started` or `refused` to STATE_FILE. The product's own output is the step's
# output. A started product is stopped before this returns. Exits 0 once the
# attempt has an answer, so a refused start is an observation.
# shellcheck disable=SC2329 # run through journey_step
production_start() {
	local pid attempt=0 state=''
	"${SERVE_COMMAND[@]}" &
	pid=$!
	while ((attempt < 60)); do
		if ! kill -0 "$pid" 2>/dev/null; then
			state=refused
			break
		fi
		if curl --silent --fail --output /dev/null "http://127.0.0.1:$PORT$READY_PATH"; then
			state=started
			break
		fi
		sleep 0.5
		attempt=$((attempt + 1))
	done
	if [[ -z "$state" ]]; then
		printf 'the product neither answered %s nor exited within 30 seconds\n' "$READY_PATH" >&2
		kill -TERM "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
		return 1
	fi
	if [[ "$state" == refused ]]; then
		wait "$pid" 2>/dev/null || printf 'the product exited with status %s\n' "$?" >&2
	else
		kill -TERM "$pid"
		for attempt in $(seq 1 100); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.1
		done
		if kill -0 "$pid" 2>/dev/null; then
			kill -KILL "$pid"
			printf 'the product ignored SIGTERM and was killed\n' >&2
		fi
		wait "$pid" 2>/dev/null || true
	fi
	printf '%s\n' "$state" >"$STATE_FILE"
}

# production_check: the production check, whatever it answers. Its exit status
# goes to stderr; its report is the step's stdout.
# shellcheck disable=SC2329 # run through journey_step
production_check() {
	local status=0
	"${CHECK_COMMAND[@]}" || status=$?
	printf 'check exit status %s\n' "$status" >&2
}

# FIX_TABLE: the fix for each diagnostic code a production refusal may carry,
# applied to the reader's files. A function per code, named
# fix_<code with dots and dashes as underscores>, is looked up here. The table
# is empty until a production posture exists to refuse anything.
apply_fix() {
	local code=$1 function
	function=fix_${code//[.-]/_}
	if ! declare -F "$function" >/dev/null; then
		journey_harness_failure "the production refusal '$code' of $CELL has no fix in promote.sh; add $function and the sentence it applies"
	fi
	"$function"
}

# call_recipe PRODUCT: the caller's client in the input's identity provider
# and the first authenticated request, as the development journey makes it.
# Sets CLIENT, CALL_METHOD, CALL_PATH and
# CALL_OPTIONS (extra request options). The request has no body unless the
# product's tutorial needs one.
call_recipe() {
	local product=$1 work
	journey_workdir "$product" work
	CALL_METHOD=GET
	CALL_OPTIONS=()
	case "$product" in
	breg)
		CLIENT="directory-client"
		CALL_PATH=/v1/records/contacts
		;;
	casework)
		CLIENT="casework-client"
		CALL_PATH=/v1/review-policies
		;;
	messaging)
		CLIENT="case-system"
		CALL_METHOD=POST
		CALL_PATH=/v1/messages
		printf '%s\n' '{"senderProfile":"reminders-sms","to":{"phone":"+15555550100"},"template":{"id":"appointment-reminder-sms","version":"1"},"locale":"en","data":{"name":"Ada Lovelace","day":"2026-10-01","office":"Central Registry Office"}}' |
			journey_write_file "$work/call-body.json"
		CALL_OPTIONS=(--header 'Content-Type: application/json' --header 'Idempotency-Key: journey-first-call' --data-file "$work/call-body.json")
		;;
	scheduling)
		CLIENT="scheduling-booking-agent"
		CALL_PATH=/v1/locations
		;;
	documents)
		CLIENT="case-portal"
		CALL_PATH=/v1/document-policies
		;;
	coordinator)
		CLIENT="coordinator-producer"
		CALL_PATH=/v1/workflows/coordinator
		;;
	render)
		CLIENT="portal"
		CALL_METHOD=POST
		CALL_PATH=/v1/render/letter
		[[ -f "$FROM/work/render/request.json" ]] || journey_harness_failure "the input of render holds no request.json"
		CALL_OPTIONS=(--header 'Content-Type: application/json' --data-file "$FROM/work/render/request.json")
		;;
	*) journey_harness_failure "no call recipe is written for $product; add one to call_recipe in promote.sh" ;;
	esac
}

# fetch_token STEP VAR: a client-credentials token for CLIENT from the input's
# identity provider, the same source the development journey used, into VAR.
# The client secret is the input's kept secret client-<product>.
fetch_token() {
	local step=$1 variable=$2 token_url
	token_url=$(jq -er '.issuerUrl' "$FROM/own-provider.json")/protocol/openid-connect/token ||
		journey_harness_failure "cannot read issuerUrl in $FROM/own-provider.json"
	journey_http "$step" --concepts client,grant,scopes \
		--typed "curl -X POST $token_url -d grant_type=client_credentials -d client_id=$CLIENT -d client_secret=\$SECRET" \
		--form grant_type=client_credentials --form "client_id=$CLIENT" --form-secret "client_secret=client-$CELL" \
		--capture-secret .access_token "$variable" POST "$token_url" ||
		journey_harness_failure "the identity provider refused the client credentials of $CLIENT (HTTP $JOURNEY_HTTP_STATUS); see $JOURNEY_STEP_STDOUT"
}

# claim_names VARIABLE: the names of the claims in the token held in VARIABLE,
# sorted, one per line. The token reaches perl through a pipe.
claim_names() {
	local variable=$1
	printf '%s' "${!variable}" | perl -MMIME::Base64 -MJSON::PP -e '
		local $/; my $token = <STDIN>;
		my $payload = (split /\./, $token)[1] // "";
		$payload =~ tr{-_}{+/};
		$payload .= "=" x ((4 - length($payload) % 4) % 4);
		print "$_\n" for sort keys %{ decode_json(decode_base64($payload)) };' ||
		journey_harness_failure "cannot read the claims of the token of $CELL"
}

# logged_stage FILE...: the stage word for the `failed_check` label of the last
# refusal line the product logged, or nothing when that label has no stage word.
logged_stage() {
	perl -e '
		my $stage = "";
		my %check_stage = (
			"credential-malformed" => "header",
			"token-algorithm" => "algorithm",
			"token-type" => "token-type",
			"token-key" => "key",
			"token-signature" => "signature",
			"token-issuer" => "issuer",
			"token-audience" => "audience",
			"token-time" => "time",
			"token-client" => "client",
			"token-assertion-issuer" => "client",
			"scope" => "scope",
			"key-source-unavailable" => "unavailable",
		);
		local $/;
		for my $path (@ARGV) {
			open my $fh, "<", $path or next;
			my $text = <$fh>;
			next unless defined $text;
			$text =~ s/\e\[[0-9;]*m//g;
			# The refusal recorder writes a `failed_check` label, which the map
			# turns into the stage word the table lists. The last refusal
			# decides, and a label with no stage word leaves the stage empty,
			# so the problem code names the refusal instead.
			while ($text =~ /\bfailed_check"?[:=]\s*"([a-z]+(?:-[a-z]+)*)"/g) {
				$stage = exists $check_stage{$1} ? $check_stage{$1} : "";
			}
		}
		print $stage;' "$@"
}

# The request as the development journey made it and as promote makes it: the
# method, the path and the headers other than the token's. The development
# journey does not save its request, so the contract is rebuilt from the same
# recipe, and the token's claim names are read from a token fetched from the
# same source before the fixes.
request_contract() {
	printf '%s %s\n' "$CALL_METHOD" "$CALL_PATH"
	printf '%s\n' "${CALL_OPTIONS[@]+"${CALL_OPTIONS[@]}"}" | LC_ALL=C sort
}

# promote_call_failure: the call after the fixes was refused. The cell stops
# with the status and the authentication stage the product logged, or with the
# problem code when its log names no stage.
promote_call_failure() {
	local stage='' attempt
	[[ "$JOURNEY_HTTP_STATUS" != 000 ]] ||
		journey_harness_failure "the call to $CELL got no answer; see $JOURNEY_STEP_STDERR"
	for attempt in 1 2 3; do
		journey_process_log server SERVER_LOG_UNUSED
		stage=$(logged_stage "$START_STDOUT" "$START_STDERR")
		[[ -z "$stage" ]] || break
		[[ $attempt -eq 3 ]] || sleep 1
	done
	if [[ -n "$stage" ]]; then
		journey_fail call "http.$JOURNEY_HTTP_STATUS.$stage"
	elif [[ "${JOURNEY_HTTP_PROBLEM_CODE:-}" =~ ^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)*$ ]]; then
		journey_fail call "product.$JOURNEY_HTTP_PROBLEM_CODE"
	else
		journey_harness_failure "the call to $CELL answered HTTP $JOURNEY_HTTP_STATUS with no authentication stage in its log and no problem code; see $JOURNEY_HTTP_HEADERS"
	fi
}

walk_product() {
	local product=$1 tier outcome count code dev_claims dev_contract
	journey_product_field "$product" tier tier
	CELL=$product
	journey_cell_begin "$product"
	if [[ "$tier" == supporting ]]; then
		journey_unreached input "Supporting runtime. It is promoted with its parent."
		journey_cell_end
		return 0
	fi

	# input
	input_outcome "$product" outcome
	if [[ "$outcome" != finished ]]; then
		printf 'promote: the %s journey did not finish for %s (cell outcome %s); nothing to promote\n' "$INPUT_JOURNEY" "$product" "$outcome" >&2
		journey_fail input journey.promote.no-input
		journey_cell_end
		return 0
	fi
	locate_input "$product"
	recipe "$product"
	call_recipe "$product"
	take_over_input
	journey_pass input

	# start-as-production
	STATE_FILE=$JOURNEY_OUT/$product/production-start.state
	port_is_free "$PORT" || journey_harness_failure "port $PORT is in use; promote cannot start $product on it"
	journey_step start-as-production --timeout 90 --typed "${SERVE_COMMAND[*]##*/}" -- production_start ||
		journey_harness_failure "the start of $product neither answered nor exited; see $JOURNEY_STEP_STDERR"
	[[ -f "$STATE_FILE" ]] || journey_harness_failure "the start attempt of $product left no state; see $JOURNEY_STEP_STDERR"
	START_CODES=$(diagnostic_codes "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR")
	if [[ "$(<"$STATE_FILE")" == refused && -z "$START_CODES" ]]; then
		journey_harness_failure "the start of $product was refused and printed no diagnostic code; see $JOURNEY_STEP_STDERR"
	fi
	if [[ "$(<"$STATE_FILE")" == started ]]; then
		START_CODES=''
	fi
	journey_pass start-as-production

	# refusals
	journey_step refusals --typed "${CHECK_COMMAND[*]##*/}" -- production_check ||
		journey_harness_failure "the production check of $product did not run; see $JOURNEY_STEP_STDERR"
	CHECK_CODES=$(diagnostic_codes "$JOURNEY_STEP_STDOUT")
	if [[ "$CHECK_CODES" != "$START_CODES" ]]; then
		journey_harness_failure "the production check of $product lists [${CHECK_CODES//$'\n'/ }] and its start lists [${START_CODES//$'\n'/ }]; the two lists must be equal (see $JOURNEY_STEP_STDOUT)"
	fi
	if [[ -z "$CHECK_CODES" ]]; then
		journey_fail refusals journey.promote.nothing-refused
		journey_cell_end
		return 0
	fi
	count=$(printf '%s\n' "$CHECK_CODES" | wc -l | tr -d ' ')
	journey_count refusals "$count"
	journey_pass refusals

	# fix: first the contract as the development files give it (the claim names
	# of a token from the same source and the request), then each refusal's fix.
	fetch_token fix DEV_TOKEN
	dev_claims=$(claim_names DEV_TOKEN)
	dev_contract=$(request_contract)
	while IFS= read -r code; do
		apply_fix "$code"
	done <<<"$CHECK_CODES"
	journey_pass fix

	# start: the fixed files, started as production. Any refusal now is the
	# cell's stop, with the product's code.
	local status=0
	port_is_free "$PORT" || journey_harness_failure "port $PORT is in use; promote cannot start $product on it"
	journey_start start server --settle 3 -- "${SERVE_COMMAND[@]}" || status=$?
	if [[ $status -ne 0 ]]; then
		code=$(diagnostic_codes "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR" | head -n 1)
		[[ -n "$code" ]] || journey_harness_failure "the start of $product after the fixes was refused and printed no diagnostic code; see $JOURNEY_STEP_STDERR"
		journey_fail start "product.$code"
		journey_cell_end
		return 0
	fi
	START_STDOUT=$JOURNEY_STEP_STDOUT
	START_STDERR=$JOURNEY_STEP_STDERR
	journey_ready start server --timeout 90 -- curl --silent --show-error --fail --output /dev/null "http://127.0.0.1:$PORT$READY_PATH" ||
		journey_harness_failure "$product kept running but did not answer $READY_PATH within 90 seconds; see $START_STDERR"
	journey_pass start

	# call: the same token source and the same request.
	fetch_token call TOKEN
	journey_http call --bearer TOKEN "${CALL_OPTIONS[@]+"${CALL_OPTIONS[@]}"}" "$CALL_METHOD" "http://127.0.0.1:$PORT$CALL_PATH" || status=$?
	if [[ $status -ne 0 ]]; then
		promote_call_failure
		journey_cell_end
		return 0
	fi
	journey_pass call

	# same-contract: the request and the token's claim names are those the
	# development files gave. Stopping the server is part of this step.
	if [[ "$(claim_names TOKEN)" != "$dev_claims" ]]; then
		journey_harness_failure "the token claims of $product differ between the development files and the production start"
	fi
	[[ "$(request_contract)" == "$dev_contract" ]] || journey_harness_failure "the request of $product changed between the development files and the production start"
	journey_stop same-contract server || journey_harness_failure "the server of $product ignored SIGTERM"
	journey_pass same-contract
	journey_cell_end
}

prepare_input
if [[ $INPUT_MADE -eq 1 ]]; then
	take_over_input
fi

for product in "${JOURNEY_PRODUCTS[@]}"; do
	walk_product "$product"
done

journey_finish
