#!/usr/bin/env bash
# The rstack-dev acceptance journey: each product from nothing to a development
# run started by `rstack dev`, using the issuer the run starts and no identity
# provider of the reader's own.
#
# Steps, as the pass rule counts them: init, plan, start, issuer, token, call,
# hook, keep, attach, stop. A cell is one product and stops at its first
# failing step. See README.md for the options, the two modes and the exit codes.
#
# What this script starts: nothing of its own except the optional PostgreSQL
# container of the attach step. `rstack dev` starts its own PostgreSQL (and a
# mail sink for a Messaging smtp provider) under the names rstack-dev-<run> and
# rstack-dev-mailpit-<run>. The cleanup hook stops every run still live with
# `rstack dev stop` and reports, never removes, a container that remains.
#
# Recipes. The steps from `start` on need a recipe per product: the person to
# sign in as, the request that makes the first authenticated call and, for
# keep, the record to write and read back. Only the products whose recipe is
# written here can walk those steps.
#
# Run it from anywhere:
#   products/platform/journeys/rstack-dev.sh --bin-dir DIR [--product ID]...
#     [--out DIR] [--expected FILE [--strict]] [--keep]

set -euo pipefail

# shellcheck disable=SC1091 # lib.sh is checked on its own
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

journey_init rstack-dev -- "$@"
journey_require_docker

# The tools every selected product's init needs, and rstack itself.
journey_resolve_binaries --package registry-rstack "${JOURNEY_PRODUCTS[@]}"
journey_bin rstack RSTACK_BIN

# rstack dev reads its tools from these variables and keeps its state in a
# directory that must be owner-only. Both sit inside the run folder, so an
# installed rstack store and an earlier run's state are never read. A variable
# names a path even when the file is absent: a missing tool is then reported
# by rstack and never replaced by an installed one.
STATE_DIR=$JOURNEY_OUT/rstack-state
INSTALL_ROOT=$JOURNEY_OUT/rstack-install
mkdir -m 700 -- "$STATE_DIR" "$INSTALL_ROOT"
export RSTACK_DEV_STATE_DIR=$STATE_DIR
unset RSTACK_DEV_DATABASE_URL RSTACK_DEV_DATABASE_CA
for name in breg casework evidence messaging scheduling documents coordinator adapter discovery; do
	upper=$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')
	export "RSTACK_${upper}_BIN=$JOURNEY_BIN_DIR/$name"
	export "RSTACK_${upper}CTL_BIN=$JOURNEY_BIN_DIR/${name}ctl"
done
export RSTACK_RENDER_BIN=$JOURNEY_BIN_DIR/registry-render

# Runs this script started and has not yet stopped, one id per line.
LIVE_RUNS=''
# The product whose cell is open, for messages.
CELL=''
# The containers `rstack dev` names for a run.
run_containers() {
	printf 'rstack-dev-%s\nrstack-dev-mailpit-%s\n' "$1" "$1"
}

# rstack_dev ARGUMENTS...: `rstack dev` with the run's own state and an empty
# install root, reporting in JSON.
rstack_dev() {
	"$RSTACK_BIN" --install-root "$INSTALL_ROOT" --format json dev "$@"
}

# state_is_empty: no run directory remains in the state directory. A `failed`
# folder only holds kept logs, and a name starting with a dot is a run whose
# files are being deleted.
state_is_empty() {
	local entry
	for entry in "$STATE_DIR"/* "$STATE_DIR"/.[!.]*; do
		[[ -e "$entry" ]] || continue
		[[ ! "${entry##*/}" =~ ^[0-9a-f]{32}$ ]] || return 1
	done
	return 0
}

# containers_absent RUN: neither container of RUN exists.
containers_absent() {
	[[ -z "$(docker ps --all --quiet --filter "name=^rstack-dev-$1\$" --filter "name=^rstack-dev-mailpit-$1\$")" ]]
}

# stop_run RUN: stop a run through rstack's own `rstack dev stop`, wait for its
# files and containers to go and forget the run. Returns 1 when something
# remains, with the cause on stderr.
stop_run() {
	local run=$1 name left=0
	if ! rstack_dev stop "$run" >/dev/null; then
		printf 'rstack dev stop %s failed\n' "$run" >&2
		return 1
	fi
	LIVE_RUNS=$(printf '%s' "$LIVE_RUNS" | grep -vx -- "$run" || true)
	journey_poll 30 -- state_is_empty || {
		printf 'the state directory still holds files of run %s\n' "$run" >&2
		left=1
	}
	while IFS= read -r name; do
		journey_check_absent "$name" || left=1
	done < <(run_containers "$run")
	return "$left"
}

# stop_live_runs: the cleanup hook. Every run this script started and did not
# stop is stopped by rstack. A run that does not stop is a cleanup failure.
stop_live_runs() {
	local run status=0
	while IFS= read -r run; do
		[[ -n "$run" ]] || continue
		stop_run "$run" || status=1
	done <<<"$LIVE_RUNS"
	return "$status"
}

# Remove only the volumes identified by our private state directory.
remove_project_volumes() {
	local state key volume status=0
	for state in "$STATE_DIR"/development-project-*; do
		[[ -d "$state" ]] || continue
		key=${state##*/development-project-}
		[[ "$key" =~ ^[0-9a-f]{32}$ ]] || continue
		volume=rstack-development-project-$key
		if [[ "$(docker volume ls --quiet --filter "label=org.registrystack.rstack.development-project=$key")" == "$volume" ]]; then
			if ! docker volume rm "$volume" >/dev/null; then
				status=1
				continue
			fi
		fi
		rm -rf -- "$state" || status=1
	done
	return "$status"
}
journey_at_cleanup remove_project_volumes
journey_at_cleanup stop_live_runs

# diagnostic_code FILE...: the first diagnostic code a product printed in any
# FILE, from a JSON report or from an error[code] line. Empty when none.
diagnostic_code() {
	local file code=''
	for file in "$@"; do
		code=$(jq -r '(.diagnostics[0].code // .error.code // empty)' "$file" 2>/dev/null || true)
		if [[ -z "$code" ]]; then
			code=$(perl -ne 'if (/^error\[([a-z0-9.-]+)\]/) { print $1; last }' "$file")
		fi
		[[ -z "$code" ]] || break
	done
	printf '%s' "$code"
}

# fail_with_product_code STEP FILE...: the cell stops at STEP with the code the
# product printed. A refusal that prints no code is a harness failure: the
# journey would otherwise invent one.
fail_with_product_code() {
	local step=$1 code
	shift
	code=$(diagnostic_code "$@")
	[[ -n "$code" ]] || journey_harness_failure "step $step of $CELL failed and printed no diagnostic code; see $*"
	journey_fail "$step" "product.$code"
}

# The command that writes a product's starter project, as a reader types it.
# PROJECT is a directory that does not exist yet. A product with no init
# command gets the command a reader would try first.
init_command() {
	local product=$1 project=$2 tool
	case "$product" in
	breg) INIT_COMMAND=("$JOURNEY_BIN_DIR/bregctl" init "$project") ;;
	casework) INIT_COMMAND=("$JOURNEY_BIN_DIR/caseworkctl" init "$project") ;;
	messaging) INIT_COMMAND=("$JOURNEY_BIN_DIR/messagingctl" init "$project") ;;
	evidence) INIT_COMMAND=("$JOURNEY_BIN_DIR/evidencectl" init --profile local --starter "$JOURNEY_ROOT/products/evidence/examples/standalone" "$project") ;;
	scheduling) INIT_COMMAND=("$JOURNEY_BIN_DIR/schedulingctl" init --template standalone-exact-time "$project") ;;
	documents) INIT_COMMAND=("$JOURNEY_BIN_DIR/documentsctl" init "$project") ;;
	coordinator) INIT_COMMAND=("$JOURNEY_BIN_DIR/coordinatorctl" init --directory "$project" --id delayed-follow-up) ;;
	render) INIT_COMMAND=("$JOURNEY_BIN_DIR/registry-render" init "$project") ;;
	adapter) INIT_COMMAND=("$JOURNEY_BIN_DIR/adapterctl" --format json init "$project") ;;
	discovery) INIT_COMMAND=("$JOURNEY_BIN_DIR/discoveryctl" init "$project") ;;
	*) journey_harness_failure "no init command is written for product $product" ;;
	esac
	tool=${INIT_COMMAND[0]##*/}
	[[ -x "${INIT_COMMAND[0]}" ]] || journey_usage_error "$tool is not in $JOURNEY_BIN_DIR"
}

# The plan a reader writes for a product that init gave none for, naming the
# product `rstack dev` is asked to start. It is the smallest plan the format
# allows, so a refusal is about the product and not about the plan's other
# parts.
write_probe_plan() {
	local product=$1 project=$2
	journey_write_file "$project/dev.yaml" --concepts development-plan,issuer-name,audience <<PLAN
apiVersion: id.registrystack.org/formats/rstack/dev/v1alpha1
kind: RStackDev
issuer: run
products:
  - {product: $product, project: ., audience: "urn:example:$product"}
people: {}
PLAN
}

# The recipe of the steps from token on. PERSON is the test person the project
# names, CALL_METHOD and CALL_PATH the first authenticated request, CALL_BODY
# the request body or empty.
recipe() {
	local product=$1
	CALL_BODY=''
	case "$product" in
	messaging)
		PERSON=case-system
		CALL_METHOD=POST
		CALL_PATH=/v1/messages
		CALL_BODY='{"senderProfile":"reminders-sms","to":{"phone":"+15555550100"},"template":{"id":"appointment-reminder-sms","version":"1"},"locale":"en","data":{"name":"Ada Lovelace","day":"2026-10-01","office":"Central Registry Office"}}'
		;;
	breg)
		PERSON=editor
		CALL_METHOD=GET
		CALL_PATH=/v1/records/contacts
		;;
	casework)
		PERSON=staff
		CALL_METHOD=GET
		CALL_PATH=/v1/review-policies
		;;
	evidence)
		PERSON=caller
		CALL_METHOD=GET
		CALL_PATH=/v1/evidence-definitions
		;;
	scheduling) PERSON=reader; CALL_METHOD=GET; CALL_PATH=/v1/offerings ;;
	documents) PERSON=reader; CALL_METHOD=GET; CALL_PATH=/v1/document-policies ;;
	coordinator) PERSON=reader; CALL_METHOD=GET; CALL_PATH=/v1/workflows/delayed-follow-up ;;
	adapter) PERSON=reader; CALL_METHOD=GET; CALL_PATH=/.well-known/registry-adapter/effective-contract ;;
	render) PERSON=reader; CALL_METHOD=GET; CALL_PATH=/v1/documents ;;
	discovery) PERSON=''; CALL_METHOD=GET; CALL_PATH=/v1/services ;;
	esac
}

# BReg's starter owns contact creation. Add its documented after-write URL
# hook to the disposable copy so that both the write and delivery are visible.
add_contact_hook() {
	local project=$1
	python3 - "$project/registry.yaml" <<'PYHOOK'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
marker = "\nactions:\n"
assert source.count(marker) == 1
hook = """    hooks:
      - id: contact-created
        phase: after
        trigger: created
        projection: [name]
        handler:
          type: url
          destinationId: contact-sink
"""
path.write_text(source.replace(marker, hook + marker))
PYHOOK
}

# The Adapter starter writes two effects to an authored reference endpoint.
# Speak the documented fixture's two replies over a disposable local socket.
start_adapter_source() {
	local project=$1 work=$2
	python3 - "$work/adapter-source.port" <<'PYSOURCE' &
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import json
import sys

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        bodies = {
            "/drafts": {"sourceId": "source-17"},
            "/finalizations?source_id=source-17": {"name": "Example Person"},
        }
        body = bodies.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

with HTTPServer(("127.0.0.1", 0), Handler) as server:
    Path(sys.argv[1]).write_text(str(server.server_port))
    server.serve_forever()
PYSOURCE
	ADAPTER_SOURCE_PID=$!
	journey_poll 10 -- test -s "$work/adapter-source.port"
	local port
	port=$(cat "$work/adapter-source.port")
	perl -pi -e "s/127[.]0[.]0[.]1:1\$/127.0.0.1:$port/" "$project/runtime.example.yaml"
}

stop_adapter_source() {
	if [[ -n "${ADAPTER_SOURCE_PID:-}" ]]; then
		kill "$ADAPTER_SOURCE_PID" 2>/dev/null || true
		wait "$ADAPTER_SOURCE_PID" 2>/dev/null || true
		ADAPTER_SOURCE_PID=''
	fi
}
journey_at_cleanup stop_adapter_source

start_evidence_source() {
	local project=$1 port
	port=$(python3 - <<'PYPORT'
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PYPORT
)
	perl -pi -e "s@http://127[.]0[.]0[.]1:8081@http://127.0.0.1:$port@" "$project/local-target.yaml"
	python3 "$JOURNEY_ROOT/products/evidence/examples/standalone/serve-source.py" --port "$port" &
	EVIDENCE_SOURCE_PID=$!
	journey_poll 10 -- evidence_source_ready "$port"
}

evidence_source_ready() {
	local port=$1
	(: >"/dev/tcp/127.0.0.1/$port") 2>/dev/null
}

stop_evidence_source() {
	if [[ -n "${EVIDENCE_SOURCE_PID:-}" ]]; then
		kill "$EVIDENCE_SOURCE_PID" 2>/dev/null || true
		wait "$EVIDENCE_SOURCE_PID" 2>/dev/null || true
		EVIDENCE_SOURCE_PID=''
	fi
}
journey_at_cleanup stop_evidence_source

check_restart_readiness() {
	local project=$1 product=$2 person=$3 path=$4
	perl -pi -e 's@^scenarioFile:.*@scenarioFile: journey-restart.yaml@' "$project/dev.yaml"
	journey_write_file "$project/journey-restart.yaml" <<SCENARIOS
apiVersion: id.registrystack.org/formats/rstack/scenarios/v1alpha1
kind: RStackScenarios
scenarios:
  - id: ready-after-restart
    steps:
      - {id: ready, product: $product, as: $person, method: GET, path: "$path", expect: {status: 200}}
SCENARIOS
}

# write_keep PRODUCT WORK PROJECT URL RUN: write data using the starter's
# contract and set the path and expected value for the read after restart.
write_keep() {
	local product=$1 work=$2 project=$3 url=$4 run=$5
	local method=POST path='' body='' field='' send_after
	local -a options=(--bearer token --header 'Content-Type: application/json' --header 'Idempotency-Key: journey-keep')
	KEEP_PERSON=$PERSON
	KEEP_EXPECT=''
	case "$product" in
	breg)
		path=/v1/records/contacts
		body='{"data":{"name":"A retained contact","email":"retained@example.test","jurisdiction":"zone-a"}}'
		field='.data.recordIdentifier'
		;;
	casework)
		KEEP_PERSON=requester
		# shellcheck disable=SC2034 # issue_token sets it by name
		local requestertoken=''
		issue_token keep "$run" "$KEEP_PERSON" requestertoken
		options=(--bearer requestertoken "${options[@]:2}" --header 'Registry-Casework-Profile: requester' --header 'Registry-Review-Profile: requester')
		path=/v1/review-requests
		body='{"policy":{"id":"decision"},"subject":{"source":"standalone","type":"batch","id":"synthetic-batch-0043","version":"1","digest":"sha256:54cb59dbbbc61ee50ade6b89a3e961156b6a2ff1a584b485ede786b1becfc7c3"},"requesterReference":"synthetic-batch-0043","context":{"mode":"submitted","snapshot":{"summary":"Confirm the prepared synthetic batch","reference":"synthetic-batch-0042"}}}'
		field='.requestId'
		;;
	messaging)
		KEEP_PATH=/v1/messages/$message_id
		KEEP_EXPECT=$message_id
		return
		;;
	scheduling)
		local config
		config=$(jq -er '.runtimeConfigs.scheduling' "$START_FILE")
		awk '{print} /^locations:$/ {print "  - id: retained-counter"; print "    timezone: UTC"}' "$project/records.yaml" >"$work/keep-records.yaml"
		journey_step keep -- "$JOURNEY_BIN_DIR/schedulingctl" records apply --runtime-config "$config" --posture development "$work/keep-records.yaml"
		KEEP_PATH=/v1/locations
		KEEP_EXPECT=retained-counter
		return
		;;
	documents)
		path=/v1/documents
		body='{"policyId":"institutional-custody","expectedDigest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","length":1,"mediaType":"application/pdf","label":"Retained document","custodian":{"subject":"starter-citizen"}}'
		field='.document.id'
		;;
	coordinator)
		path=/v1/runs
		send_after=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(days=1)).isoformat(timespec="seconds"))')
		body=$(jq -nc --arg revision "$workflow_revision" --arg due "$send_after" '{workflow:"delayed-follow-up",workflowRevision:$revision,input:{applicationId:"12345678-1234-4234-8234-123456789abc",sendAfter:$due}}')
		field='.runId'
		;;
	adapter)
		path=/v1/records/person
		body='{"data":{"recordIdentifier":"person-17","domainData":{"name":"Example Person"}}}'
		field='.data.name'
		;;

	esac
	local saved_id
	printf '%s\n' "$body" | journey_write_file "$work/keep-body.json"
	local step=keep
	[[ "$product" != breg ]] || step=hook
	journey_http "$step" "${options[@]}" --data-file "$work/keep-body.json" --capture "$field" saved_id "$method" "$url$path" || unexpected_answer "$step"
	case "$product" in
		breg|documents|coordinator) KEEP_PATH=$path/$saved_id ;;
		casework) KEEP_PATH=$path/$saved_id ;;
		adapter) KEEP_PATH=$path ;;
	esac
	KEEP_EXPECT=$saved_id
}

# start_run STEP PROJECT: `rstack dev start` on PROJECT as part of STEP. Sets
# RUN, BASE_URL and START_FILE (the report) on success. Returns the command's
# status; the caller records the outcome.
start_run() {
	local step=$1 project=$2 status=0
	journey_step "$step" --timeout 240 --concepts run-id-and-ttl,scenario-file \
		--typed "rstack dev start $project" -- rstack_dev start "$project" || status=$?
	START_FILE=$JOURNEY_STEP_STDOUT
	if [[ $status -eq 0 ]]; then
		RUN=$(jq -er '.run_id' "$START_FILE") || journey_harness_failure "the start report of $CELL names no run id; see $START_FILE"
		LIVE_RUNS+="$RUN"$'\n'
	fi
	return "$status"
}

# run_url PRODUCT: the address the start report gives for PRODUCT.
run_url() {
	jq -er --arg product "$1" '.products[$product]' "$START_FILE" ||
		journey_harness_failure "the start report names no address for $1; see $START_FILE"
}

# issue_token STEP RUN PERSON VAR: `rstack dev token` as part of STEP, then the
# bearer token its header file holds into the shell variable VAR. The token is
# registered as a secret and is never written to a saved file.
issue_token() {
	local step=$1 run=$2 person=$3 variable=$4 status=0 header_file line
	journey_step "$step" --concepts test-person,header-file,short-lived-token \
		--typed "rstack dev token $run --as $person" -- rstack_dev token "$run" --as "$person" || status=$?
	[[ $status -eq 0 ]] || return "$status"
	header_file=$(jq -er '.credentials[0].header_file' "$JOURNEY_STEP_STDOUT") ||
		journey_harness_failure "the token report names no header file; see $JOURNEY_STEP_STDOUT"
	IFS= read -r line <"$header_file" || journey_harness_failure "cannot read the header file of the token for $person"
	[[ "$line" == "Authorization: Bearer "* ]] || journey_harness_failure "the header file of the token for $person is not an Authorization header"
	printf -v "$variable" '%s' "${line#Authorization: Bearer }"
	journey_secret_register "token-$variable" "$variable"
}

# unexpected_answer STEP: the call answered with a status this journey has no
# code for. It is a harness failure so that a new kind of refusal is looked at
# and named, never recorded under a code the product did not print.
unexpected_answer() {
	journey_harness_failure "step $1 of $CELL answered HTTP $JOURNEY_HTTP_STATUS (problem code '${JOURNEY_HTTP_PROBLEM_CODE:-none}'); name the stage word for the operator log's failed_check and extend rstack-dev.sh"
}

# walk_product PRODUCT: walk one product through the steps.
walk_product() {
	# shellcheck disable=SC2034 # token and token2 are set by name through issue_token
	local product=$1 work project tier plan_capable status=0 url message_id='' token='' token2='' workflow_revision='' uses_postgres
	journey_product_field "$product" tier tier
	journey_product_field "$product" rstackDevPlan plan_capable
	journey_product_field "$product" usesPostgres uses_postgres
	CELL=$product
	journey_cell_begin "$product"
	if [[ "$tier" == supporting ]]; then
		journey_unreached init "Supporting runtime. It has no rstack dev plan type and starts beside its parent."
		journey_cell_end
		return 0
	fi
	journey_workdir "$product" work
	project=$work/project

	# init: the product's own init.
	init_command "$product" "$project"
	journey_step init --concepts project -- "${INIT_COMMAND[@]}" || status=$?
	if [[ $status -ne 0 ]]; then
		fail_with_product_code init "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"
		journey_cell_end
		return 0
	fi
	journey_pass init

	# plan: `rstack dev check` on the project init wrote. A product that init
	# gave no plan for, and that the plan format cannot name, is given the plan
	# a reader would write first.
	if [[ ! -f "$project/dev.yaml" && "$plan_capable" != true ]]; then
		write_probe_plan "$product" "$project"
	fi
	journey_step plan --concepts development-plan --typed "rstack dev check $project" -- rstack_dev check "$project" || status=$?
	if [[ $status -ne 0 ]]; then
		if [[ ! -f "$project/dev.yaml" ]]; then
			journey_needs plan hand-written-plan
		else
			fail_with_product_code plan "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"
		fi
		journey_cell_end
		return 0
	fi
	journey_pass plan

	# start: one command, after supplying the optional fixture endpoints.
	case "$product" in
		breg) add_contact_hook "$project" ;;
		casework)
			# Use the generated test person's issuer for the starter's
			# trusted producer on this disposable project.
			perl -pi -e 's@^    issuer: http://127[.]0[.]0[.]1:8093$@    issuer: https://identity.casework.example.test@' "$project/casework.yaml"
			;;
		adapter) start_adapter_source "$project" "$work" ;;
		evidence) start_evidence_source "$project" ;;
	esac
	start_run start "$project" || status=$?
	if [[ $status -ne 0 ]]; then
		fail_with_product_code start "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"
		stop_live_runs
		journey_cell_end
		return 0
	fi
	if ! jq -e 'all(.scenarios[]; .result == "passed")' "$START_FILE" >/dev/null; then
		journey_harness_failure "the start report of $product holds a scenario that did not pass; see $START_FILE"
	fi
	journey_pass start
	local run=$RUN
	url=$(run_url "$product")
	recipe "$product"

	# issuer: the issuer the run gave the product, read from the runtime file
	# the report names.
	local runtime_file
	runtime_file=$(jq -er --arg product "$product" '.runtimeConfigs[$product]' "$START_FILE") ||
		journey_harness_failure "the start report names no runtime file for $product"
	if [[ "$product" == evidence ]]; then
		journey_step issuer --concepts issuer-url,jwks-uri,audience,allowed-clients,scope-claim -- \
			"$JOURNEY_BIN_DIR/evidence" check --posture development --runtime-config "$runtime_file" --format json
	elif [[ "$product" == discovery ]]; then
		printf '%s\n' "Discovery's public index has no issuer."
	else
		journey_step issuer --concepts issuer-url,jwks-uri,audience,allowed-clients,scope-claim \
			--typed "jq read issuer settings $runtime_file" -- \
			jq '(.authentication.oidc // .deployment.authentication.oidc // .oidc // {}) | {issuer, audience, allowedClients, scopeClaim, jwksSource: .jwksSource.type}' "$runtime_file" ||
			journey_harness_failure "cannot read the issuer of $product from $runtime_file"
	fi
	journey_pass issuer

	# token: a token for the recipe's person.
	if [[ -n "$PERSON" ]]; then
		issue_token token "$run" "$PERSON" token || status=$?
	else
		printf '%s\n' "Discovery's public read uses no token."
	fi
	if [[ $status -ne 0 ]]; then
		fail_with_product_code token "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"
		stop_live_runs
		journey_cell_end
		return 0
	fi
	journey_pass token

	# call: the first authenticated request.
	local -a call_options=()
	[[ -z "$PERSON" ]] || call_options+=(--bearer token)
	case "$product" in
		coordinator) call_options+=(--capture '.workflowRevision' workflow_revision) ;;
		casework) call_options+=(--header 'Registry-Casework-Profile: staff') ;;
	esac
	if [[ -n "$CALL_BODY" ]]; then
		printf '%s\n' "$CALL_BODY" | journey_write_file "$work/call-body.json"
		call_options+=(--header 'Content-Type: application/json' --header 'Idempotency-Key: journey-first-call' --data-file "$work/call-body.json" --capture '.id' message_id)
	fi
	journey_http call "${call_options[@]}" "$CALL_METHOD" "$url$CALL_PATH" || status=$?
	if [[ $status -ne 0 ]]; then
		unexpected_answer call
	fi
	journey_pass call

	# hook: BReg's keep write also triggers its local sink.
	if [[ "$product" == breg ]]; then
		local sink
		write_keep "$product" "$work" "$project" "$url" "$run"
		sink=$(jq -er '.bregHookSink.receivedUrl' "$START_FILE")
		journey_poll 30 -- hook_received "$sink" "A retained contact"
		journey_http hook GET "$sink" || unexpected_answer hook
	fi
	journey_pass hook

	if [[ "$uses_postgres" == true ]]; then
		if [[ "$product" != breg ]]; then
			write_keep "$product" "$work" "$project" "$url" "$run"
		fi
		local audit=''
		case "$product" in
			breg) audit=$(jq -er '.audit.path' "$runtime_file") ;;
			scheduling)
				audit=$(jq -er '.audit.path' "$runtime_file")
				audit=${audit%.jsonl}.schedulingctl.jsonl
				;;
		esac
		journey_step keep --typed "rstack dev stop $run" -- rstack_dev stop "$run"
		LIVE_RUNS=$(printf '%s' "$LIVE_RUNS" | grep -vx -- "$run" || true)
		journey_poll 30 -- state_is_empty || journey_harness_failure "the state of run $run did not go after its stop"
		if [[ -n "$audit" ]]; then
			cp -- "$audit" "$work/audit-before-restart.jsonl"
			edit_for_restart "$product" "$project"
		fi
		# The authored startup scenario has already passed. Keep tests issue
		# their own calls against the same data and refresh their credentials.
		local restart_path=$CALL_PATH restart_person=$PERSON
		if [[ "$product" == messaging ]]; then
			restart_path=$KEEP_PATH
		fi
		check_restart_readiness "$project" "$product" "$restart_person" "$restart_path"
		if [[ "$product" == adapter ]]; then
			stop_adapter_source
		fi
		start_run keep "$project" || journey_harness_failure "the project did not start a second time; see $JOURNEY_STEP_STDERR"
		issue_token keep "$RUN" "$KEEP_PERSON" token2
		local -a keep_options=(--bearer token2)
		local method=GET
		if [[ "$product" == casework ]]; then
			keep_options+=(--header 'Registry-Casework-Profile: requester' --header 'Registry-Review-Profile: requester')
		fi
		if [[ "$product" == adapter ]]; then
			# The sole write route returns its retained response for the
			# same request and key even with the upstream offline.
			method=POST
			keep_options+=(--header 'Content-Type: application/json' --header 'Idempotency-Key: journey-keep' --data-file "$work/keep-body.json")
		fi
		status=0
		journey_http keep "${keep_options[@]}" "$method" "$(run_url "$product")$KEEP_PATH" || status=$?
		if [[ $status -ne 0 ]]; then
			if [[ "$JOURNEY_HTTP_STATUS" == 404 ]]; then
				journey_fail keep journey.keep.state-lost
				stop_live_runs
				journey_cell_end
				return 0
			fi
			unexpected_answer keep
		fi
		jq -e --arg expected "$KEEP_EXPECT" '[.. | strings] | index($expected) != null' "$JOURNEY_STEP_STDOUT" >/dev/null ||
			journey_harness_failure "the retained $product response did not contain the written record"
		if [[ -n "$audit" ]]; then
			journey_step keep -- audit_was_appended "$work/audit-before-restart.jsonl" "$audit"
		fi
	else
		printf '%s\n' "$product has no PostgreSQL state to retain."
	fi
	journey_pass keep

	# attach: only products with a database accept a PostgreSQL server.
	if [[ "$uses_postgres" == true ]]; then
		attach_database "$project" || status=$?
		if [[ $status -ne 0 ]]; then
			stop_live_runs
			journey_cell_end
			return 0
		fi
	else
		printf '%s\n' "$product does not use an attached PostgreSQL server."
		journey_pass attach
	fi

	# stop: rstack's own stop, then nothing left of the run.
	local last=$RUN
	journey_step stop --typed "rstack dev stop $last" -- rstack_dev stop "$last" ||
		journey_harness_failure "rstack dev stop $last failed; see $JOURNEY_STEP_STDERR"
	LIVE_RUNS=$(printf '%s' "$LIVE_RUNS" | grep -vx -- "$last" || true)
	journey_poll 30 -- state_is_empty || journey_harness_failure "the state of run $last did not go after its stop"
	journey_check_absent "$(run_containers "$last" | head -n 1)" "$(run_containers "$last" | tail -n 1)" ||
		journey_harness_failure "a container of run $last remains after its stop"
	journey_pass stop
	[[ "$product" != evidence ]] || stop_evidence_source
	journey_cell_end
}

edit_for_restart() {
	local product=$1 project=$2
	case "$product" in
	breg)
		python3 - "$project/registry.yaml" <<'PYEDIT'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
marker = "\nactions:\n"
assert source.count(marker) == 1
record = """
  directory-note:
    route: directory-notes
    primaryDataset: directory
    mutationMode: mutable
    fields:
      - {id: name, type: string, maximumLength: 160, classification: internal}
"""
path.write_text(source.replace(marker, record + marker))
PYEDIT
		;;
	scheduling)
		perl -pi -e 's/^  version: "1"$/  version: "2"/' "$project/scheduling.yaml"
		;;
	esac
}

audit_was_appended() {
	python3 - "$1" "$2" <<'PYAUDIT'
import json
from pathlib import Path
import sys

before, after = (Path(path).read_bytes() for path in sys.argv[1:])
assert before and after.startswith(before) and before != after
assert all(json.loads(line)["eventId"] for line in after[len(before):].splitlines())
PYAUDIT
}

hook_received() {
	curl --silent --fail --max-time 3 "$1" | jq -e --arg name "$2" 'any(.[] | .body | fromjson? | .. | strings; . == $name)' >/dev/null
}

# attach_database PROJECT: start PROJECT against a PostgreSQL server the reader
# runs: a stock container with no certificate. `rstack dev` accepts only a TLS
# server, so a reader with a plain one has no way forward that the journeys
# allow. The password reaches the child process through the environment, never
# an argument. The run that was live when this step began is stopped first.
# Records the outcome of step attach; returns 1 when the cell stopped.
attach_database() {
	local project=$1 port password_file password status=0
	local role=owned-database-$CELL password_label=attach-database-password-$CELL
	stop_live_runs || journey_harness_failure "cannot stop the run before attach"
	journey_secret_new "$password_label" 24
	journey_secret_path "$password_label" password_file
	IFS= read -r password <"$password_file"
	journey_container_run "$role" --port 5432 --secret-env "POSTGRES_PASSWORD=$password_label" -- \
		postgres:18.7@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc
	journey_container_port "$role" 5432 port
	# shellcheck disable=SC2016 # the probe expands its own argument
	journey_container_wait "$role" 60 -- bash -c ': </dev/tcp/127.0.0.1/"$1"' _ "$port"
	attach_start() {
		RSTACK_DEV_DATABASE_URL="postgresql://postgres:$password@127.0.0.1:$port/postgres" rstack_dev start "$project"
	}
	journey_step attach --timeout 240 --concepts database-url,database-tls \
		--typed "RSTACK_DEV_DATABASE_URL=postgresql://postgres:...@127.0.0.1:$port/postgres rstack dev start $project" -- attach_start || status=$?
	if [[ $status -eq 0 ]]; then
		RUN=$(jq -er '.run_id' "$JOURNEY_STEP_STDOUT") || journey_harness_failure "the attach start report names no run id"
		LIVE_RUNS+="$RUN"$'\n'
		journey_pass attach
		return 0
	fi
	if grep -qi 'tls\|certificate' "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"; then
		journey_needs attach certificate
		return 1
	fi
	fail_with_product_code attach "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"
	return 1
}

for product in "${JOURNEY_PRODUCTS[@]}"; do
	walk_product "$product"
done

journey_finish
