#!/usr/bin/env bash
# Self-test of lib.sh, the shared helpers of the acceptance journeys. Fake
# docker, curl, cargo and uname commands stand in for the real ones, so the
# test starts no container, builds nothing and reaches no network.
#
#   bash products/platform/journeys/test_lib.sh
#
# The file plays three parts. Run plainly, it is the test: each case starts
# this file again as a journey script (--driver) in its own bash process and
# checks the exit status, what the run saved and what the fakes were asked to
# do. Started through the wrappers the test writes on PATH (--fake NAME), it
# is a fake command. Everything the fakes record stays in the test's scratch
# directory, which is deleted at the end.
#
# JOURNEY_LIB_UNDER_TEST names another copy of lib.sh to test. The copy needs
# the four tables beside it and scripts/cargo-runtime-library-path.sh with
# scripts/cargo_runtime_library_path.py three folders up, as in the
# repository. TEST_LIB_KEEP=1 keeps the scratch directory.
set -euo pipefail

self="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/${BASH_SOURCE[0]##*/}"
test_image='registry.test/fake/postgres:17@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
nl=$'\n'
alpha=''

# ---------------------------------------------------------------------------
# Shared by every part

mode_of() {
	perl -e 'printf "%o\n", (stat $ARGV[0])[2] & 07777' "$1"
}

random_hex() {
	od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'
}

# ---------------------------------------------------------------------------
# The fakes. Each appends its arguments, one invocation per line, to
# $FAKE_STATE/<name>.argv and answers from the marker files a case leaves in
# $FAKE_STATE.

fake_record() {
	local name=$1
	shift
	printf '%s\n' "$*" >>"$FAKE_STATE/$name.argv"
}

# docker: version, inspect, run, port, rm and logs; any other verb fails.
# Markers: daemon-down, inspect-fails, every-name-exists, stopped, fail-start,
# fail-after-create, hang-before-cidfile (the container exists, the cidfile
# is not yet written), hang-after-create, rm-fails. It keeps containers/<name>,
# publish (one --publish value per line) and env-file.<name> (a copy of the
# --env-file it was given).
fake_docker() {
	local verb=${1:-} name='' cidfile='' env_file='' image='' format='' port line host
	fake_record docker "$@"
	[[ $# -eq 0 ]] || shift
	case "$verb" in
	version)
		if [[ -e "$FAKE_STATE/daemon-down" ]]; then
			printf 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n' >&2
			return 1
		fi
		printf '27.0.0\n'
		;;
	inspect)
		while [[ $# -gt 1 ]]; do
			case "$1" in
			--type) shift 2 ;;
			--format)
				format=$2
				shift 2
				;;
			*) shift ;;
			esac
		done
		name=${1:-}
		if [[ -e "$FAKE_STATE/inspect-fails" ]]; then
			printf 'Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n' >&2
			return 1
		fi
		if [[ ! -e "$FAKE_STATE/containers/$name" && ! -e "$FAKE_STATE/every-name-exists" ]]; then
			printf 'Error: No such object: %s\n' "$name" >&2
			return 1
		fi
		case "$format" in
		'{{.State.Running}}')
			if [[ -e "$FAKE_STATE/stopped" ]]; then printf 'false\n'; else printf 'true\n'; fi
			;;
		'{{.NetworkSettings.IPAddress}}') printf '172.17.0.9\n' ;;
		*) printf '[{"Name": "/%s"}]\n' "$name" ;;
		esac
		;;
	run)
		while [[ $# -gt 0 ]]; do
			case "$1" in
			--name)
				name=$2
				shift 2
				;;
			--cidfile)
				cidfile=$2
				shift 2
				;;
			--env-file)
				env_file=$2
				shift 2
				;;
			--publish)
				printf '%s\n' "$2" >>"$FAKE_STATE/publish"
				shift 2
				;;
			--label | --pull | -e | --env | -v | --volume | --user | --tmpfs) shift 2 ;;
			--detach) shift ;;
			-*)
				printf 'fake docker: run option %s is not known to the fake\n' "$1" >&2
				return 125
				;;
			*)
				image=$1
				break
				;;
			esac
		done
		if [[ -z "$name" || -z "$cidfile" || -z "$image" ]]; then
			printf 'fake docker: run needs --name, --cidfile and an image\n' >&2
			return 125
		fi
		if [[ -e "$FAKE_STATE/containers/$name" ]]; then
			printf 'docker: Error response from daemon: Conflict. The container name "/%s" is already in use.\n' "$name" >&2
			return 125
		fi
		if [[ -e "$FAKE_STATE/fail-start" ]]; then
			printf 'docker: Error response from daemon: fake start failure.\n' >&2
			return 125
		fi
		printf '%s\n' "$image" >"$FAKE_STATE/containers/$name"
		if [[ -n "$env_file" ]]; then
			cp -- "$env_file" "$FAKE_STATE/env-file.$name"
		fi
		if [[ -e "$FAKE_STATE/hang-before-cidfile" ]]; then
			exec sleep 30
		fi
		printf 'f00d%060d\n' 0 >"$cidfile"
		if [[ -e "$FAKE_STATE/fail-after-create" ]]; then
			printf 'docker: Error response from daemon: fake failure after create.\n' >&2
			return 125
		fi
		if [[ -e "$FAKE_STATE/hang-after-create" ]]; then
			exec sleep 30
		fi
		cat -- "$cidfile"
		;;
	port)
		name=${1:-}
		port=${2:-}
		port=${port%/tcp}
		if [[ ! -e "$FAKE_STATE/containers/$name" ]]; then
			printf 'Error: No such container: %s\n' "$name" >&2
			return 1
		fi
		if [[ -f "$FAKE_STATE/publish" ]]; then
			while IFS= read -r line; do
				if [[ "$line" == 127.0.0.1:*:"$port" ]]; then
					host=${line#127.0.0.1:}
					host=${host%%:*}
					printf '127.0.0.1:%s\n' "${host:-49153}"
					return 0
				fi
			done <"$FAKE_STATE/publish"
		fi
		printf 'Error: No public port %s/tcp published for %s\n' "$port" "$name" >&2
		return 1
		;;
	rm)
		if [[ "${1:-}" != --force || "${2:-}" != --volumes || $# -ne 3 ]]; then
			printf 'fake docker: rm expects --force --volumes NAME\n' >&2
			return 1
		fi
		if [[ -e "$FAKE_STATE/rm-fails" ]]; then
			printf 'Error response from daemon: fake removal failure\n' >&2
			return 1
		fi
		if [[ -e "$FAKE_STATE/containers/$3" ]]; then
			rm -- "$FAKE_STATE/containers/$3"
		fi
		printf '%s\n' "$3"
		;;
	logs)
		printf 'fake log of %s\n' "${1:-}"
		;;
	*)
		printf 'fake docker: the journeys never call docker %s\n' "$verb" >&2
		return 1
		;;
	esac
}

# curl: answers its Nth call with http-status.N and http-body.N (default 200
# and {"ok": true}). It keeps curl.headers (the headers -H @FILE read),
# curl.form (each --data-urlencode value, with NAME@FILE read from the file)
# and curl.urls. Marker: curl-fails.
fake_curl() {
	local headers_file='' body_file='' write_out='' value status=200 body='{"ok": true}' count=0
	fake_record curl "$@"
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--dump-header)
			headers_file=$2
			shift 2
			;;
		--output)
			body_file=$2
			shift 2
			;;
		--write-out)
			write_out=$2
			shift 2
			;;
		-H)
			if [[ "$2" == @* ]]; then
				cat -- "${2#@}" >>"$FAKE_STATE/curl.headers"
			else
				printf '%s\n' "$2" >>"$FAKE_STATE/curl.headers"
			fi
			shift 2
			;;
		--data-urlencode)
			if [[ "$2" == *@* && "${2%%@*}" != *=* ]]; then
				value="$(<"${2#*@}")"
				printf '%s=%s\n' "${2%%@*}" "$value" >>"$FAKE_STATE/curl.form"
			else
				printf '%s\n' "$2" >>"$FAKE_STATE/curl.form"
			fi
			shift 2
			;;
		--max-time | --connect-timeout | -X | --cookie | --cookie-jar | --data-binary) shift 2 ;;
		--silent | --show-error | --location) shift ;;
		-*)
			printf 'fake curl: option %s is not known to the fake\n' "$1" >&2
			return 2
			;;
		*)
			printf '%s\n' "$1" >>"$FAKE_STATE/curl.urls"
			shift
			;;
		esac
	done
	if [[ -e "$FAKE_STATE/curl-fails" ]]; then
		printf 'curl: (7) Failed to connect to 127.0.0.1 port 38099: Connection refused\n' >&2
		printf '000'
		return 7
	fi
	if [[ -f "$FAKE_STATE/curl.count" ]]; then
		count="$(<"$FAKE_STATE/curl.count")"
	fi
	count=$((count + 1))
	printf '%s\n' "$count" >"$FAKE_STATE/curl.count"
	if [[ -f "$FAKE_STATE/http-status.$count" ]]; then
		status="$(<"$FAKE_STATE/http-status.$count")"
	fi
	if [[ -f "$FAKE_STATE/http-body.$count" ]]; then
		body="$(<"$FAKE_STATE/http-body.$count")"
	fi
	if [[ -n "$headers_file" ]]; then
		printf 'HTTP/1.1 %s Fake\r\ncontent-type: application/json\r\n\r\n' "$status" >"$headers_file"
	fi
	if [[ -n "$body_file" ]]; then
		printf '%s\n' "$body" >"$body_file"
	fi
	if [[ "$write_out" == '%{http_code}' ]]; then
		printf '%s' "$status"
	fi
}

# cargo: records its arguments and CARGO_TARGET_DIR (cargo.target). Asked for
# JSON messages, it prints the build-script message of aws-lc-fips-sys with
# out_dir $FAKE_STATE/fips-out. Marker: cargo-fails.
fake_cargo() {
	local argument json=0
	fake_record cargo "$@"
	printf '%s\n' "${CARGO_TARGET_DIR:-unset}" >>"$FAKE_STATE/cargo.target"
	if [[ -e "$FAKE_STATE/cargo-fails" ]]; then
		printf 'error: could not compile registry-alpha (fake)\n' >&2
		return 101
	fi
	for argument in "$@"; do
		if [[ "$argument" == --message-format=json-render-diagnostics ]]; then
			json=1
		fi
	done
	if [[ $json -eq 1 ]]; then
		printf '{"reason":"build-script-executed","package_id":"registry+https://github.com/rust-lang/crates.io-index#aws-lc-fips-sys@0.13.7","linked_libs":["dylib=aws_lc_fips_0_13_7_crypto"],"linked_paths":[],"cfgs":[],"env":[],"out_dir":"%s"}\n' "$FAKE_STATE/fips-out"
		printf '{"reason":"build-finished","success":true}\n'
	fi
}

fake_uname() {
	case "${1:-}" in
	-s) printf '%s\n' "${FAKE_UNAME_S:?}" ;;
	-m) printf 'arm64\n' ;;
	*)
		printf 'fake uname: only -s and -m are answered\n' >&2
		return 1
		;;
	esac
}

# The product binary alpha. The long-running commands write their pid to
# $FAKE_STATE/alpha.pid.
fake_alpha() {
	case "${1:-}" in
	ok) printf 'alpha: ready\n' ;;
	fail)
		printf 'alpha: product.config.unknown-field: remove the field color from alpha.yaml\n' >&2
		return 4
		;;
	print-env)
		printf 'carrier=%s\n' "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH-unset}"
		printf 'dyld=%s\n' "${DYLD_FALLBACK_LIBRARY_PATH-unset}"
		;;
	cat) cat -- "$2" ;;
	pwd-and-stdin)
		printf 'cwd=%s\n' "$(pwd -P)"
		printf 'stdin=%s\n' "$(cat)"
		;;
	sleep)
		printf '%s\n' "$$" >"$FAKE_STATE/alpha.pid"
		exec sleep "$2"
		;;
	stubborn)
		printf '%s\n' "$$" >"$FAKE_STATE/alpha.pid"
		trap '' TERM
		printf 'ignoring TERM\n'
		while :; do sleep 0.2; done
		;;
	serve)
		printf '%s\n' "$$" >"$FAKE_STATE/alpha.pid"
		trap 'printf "stopping\n"; exit 0' TERM
		printf 'serving\n'
		if [[ -n "${3:-}" ]]; then
			printf 'loaded key %s\n' "$(<"$3")" >&2
		fi
		: >"$2"
		while :; do sleep 0.2; done
		;;
	exit-now)
		printf 'alpha: product.start.refused: no runtime file\n' >&2
		return 5
		;;
	*)
		printf 'alpha: unknown command %s\n' "${1:-}" >&2
		return 64
		;;
	esac
}

fake_main() {
	local name=${1:-}
	[[ $# -eq 0 ]] || shift
	case "$name" in
	docker) fake_docker "$@" ;;
	curl) fake_curl "$@" ;;
	cargo) fake_cargo "$@" ;;
	uname) fake_uname "$@" ;;
	alpha) fake_alpha "$@" ;;
	*)
		printf 'test_lib: no fake named %s\n' "$name" >&2
		return 2
		;;
	esac
}

# ---------------------------------------------------------------------------
# The journey script each case runs (--driver). SCENARIO picks what it does.
# It appends KEY=VALUE lines to $REPORT, and every raw secret value it
# handles to $PATTERNS so the test can look for them in what the run saved.

report() {
	printf '%s=%s\n' "$1" "$2" >>"$REPORT"
}

remember() {
	printf '%s\n' "$1" >>"$PATTERNS"
}

driver_binaries() {
	if [[ -n "${DRIVER_DYLD:-}" ]]; then
		# Set here, not inherited: a protected launcher drops DYLD_* variables.
		export DYLD_FALLBACK_LIBRARY_PATH=$DRIVER_DYLD
	fi
	journey_resolve_binaries "${JOURNEY_PRODUCTS[@]}"
	report bin_dir "$JOURNEY_BIN_DIR"
	report carrier "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH-unset}"
	report dyld "${DYLD_FALLBACK_LIBRARY_PATH-unset}"
	journey_bin "${BIN_NAME:-alpha}" alpha
}

# The cell of PRODUCT as CELL_<product> describes it: pass, fail:STEP:CODE,
# needs:STEP:THING, poll:STEP (a journey_poll that runs out of time),
# unreached:STEP, blocker:STEP:CODE:ASSIST or harness:STEP. The default is the
# product's row in the synthetic table.
driver_cell() {
	local product=$1 plan_name plan kind stop code assist step
	plan_name="CELL_$product"
	plan=${!plan_name:-}
	if [[ -z "$plan" ]]; then
		case "$product" in
		beta) plan=fail:call:http.401.issuer ;;
		gamma) plan=unreached:prepare ;;
		delta) plan=fail:start:product.config.unknown-field ;;
		*) plan=pass ;;
		esac
	fi
	IFS=: read -r kind stop code assist <<<"$plan"
	journey_cell_begin "$product"
	for step in prepare start call stop; do
		if [[ "$step" == "${stop:-}" ]]; then
			case "$kind" in
			unreached)
				journey_unreached "$step" "runs beside its parent"
				break
				;;
			fail)
				if ! journey_step "$step" -- "$alpha" fail; then
					journey_fail "$step" "$code"
				fi
				break
				;;
			needs)
				journey_needs "$step" "$code"
				break
				;;
			poll)
				if ! journey_step "$step" -- journey_poll 2 -- false; then
					journey_fail "$step" product.poll.timed-out
				fi
				break
				;;
			blocker)
				if ! journey_step "$step" -- "$alpha" fail; then
					journey_blocker "$step" "$code" "$assist" "$JOURNEY_OUT/work" || break
				fi
				continue
				;;
			harness) journey_harness_failure "a harness failure the test asked for" ;;
			esac
		fi
		if [[ "$step" == prepare ]]; then
			journey_step prepare --concepts runtime-file -- "$alpha" "${PREPARE:-ok}"
		fi
		journey_pass "$step"
	done
	journey_cell_end
}

driver_all_cells() {
	local product
	for product in "${JOURNEY_PRODUCTS[@]}"; do
		driver_cell "$product"
	done
}

# A cleanup hook: records whether the container still existed when it ran
# (hooks run before containers are removed) and fails when HOOK=fail.
driver_cleanup_hook() {
	local name
	journey_container_name db name
	if [[ -e "$FAKE_STATE/containers/$name" ]]; then
		printf 'container-present\n' >>"$FAKE_STATE/hook-ran"
	else
		printf 'container-absent\n' >>"$FAKE_STATE/hook-ran"
	fi
	[[ "${HOOK:-ok}" != fail ]]
}

driver_containers() {
	local path port address
	local -a options=() ports=(--port 5432)
	journey_require_docker
	journey_at_cleanup driver_cleanup_hook
	journey_set_address_class bridge
	journey_secret_new db-password
	journey_secret_path db-password path
	remember "$(<"$path")"
	if [[ -n "${CONTAINER_OPTS:-}" ]]; then
		read -r -a options <<<"$CONTAINER_OPTS"
	fi
	if [[ -n "${EXTRA_PORT:-}" ]]; then
		ports+=(--port "$EXTRA_PORT")
	fi
	journey_container_run db "${ports[@]}" --secret-env POSTGRES_PASSWORD=db-password -e PLAIN=1 \
		${options[@]+"${options[@]}"} -- "${CONTAINER_IMAGE:-$test_image}"
	journey_container_port db 5432 port
	report port "$port"
	journey_container_address db address
	report address "$address"
	journey_container_wait db "${WAIT_SECONDS:-5}" -- "${WAIT_PROBE:-true}"
	journey_container_logs db
	if ! journey_check_absent stackrun-m0-libtest-foreign stackrun-m0-libtest-absent; then
		report leftover found
	fi
	driver_binaries
	if [[ "${START_SERVER:-0}" == 1 ]]; then
		journey_cell_begin alpha
		journey_pass prepare
		journey_start start server --settle 1 -- "$alpha" serve "$FAKE_STATE/ready"
		journey_pass start
		journey_pass call
		journey_pass stop
		journey_cell_end
	else
		driver_all_cells
	fi
}

driver_takeover() {
	local from
	journey_option_value from from
	journey_take_over_run "$from"
	driver_binaries
	journey_cell_begin alpha
	journey_step prepare -- "$alpha" cat "$from/secrets/db-password"
	journey_pass prepare
	journey_pass start
	journey_pass call
	journey_pass stop
	journey_cell_end
}

driver_secrets() {
	local path value env_path token variable input jwt_head='ey' jwt_payload jwt
	local pem_body basic cookie bearer url_password json_token json_password
	journey_secret_new api-key
	journey_secret_path api-key path
	value="$(<"$path")"
	remember "$value"
	report secret-mode "$(mode_of "$path")"
	report secret-length "${#value}"
	journey_secret_env_file app env_path API_KEY=api-key
	report env-mode "$(mode_of "$env_path")"
	if [[ "$(<"$env_path")" == "API_KEY=$value" ]]; then
		report env-file ok
	fi
	token="tok$(random_hex 12)"
	remember "$token"
	# Registered through a variable named like a local of journey_secret_register,
	# to show the value is read from the caller.
	# shellcheck disable=SC2034 # read by name
	variable=$token
	journey_secret_register access-token variable
	pem_body="$(random_hex 24)"
	jwt_payload="$(random_hex 12)"
	jwt="${jwt_head}J$(random_hex 8).$jwt_payload.$(random_hex 8)"
	basic="$(random_hex 12)"
	cookie="$(random_hex 12)"
	bearer="$(random_hex 12)"
	url_password="$(random_hex 12)"
	json_token="$(random_hex 12)"
	json_password="$(random_hex 12)"
	for value in "$pem_body" "$jwt_payload" "$basic" "$cookie" "$bearer" "$url_password" "$json_token" "$json_password"; do
		remember "$value"
	done
	journey__raw_path input redact-input
	{
		printf 'api key: %s\n' "$(<"$path")"
		printf 'token in text: %s\n' "$token"
		printf -- '-----BEGIN %s-----\n%s\n-----END %s-----\n' 'PRIVATE KEY' "$pem_body" 'PRIVATE KEY'
		printf 'jwt: %s\n' "$jwt"
		printf 'Authorization: Basic %s\n' "$basic"
		printf '> Cookie: session=%s\n' "$cookie"
		printf 'the server said Bearer %s\n' "$bearer"
		printf 'url: postgres://registry:%s@127.0.0.1:38010/registry\n' "$url_password"
		printf '{"access_token": "%s", "password": "%s", "note": "kept"}\n' "$json_token" "$json_password"
	} >"$input"
	journey_redact "$input" "$JOURNEY_OUT/redacted.txt"
	report redacted "$JOURNEY_OUT/redacted.txt"
	driver_binaries
	driver_all_cells
}

driver_leak() {
	local path jwt_head='ey'
	journey_secret_new api-key
	journey_secret_path api-key path
	remember "$(<"$path")"
	case "${LEAK:-secret}" in
	secret) cp -- "$path" "$JOURNEY_OUT/leak.txt" ;;
	jwt) printf '%sJ%s.%s.%s\n' "$jwt_head" "$(random_hex 8)" "$(random_hex 8)" "$(random_hex 8)" >"$JOURNEY_OUT/leak.txt" ;;
	esac
	driver_binaries
	driver_all_cells
}

driver_http() {
	local path step
	journey_secret_new client-secret
	journey_secret_path client-secret path
	remember "$(<"$path")"
	journey_cell_begin alpha
	journey_pass prepare
	journey_http start --form grant_type=client_credentials --form-secret client_secret=client-secret --cookie-jar session \
		--capture-secret .access_token step POST http://127.0.0.1:38001/token
	journey_pass start
	# The token is held in a variable named step, a word journey_http also uses,
	# to show the caller's variable is the one set and read.
	report token-length "${#step}"
	if ! journey_http call --bearer step --header 'Accept: application/json' GET http://127.0.0.1:38001/records; then
		report http-status "$JOURNEY_HTTP_STATUS"
		report problem-code "$JOURNEY_HTTP_PROBLEM_CODE"
		journey_fail call "http.$JOURNEY_HTTP_STATUS.issuer"
	fi
	journey_cell_end
}

# The options of journey_step and journey_http that the other scenarios leave
# out: --cwd, --stdin, --doc-words and --typed of a step, and --data-file and
# --location of a request that gets no answer.
driver_options() {
	local dir
	driver_binaries
	journey_cell_begin alpha
	journey_workdir alpha dir
	printf 'reader input\n' >"$dir/input.txt"
	journey_step prepare --cwd "$dir" --stdin "$dir/input.txt" --doc-words 40 --typed 'alpha check' -- "$alpha" pwd-and-stdin
	journey_pass prepare
	if ! journey_http start --data-file "$dir/input.txt" --location POST http://127.0.0.1:38001/upload; then
		report curl-status "$JOURNEY_HTTP_STATUS"
		journey_fail start product.http.no-answer
	fi
	journey_cell_end
}

# One way of breaking the rules a cell keeps; each is a journey script error.
driver_discipline() {
	driver_binaries
	case "${DISCIPLINE:?}" in
	pass-after-fail)
		journey_cell_begin alpha
		journey_step prepare -- "$alpha" fail || report prepare failed
		journey_pass prepare
		;;
	begin-twice)
		journey_cell_begin alpha
		journey_cell_begin alpha
		;;
	end-without-last)
		journey_cell_begin alpha
		journey_pass prepare
		journey_cell_end
		;;
	unknown-step)
		journey_cell_begin alpha
		journey_pass deploy
		;;
	unresolved)
		journey_cell_begin alpha
		journey_step prepare -- "$alpha" fail || report prepare failed
		journey_pass start
		;;
	unknown-concept)
		journey_cell_begin alpha
		journey_step prepare --concepts warp-drive -- "$alpha" ok
		;;
	unknown-suffix)
		journey_cell_begin alpha
		journey_fail prepare journey.needs.magic
		;;
	unknown-stage)
		journey_cell_begin alpha
		journey_fail call http.401.moon
		;;
	bad-code)
		journey_cell_begin alpha
		journey_fail call refused
		;;
	after-stop)
		journey_cell_begin alpha
		journey_fail prepare product.config.bad
		journey_pass start
		;;
	unknown-counter)
		journey_cell_begin alpha
		journey_count coffee-breaks
		;;
	library-name)
		journey_cell_begin alpha
		journey_workdir alpha _jr_target
		;;
	missing-cell) ;;
	esac
}

driver_ready_probe() {
	[[ -f "$FAKE_STATE/ready" ]]
}

driver_processes() {
	local path log
	journey_secret_new server-key
	journey_secret_path server-key path
	remember "$(<"$path")"
	driver_binaries
	journey_cell_begin alpha
	journey_pass prepare
	case "${PROCESS_MODE:-serve}" in
	serve)
		journey_start start server --settle 1 -- "$alpha" serve "$FAKE_STATE/ready" "$path"
		journey_pass start
		journey_ready call server --timeout 10 -- driver_ready_probe
		journey_pass call
		if journey_process_running server; then
			report running yes
		fi
		journey_process_log server log
		report log "$log"
		journey_stop stop server --timeout 5
		report stop-status "$JOURNEY_PROCESS_STATUS"
		journey_pass stop
		;;
	stubborn)
		journey_start start server --settle 1 -- "$alpha" stubborn
		journey_pass start
		journey_pass call
		if ! journey_stop stop server --timeout 1; then
			journey_fail stop product.stop.ignored-signal
		fi
		;;
	exit-now)
		if ! journey_start start server --settle 1 -- "$alpha" exit-now; then
			report start-status "$JOURNEY_PROCESS_STATUS"
			journey_fail start product.start.refused
		fi
		;;
	esac
	journey_cell_end
}

driver_files() {
	local dir
	journey_cell_begin alpha
	journey_workdir alpha dir
	journey_pass prepare
	case "${FILES_MODE:-count}" in
	count)
		journey_write_file "$dir/alpha.yaml" --concepts runtime-file < <(printf 'ab: 1\ncd: 2\nef: 3\n')
		journey_reached t1
		journey_edit_file "$dir/alpha.yaml" 'cd: 2' 'cd: 20' --concepts issuer
		;;
	outside)
		journey_write_file "$JOURNEY_OUT/alpha.yaml" </dev/null
		;;
	twice)
		journey_write_file "$dir/alpha.yaml" < <(printf 'x: 1\nx: 1\n')
		journey_edit_file "$dir/alpha.yaml" 'x: 1' 'x: 2'
		;;
	esac
	journey_pass start
	journey_pass call
	journey_pass stop
	journey_reached t2
	journey_count errors-that-say-what-to-change 2
	journey_count identity-provider-changes
	journey_cell_end
}

# Replay every row of the table for this journey: each cell passes the steps
# before its row's step and stops there with the row's outcome, so ratchet
# mode must find every cell equal to the table and every code accepted.
driver_replay() {
	local table steps row kind stop code product step
	# lib.sh's own reader, so the replay reads the table exactly as the run did.
	journey__yaml_json "$JOURNEY_EXPECTED_FILE" table
	steps="$(jq -r --arg j "$JOURNEY_NAME" '.journeys[$j].steps[]' <<<"$table")"
	for product in "${JOURNEY_PRODUCTS[@]}"; do
		row="$(jq -r --arg j "$JOURNEY_NAME" --arg p "$product" '
			[(.expectedFailures // [])[] | select(.journey == $j and .product == $p) | ["fail", .step, .code]]
			+ [(.unreached // [])[] | select(.journey == $j and .product == $p) | ["unreached", .step, "-"]]
			+ [(.passes // [])[] | select(.journey == $j and .product == $p) | ["pass", "-", "-"]]
			| if length == 1 then .[0] | @tsv else error("\($p) has \(length) rows for \($j)") end' <<<"$table")"
		IFS=$'\t' read -r kind stop code <<<"$row"
		journey_cell_begin "$product"
		while IFS= read -r step; do
			if [[ "$step" == "$stop" ]]; then
				case "$kind" in
				fail) journey_fail "$step" "$code" ;;
				unreached) journey_unreached "$step" "replayed from the table" ;;
				esac
				break
			fi
			journey_pass "$step"
		done <<<"$steps"
		journey_cell_end
	done
	report replayed "${#JOURNEY_PRODUCTS[@]}"
}

driver_main() {
	local short_value
	journey_init "${TEST_JOURNEY:-sample}" --value-option from -- "$@"
	report out "$JOURNEY_OUT"
	report run "$JOURNEY_RUN_ID"
	case "${SCENARIO:-cells}" in
	cells)
		driver_binaries
		driver_all_cells
		;;
	containers) driver_containers ;;
	takeover) driver_takeover ;;
	error)
		journey_require_docker
		journey_container_run db --port 5432 -- "$test_image"
		false
		;;
	interrupt)
		journey_require_docker
		journey_secret_new db-password
		journey_container_run db --port 5432 --secret-env POSTGRES_PASSWORD=db-password -- "$test_image"
		driver_binaries
		journey_cell_begin alpha
		journey_step prepare -- "$alpha" sleep 30
		report after-step reached
		;;
	secrets) driver_secrets ;;
	secret-short) journey_secret_new short 8 ;;
	register-short)
		# shellcheck disable=SC2034 # read by name by journey_secret_register
		short_value=abc1234
		journey_secret_register short short_value
		;;
	leak) driver_leak ;;
	http) driver_http ;;
	options) driver_options ;;
	http-header)
		journey_cell_begin alpha
		journey_http call --header 'Authorization: Bearer not-a-real-token' GET http://127.0.0.1:38001/records
		;;
	discipline) driver_discipline ;;
	timeout)
		driver_binaries
		journey_cell_begin alpha
		journey_step prepare --timeout 1 -- "$alpha" "${TIMEOUT_MODE:-sleep}" 30
		;;
	processes) driver_processes ;;
	files) driver_files ;;
	replay) driver_replay ;;
	*) journey_harness_failure "the test asked for an unknown scenario ${SCENARIO:-}" ;;
	esac
	journey_finish
}

# ---------------------------------------------------------------------------
# The test

checks=0
failed_checks=0
case_name=''
case_failed=0
drive_count=0
add_out=1
launched=''

problem() {
	printf 'FAIL %s: %s%s\n' "$case_name" "$1" "${2:+ ($2)}"
	case_failed=1
	failed_checks=$((failed_checks + 1))
}

finish_case() {
	if [[ -n "$case_name" && $case_failed -eq 0 ]]; then
		printf 'ok   %s\n' "$case_name"
	fi
	case_name=''
}

begin_case() {
	finish_case
	case_name=$1
	case_failed=0
	drive_count=0
	add_out=1
	state="$work/state/$1"
	patterns="$work/patterns/$1"
	mkdir -p "$state/containers"
	: >"$patterns"
}

# check DESCRIPTION COMMAND...: COMMAND must succeed.
check() {
	local description=$1
	shift
	checks=$((checks + 1))
	if ! "$@"; then
		problem "$description"
	fi
}

check_equal() {
	checks=$((checks + 1))
	if [[ "$2" != "$3" ]]; then
		problem "$1" "expected '$2', got '$3'"
	fi
}

has() {
	[[ -f "$2" ]] && grep -qF -- "$1" "$2"
}

lacks() {
	[[ ! -f "$2" ]] || ! grep -qF -- "$1" "$2"
}

no_file() {
	[[ ! -e "$1" && ! -L "$1" ]]
}

contents() {
	if [[ -f "$1" ]]; then
		printf '%s' "$(<"$1")"
	fi
}

directory_empty() (
	shopt -s nullglob dotglob
	set -- "$1"/*
	[[ $# -eq 0 ]]
)

# only_entry DIR NAME: DIR holds NAME and nothing else.
only_entry() (
	shopt -s nullglob dotglob
	set -- "$1"/* "$2"
	[[ $# -eq 2 && "${1##*/}" == "$2" ]]
)

run_id_ok() {
	[[ "$1" =~ ^[0-9]{14}-[0-9a-f]{4}$ ]]
}

# row_words PRODUCT FILE: the words of the printed table row of PRODUCT.
row_words() {
	local line
	local -a words=()
	if [[ -f "$2" ]]; then
		while IFS= read -r line; do
			if [[ "$line" == "$1 "* ]]; then
				read -r -a words <<<"$line"
				printf '%s' "${words[*]}"
				return 0
			fi
		done <"$2"
	fi
}

# value KEY: the last KEY=VALUE line the latest driver run reported.
value() {
	local line found=''
	if [[ -f "$report" ]]; then
		while IFS= read -r line; do
			if [[ "$line" == "$1="* ]]; then
				found=${line#*=}
			fi
		done <"$report"
	fi
	printf '%s' "$found"
}

json() {
	if [[ -f "$2" ]]; then
		jq -r "$1" "$2" 2>/dev/null || printf 'unreadable'
	else
		printf 'missing'
	fi
}

line_of() {
	local line
	if [[ -f "$2" ]]; then
		while IFS= read -r line; do
			if [[ "$line" == "$1"* ]]; then
				printf '%s' "$line"
				return 0
			fi
		done <"$2"
	fi
}

verb_count() {
	local line count=0
	if [[ -f "$2" ]]; then
		while IFS= read -r line; do
			if [[ "$line" == "$1 "* || "$line" == "$1" ]]; then
				count=$((count + 1))
			fi
		done <"$2"
	fi
	printf '%s' "$count"
}

# Every rm the fake docker saw names exactly NAME, and there was one.
only_rm_of() {
	local line found=0
	[[ -f "$2" ]] || return 1
	while IFS= read -r line; do
		if [[ "$line" == rm* ]]; then
			[[ "$line" == "rm --force --volumes $1" ]] || return 1
			found=1
		fi
	done <"$2"
	[[ $found -eq 1 ]]
}

# None of the recorded secret values is in PATH... (secrets/ folders aside).
# Only file names are printed, never a value.
no_secret_in() {
	local found status=0
	if [[ ! -s "$patterns" ]]; then
		printf '  no secret values were recorded to look for\n'
		return 1
	fi
	found="$(grep -rlF --exclude-dir=secrets -f "$patterns" -- "$@")" || status=$?
	case "$status" in
	1) return 0 ;;
	0) printf '  a secret value is in: %s\n' "${found//$nl/ }" ;;
	*) printf '  grep could not search %s\n' "$*" ;;
	esac
	return 1
}

# The env file Docker was given sets the generated password, by value.
env_file_carries_secret() {
	local text
	[[ -f "$1" ]] || return 1
	text="$(<"$1")"
	[[ "$text" =~ ^POSTGRES_PASSWORD=([0-9a-f]{48})$ ]] || return 1
	grep -qxF -- "${BASH_REMATCH[1]}" "$patterns"
}

# curl received NAME=<a recorded secret> as a form value.
form_has_secret() {
	local line
	[[ -f "$1" ]] || return 1
	while IFS= read -r line; do
		if [[ "$line" == "$2="* ]] && grep -qxF -- "${line#*=}" "$patterns"; then
			return 0
		fi
	done <"$1"
	return 1
}

process_gone() {
	local tries=0
	[[ "${1:-}" =~ ^[0-9]+$ ]] || return 1
	while kill -0 "$1" 2>/dev/null; do
		tries=$((tries + 1))
		((tries <= 60)) || return 1
		sleep 0.05
	done
}

wait_for_file() {
	local tries=0
	while [[ ! -s "$1" ]]; do
		tries=$((tries + 1))
		((tries <= 200)) || return 1
		sleep 0.05
	done
}

wait_for_container() {
	local tries=0
	while directory_empty "$state/containers"; do
		tries=$((tries + 1))
		((tries <= 200)) || return 1
		sleep 0.05
	done
}

# /bin/bash and the other system binaries drop DYLD_* variables on macOS.
bash_is_protected() {
	[[ "$(command -p uname -s)" == Darwin ]] || return 1
	case "$BASH" in
	/bin/* | /usr/bin/* | /sbin/* | /usr/sbin/*) return 0 ;;
	esac
	return 1
}

driver_environment() {
	unset CARGO_TARGET_DIR REGISTRY_CARGO_RUNTIME_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH JOURNEY_PORT_BASE \
		JOURNEY_ASSISTS_FILE JOURNEY_STEP_TIMEOUT
	export PATH="$test_path" FAKE_STATE="$state" REPORT="$report" PATTERNS="$patterns" \
		JOURNEY_LIB_UNDER_TEST="$lib" JOURNEY_TABLES_DIR="$work/tables" \
		JOURNEY_CONTAINER_PREFIX=stackrun-m0-libtest JOURNEY_KILL_GRACE=1 TMPDIR="$work/tmp" \
		FAKE_UNAME_S=Linux SCENARIO=cells
}

# Start the driver through perl: INT and TERM back to their default (a
# background job of a script starts with INT ignored), an alarm after 120
# seconds so a hung case cannot hang the test, and with GROUP=1 a process
# group of its own so a case can signal the driver and its children at once.
start_driver() {
	local group=$1
	shift
	drive_count=$((drive_count + 1))
	out="$work/runs/$case_name-$drive_count"
	report="$work/reports/$case_name-$drive_count"
	last_out="$work/logs/$case_name-$drive_count.out"
	last_err="$work/logs/$case_name-$drive_count.err"
	: >"$report"
	(
		driver_environment
		while [[ $# -gt 0 && "$1" != -- ]]; do
			# shellcheck disable=SC2163 # each argument is NAME=VALUE
			export "$1"
			shift
		done
		[[ $# -eq 0 ]] || shift
		if [[ $add_out -eq 1 ]]; then
			set -- --out "$out" "$@"
		fi
		exec perl -e '
			my ($seconds, $group) = splice @ARGV, 0, 2;
			$SIG{INT} = $SIG{TERM} = "DEFAULT";
			if ($group) { setpgrp(0, 0) or die "setpgrp: $!\n" }
			alarm $seconds;
			exec { $ARGV[0] } @ARGV or die "cannot start $ARGV[0]: $!\n";' -- 120 "$group" "$BASH" "$self" --driver "$@"
	) </dev/null >"$last_out" 2>"$last_err" &
	launched=$!
}

# collect STATUS: wait for the driver and compare its exit status.
collect() {
	local want=$1 status=0 tail_text
	wait "$launched" || status=$?
	launched=''
	checks=$((checks + 1))
	if [[ $status -ne $want ]]; then
		tail_text="$(tail -n 3 "$last_err")"
		problem "exit status $status, expected $want" "${tail_text//$nl/ | }"
	fi
}

# drive STATUS [NAME=VALUE]... -- [ARGUMENT]...: run the driver to the end.
drive() {
	local want=$1
	shift
	start_driver 0 "$@"
	collect "$want"
}

# launch [NAME=VALUE]... -- [ARGUMENT]...: start the driver in its own
# process group and return; collect waits for it.
launch() {
	start_driver 1 "$@"
}

write_wrapper() {
	{
		printf '#!%s\n' "$BASH"
		# shellcheck disable=SC2016 # "$@" belongs to the wrapper
		printf 'exec %q %q --fake %q "$@"\n' "$BASH" "$self" "$2"
	} >"$1"
	chmod 755 "$1"
}

expected_table() {
	cat <<'YAML'
schema: registry.journey-expected-failures/v1
journeys:
  sample:
    steps: [prepare, start, call, stop]
journeyCodeSuffixes:
  needs: [certificate, hand-written-sql]
  promote: [no-input]
authenticationStages: [issuer, audience]
changes: [posture, shared-trust-rules]
expectedFailures:
  - journey: sample
    product: beta
    step: call
    code: http.401.issuer
    removedBy: posture
    basis: predicted
    reason: The issuer is refused.
YAML
	if [[ "${1:-}" != unlisted ]]; then
		cat <<'YAML'
  - journey: sample
    product: delta
    step: start
    code: product.config.unknown-field
    removedBy: shared-trust-rules
    basis: predicted
    reason: The runtime file names a field the product does not know.
YAML
	fi
	if [[ "${1:-}" == twice ]]; then
		cat <<'YAML'
  - journey: sample
    product: alpha
    step: call
    code: http.401.audience
    removedBy: shared-trust-rules
    basis: predicted
    reason: Listed twice on purpose.
YAML
	fi
	cat <<'YAML'
unreached:
  - journey: sample
    product: gamma
    step: prepare
    basis: predicted
    reason: Runs beside alpha.
passes:
  - journey: sample
    product: alpha
    basis: predicted
YAML
}

write_tables() {
	local dir="$work/tables"
	mkdir -p "$dir" "$work/empty"
	cat >"$dir/products.yaml" <<'YAML'
schema: registry.journey-products/v1
products:
  - id: alpha
    tier: primary
    binary: alpha
    crate: registry-alpha
    ctl: registry-alphactl
    cargoPackages: [registry-alpha, registry-alphactl]
    cargoFeatures: [registry-alpha/runtime]
    usesPostgres: true
    verifiesTokens: true
    rstackDevPlan: false
  - id: beta
    tier: primary
    binary: beta
    crate: registry-beta
    ctl: null
    cargoPackages: [registry-beta, registry-alphactl]
    cargoFeatures: []
    usesPostgres: false
    verifiesTokens: true
    rstackDevPlan: false
  - id: gamma
    tier: supporting
    parent: alpha
    binary: gamma
    crate: registry-gamma
    ctl: null
    cargoPackages: [registry-gamma]
    cargoFeatures: [registry-gamma/runtime]
    usesPostgres: false
    verifiesTokens: false
    rstackDevPlan: false
  - id: delta
    tier: primary
    binary: delta
    crate: registry-delta
    ctl: null
    cargoPackages: [registry-delta]
    cargoFeatures: []
    usesPostgres: false
    verifiesTokens: false
    rstackDevPlan: true
YAML
	cat >"$dir/concepts.yaml" <<'YAML'
schema: registry.journey-concepts/v1
concepts:
  - id: runtime-file
    meaning: The file a product reads when it starts.
  - id: issuer
    meaning: The identity provider that signs the tokens a product accepts.
YAML
	cat >"$dir/first-hour-pass-rule.yaml" <<'YAML'
# lib.sh reads only readerTimeModel; the flow mapping below is outside the
# core YAML reader's subset and must not stop it.
rules: {steps: 12}
readerTimeModel:
  typingCharactersPerMinute: 200
  readingWordsPerMinute: 200
  secondsPerHandWrittenLine: 30
  secondsPerConceptFirstMet: 60
  minutesPerRefusalMet: 5
  minutesPerAssistUsed: 10
YAML
	expected_table >"$dir/expected-failures.yaml"
	expected_table unlisted >"$dir/expected-unlisted.yaml"
	expected_table twice >"$dir/expected-twice.yaml"
}

write_fixtures() {
	local fips="$work/bins/debug/build/aws-lc-fips-sys-0f1e2d/out/build/artifacts" tool
	mkdir -p "$work/bin" "$work/cargo-bin" "$work/tools" "$work/tmp" "$work/state" "$work/patterns" \
		"$work/reports" "$work/runs" "$work/logs" "$fips" "$work/bins/debug/build/aws-lc-fips-sys-000000/out" \
		"$work/bare-bins" "$work/target/debug" "$work/carrier"
	chmod 700 "$work/tmp"
	: >"$fips/libaws_lc_fips_0_13_7_crypto.dylib"
	for tool in jq python3; do
		ln -s "$(command -v "$tool")" "$work/tools/$tool"
	done
	write_wrapper "$work/bin/docker" docker
	write_wrapper "$work/bin/curl" curl
	write_wrapper "$work/bin/uname" uname
	write_wrapper "$work/cargo-bin/cargo" cargo
	write_wrapper "$work/bins/debug/alpha" alpha
	write_wrapper "$work/bare-bins/alpha" alpha
	write_wrapper "$work/target/debug/alpha" alpha
	ln -s "$work/bins" "$work/bin-link"
	cat >"$work/assists.sh" <<'SH'
# Assists of the self-test: each records its arguments.
journey_assist_certificate() {
	printf '%s\n' "$*" >>"$FAKE_STATE/assist-ran"
}
SH
	write_tables
}

# ---------------------------------------------------------------------------
# Cases

case_usage() {
	begin_case usage
	add_out=0
	drive 2 -- --no-such-option
	check "an unknown option is named" has "unknown option --no-such-option" "$last_err"
	drive 2 -- --product alpha --strict
	check "--strict needs --expected" has "--strict needs --expected" "$last_err"
	drive 2 -- --all --product alpha
	drive 2 -- --product omega
	check "an unknown product lists the known ones" has "products.yaml lists: alpha beta gamma delta" "$last_err"
	drive 2 -- --product alpha --expected "$work/no-such-table.yaml"
	drive 2 -- --assist certificate --expected "$work/tables/expected-failures.yaml"
	check "--assist and --expected exclude each other" has "--assist and --expected exclude each other" "$last_err"
	drive 2 -- --out "$work/runs/a" --out "$work/runs/b"
	check "an option given twice is refused" has "--out is given twice" "$last_err"
	drive 2 JOURNEY_CONTAINER_PREFIX=Bad_Prefix -- --product alpha
	drive 2 JOURNEY_PORT_BASE=80 -- --product alpha
	drive 2 JOURNEY_TABLES_DIR="$work/empty" -- --product alpha
	check "a missing table is named" has "does not exist" "$last_err"
	drive 0 -- --help
	check "--help prints the usage" has "usage:" "$last_out"
	check "no usage error created a run directory" directory_empty "$work/tmp"
	check "no usage error created a --out directory" directory_empty "$work/runs"
	checks=$((checks + 1))
	local status=0
	"$BASH" "$lib" >/dev/null 2>&1 || status=$?
	if [[ $status -ne 2 ]]; then
		problem "lib.sh run on its own exits 2" "it exited $status"
	fi
}

case_binaries() {
	local artifacts="$work/bins/debug/build/aws-lc-fips-sys-0f1e2d/out/build/artifacts"
	local cargo_path="$work/cargo-bin:$test_path"

	begin_case bin-dir-darwin
	drive 0 FAKE_UNAME_S=Darwin DRIVER_DYLD=/caller/lib PREPARE=print-env -- --product alpha --bin-dir "$work/bin-link/debug"
	check_equal "the binary directory is resolved to its physical path" "$work/bins/debug" "$(value bin_dir)"
	check_equal "the FIPS directory is the first artifacts folder under build/" "$artifacts" "$(value carrier)"
	check_equal "it goes first in DYLD_FALLBACK_LIBRARY_PATH, the caller's value after it" "$artifacts:/caller/lib" "$(value dyld)"
	check_equal "the product sees REGISTRY_CARGO_RUNTIME_LIBRARY_PATH" "carrier=$artifacts" "$(line_of carrier= "$out/alpha/prepare.stdout")"
	if bash_is_protected; then
		printf 'note %s: %s is a protected binary, so a product started through it never sees DYLD_* variables; that check is skipped under this bash\n' "$case_name" "$BASH"
	else
		check_equal "the product started directly by bash sees DYLD_FALLBACK_LIBRARY_PATH" "dyld=$artifacts:/caller/lib" "$(line_of dyld= "$out/alpha/prepare.stdout")"
	fi
	check_equal "run.json records the runtime library path" "$artifacts" "$(json '.binaries.runtimeLibraryPath' "$out/run.json")"
	check_equal "run.json records the binaries' source" bin-dir "$(json '.binaries.source' "$out/run.json")"

	begin_case bin-dir-carrier
	drive 0 FAKE_UNAME_S=Darwin REGISTRY_CARGO_RUNTIME_LIBRARY_PATH="$work/carrier" -- --product alpha --bin-dir "$work/bins/debug"
	check_equal "the caller's REGISTRY_CARGO_RUNTIME_LIBRARY_PATH wins over the build folder" "$work/carrier" "$(value carrier)"
	check_equal "DYLD_FALLBACK_LIBRARY_PATH holds it alone" "$work/carrier" "$(value dyld)"
	drive 2 FAKE_UNAME_S=Darwin REGISTRY_CARGO_RUNTIME_LIBRARY_PATH="$work/no-such-dir" -- --product alpha --bin-dir "$work/bins/debug"
	check "a carrier naming no directory is refused" has "names no directory" "$last_err"

	begin_case bin-dir-linux
	drive 0 FAKE_UNAME_S=Linux -- --product alpha --bin-dir "$work/bins/debug"
	check_equal "off macOS no FIPS directory is exported" unset "$(value carrier)"
	check_equal "off macOS DYLD_FALLBACK_LIBRARY_PATH is left alone" unset "$(value dyld)"

	begin_case bin-dir-without-fips-library
	drive 0 FAKE_UNAME_S=Darwin -- --product alpha --bin-dir "$work/bare-bins"
	check "a bin dir without the FIPS library warns" has "warning: no AWS-LC FIPS library directory" "$last_err"
	check_equal "and exports nothing" unset "$(value carrier)"

	begin_case build-darwin
	mkdir -p "$state/fips-out/build/artifacts"
	: >"$state/fips-out/build/artifacts/libaws_lc_fips_0_13_7_crypto.dylib"
	drive 0 PATH="$cargo_path" FAKE_UNAME_S=Darwin CARGO_TARGET_DIR="$work/target" CELL_beta=pass -- --product alpha --product beta
	check_equal "cargo builds each package once, locked, through the repository helper" \
		"build --locked --manifest-path $root/Cargo.toml -p registry-alpha -p registry-alphactl -p registry-beta --features registry-alpha/runtime --bins --message-format=json-render-diagnostics" \
		"$(contents "$state/cargo.argv")"
	check_equal "cargo sees the exported CARGO_TARGET_DIR" "$work/target" "$(contents "$state/cargo.target")"
	check_equal "the binaries come from its debug folder" "$work/target/debug" "$(value bin_dir)"
	check_equal "the FIPS directory comes from cargo's build messages" "$state/fips-out/build/artifacts" "$(value carrier)"
	check_equal "and is exported for the dynamic loader" "$state/fips-out/build/artifacts" "$(value dyld)"
	check_equal "run.json records a build" build "$(json '.binaries.source' "$out/run.json")"

	begin_case build-linux
	drive 0 PATH="$cargo_path" FAKE_UNAME_S=Linux CARGO_TARGET_DIR="$work/target" -- --product alpha
	check_equal "off macOS it is a plain cargo build" \
		"build --locked --manifest-path $root/Cargo.toml -p registry-alpha -p registry-alphactl --features registry-alpha/runtime --bins" \
		"$(contents "$state/cargo.argv")"
	check_equal "and exports no FIPS directory" unset "$(value carrier)"

	begin_case build-refusals
	drive 2 PATH="$cargo_path" CARGO_TARGET_DIR="$root/target" -- --product alpha
	check "the repository target/ directory is refused" has "points at the repository target/ directory" "$last_err"
	drive 2 PATH="$cargo_path" CARGO_TARGET_DIR="$root/target/journeys" -- --product alpha
	check "a folder under it is refused" has "points at the repository target/ directory" "$last_err"
	drive 2 -- --product alpha
	check "with neither --bin-dir nor CARGO_TARGET_DIR the run stops" has "pass --bin-dir DIR or export CARGO_TARGET_DIR" "$last_err"
	drive 2 PATH="$cargo_path" CARGO_TARGET_DIR="$work/target" -- --product alpha --timed
	check "--timed refuses a build" has "--timed needs --bin-dir" "$last_err"
	local filtered="$work/no-cargo" entry executable
	local -a search_dirs
	mkdir -p "$filtered"
	IFS=: read -r -a search_dirs <<<"$test_path"
	for entry in "${search_dirs[@]}"; do
		for executable in "$entry"/*; do
			[[ -f "$executable" && -x "$executable" && "${executable##*/}" != cargo ]] || continue
			[[ -L "$filtered/${executable##*/}" ]] || ln -s "$executable" "$filtered/"
		done
	done
	drive 2 PATH="$filtered" CARGO_TARGET_DIR="$work/target" -- --product alpha
	check "a build needs cargo on PATH" has "cargo is not on PATH" "$last_err"
	check "no refused build ran cargo" no_file "$state/cargo.argv"

	begin_case build-fails
	: >"$state/cargo-fails"
	drive 2 PATH="$cargo_path" CARGO_TARGET_DIR="$work/target" -- --product alpha
	check "a failed build stops the run" has "the build of the journey binaries failed" "$last_err"

	begin_case missing-binary
	drive 2 BIN_NAME=omega -- --product alpha --bin-dir "$work/bins/debug"
	check "a binary missing from the bin dir is named" has "no executable omega" "$last_err"
}

case_run_directories() {
	begin_case out-through-symlink
	add_out=0
	mkdir -p "$work/out-real"
	ln -s "$work/out-real" "$work/out-link"
	drive 0 -- --product alpha --bin-dir "$work/bins/debug" --out "$work/out-link/run"
	finished_run="$work/out-real/run"
	check_equal "the run directory is resolved to its physical path" "$finished_run" "$(value out)"
	check_equal "the run directory has mode 700" 700 "$(mode_of "$finished_run")"
	check "cells.tsv records the cell" has $'alpha\tstop\tpass' "$finished_run/cells.tsv"
	check "the raw folder is gone after the run" no_file "$finished_run/.raw"
	check "the secrets folder is gone after the run" no_file "$finished_run/secrets"
	check_equal "run.json ends with exit status 0" 0 "$(json '.exitStatus' "$finished_run/run.json")"
	check_equal "summary.json names its schema" registry.journey-summary/v1 "$(json '.schema' "$finished_run/summary.json")"

	begin_case out-refusals
	add_out=0
	mkdir -p "$work/out-full"
	printf 'keep me\n' >"$work/out-full/note"
	drive 2 -- --product alpha --bin-dir "$work/bins/debug" --out "$work/out-full"
	check "a non-empty --out is refused" has "is not empty" "$last_err"
	check "and left as it was" has "keep me" "$work/out-full/note"
	check "nothing was added to it" only_entry "$work/out-full" note
	printf 'x\n' >"$work/out-file"
	drive 2 -- --product alpha --bin-dir "$work/bins/debug" --out "$work/out-file"
	check "a --out that is a file is refused" has "exists and is not a directory" "$last_err"

	begin_case out-default
	add_out=0
	drive 0 -- --product alpha --bin-dir "$work/bins/debug"
	check_equal "without --out the run goes under TMPDIR, named by prefix, journey and run" \
		"$work/tmp/stackrun-m0-libtest-sample-$(value run)" "$(value out)"
	check "the run id is a UTC time and four hexadecimal digits" run_id_ok "$(value run)"
}

case_containers() {
	local name options
	local -a alpha_args=(--product alpha --bin-dir "$work/bins/debug")

	begin_case containers
	printf '%s\n' "$test_image" >"$state/containers/stackrun-m0-libtest-foreign"
	drive 0 SCENARIO=containers -- "${alpha_args[@]}"
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check_equal "containers.txt lists exactly the container the run made" "$name" "$(contents "$out/containers.txt")"
	check "docker run is detached, named and given a cidfile" has "run --detach --name $name --cidfile $out/.raw/" "$state/docker.argv"
	check "it is labelled, published on 127.0.0.1 only and given the env file" \
		has "--label registry.journey.run=$(value run) --publish 127.0.0.1::5432 -e PLAIN=1 --env-file $out/secrets/container-db.env $test_image" "$state/docker.argv"
	check "no docker network command ran" lacks network "$state/docker.argv"
	check_equal "the host port is read back from docker port" 49153 "$(value port)"
	check_equal "the bridge address is read from docker inspect" 172.17.0.9 "$(value address)"
	check "cleanup removes the container by its exact name and nothing else" only_rm_of "$name" "$state/docker.argv"
	check "the fake no longer holds it" no_file "$state/containers/$name"
	check "a container the run did not make is still there" test -f "$state/containers/stackrun-m0-libtest-foreign"
	check "the leftover check names it" has "leftover container stackrun-m0-libtest-foreign still exists" "$last_err"
	check_equal "run.json records the leftover" stackrun-m0-libtest-foreign "$(json '.leftovers | join(",")' "$out/run.json")"
	check_equal "run.json records the image by digest" "$test_image" "$(json '.images[0].image' "$out/run.json")"
	check "the password reached Docker in the env file" env_file_carries_secret "$state/env-file.$name"
	check "the password is on no docker argument list" no_secret_in "$state/docker.argv"
	check "the password is in no saved output" no_secret_in "$out"
	check "the container log is saved" has "fake log of $name" "$out/containers/db.log.stdout"
	check "the secrets folder is gone after the run" no_file "$out/secrets"
	check_equal "a cleanup hook runs before the containers are removed" container-present "$(contents "$state/hook-ran")"
	check_equal "run.json records the address class" bridge "$(json '.addressClass' "$out/run.json")"

	begin_case cleanup-hook-fails
	drive 3 SCENARIO=containers HOOK=fail -- "${alpha_args[@]}"
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check "a failing cleanup hook is a cleanup failure" has "cleanup failure: cleanup hook driver_cleanup_hook failed" "$last_err"
	check "cleanup carries on and removes the container" only_rm_of "$name" "$state/docker.argv"

	begin_case container-timed
	drive 0 SCENARIO=containers -- "${alpha_args[@]}" --timed
	check "--timed refuses image pulls" has "--env-file $out/secrets/container-db.env --pull never $test_image" "$state/docker.argv"
	check_equal "run.json records --timed" true "$(json '.timed' "$out/run.json")"

	begin_case container-not-ready
	drive 3 SCENARIO=containers WAIT_PROBE=false WAIT_SECONDS=1 -- "${alpha_args[@]}"
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check "a container not ready in time is a harness failure" has "was not ready within 1 seconds" "$last_err"
	check "its log is saved" has "fake log of $name" "$out/containers/db.log.stdout"
	check "it is removed" only_rm_of "$name" "$state/docker.argv"

	begin_case container-port-base
	mkdir -p "$work/mount"
	drive 0 SCENARIO=containers JOURNEY_PORT_BASE=38040 EXTRA_PORT=8080 CONTAINER_OPTS="-v $work/mount:/data:ro" -- "${alpha_args[@]}"
	check "fixed ports count up from JOURNEY_PORT_BASE on 127.0.0.1" \
		has "--publish 127.0.0.1:38040:5432 --publish 127.0.0.1:38041:8080 -e PLAIN=1 -v $work/mount:/data:ro" "$state/docker.argv"
	check_equal "the port is read back" 38040 "$(value port)"

	begin_case container-refusals
	for options in "--network host" "--network=bridge" "--net host" "-p 5432:5432" "-p5432:5432" \
		"--publish 5432" "--publish-all" "-P" "--privileged" "--name other" "-d" "--detach" "--rm" \
		"--cidfile /dev/null" "--pull always" "--mount type=volume,dst=/data" "-v data:/var/lib/data" "-vdata:/data"; do
		drive 3 SCENARIO=containers CONTAINER_OPTS="$options" -- "${alpha_args[@]}"
		check "'$options' is refused as a journey script error" has "journey script error" "$last_err"
	done
	drive 3 SCENARIO=containers CONTAINER_IMAGE=registry.test/fake/postgres:17 -- "${alpha_args[@]}"
	check "an image not pinned by digest is refused" has "is not pinned by digest" "$last_err"
	check_equal "no refused container reached docker run" 0 "$(verb_count run "$state/docker.argv")"

	begin_case container-occupied
	: >"$state/every-name-exists"
	drive 3 SCENARIO=containers -- "${alpha_args[@]}"
	check "an existing name is a harness failure" has "already exists; the journey never adopts one" "$last_err"
	check_equal "docker run never ran" 0 "$(verb_count run "$state/docker.argv")"
	check_equal "and nothing was removed" 0 "$(verb_count rm "$state/docker.argv")"
	check_equal "containers.txt is empty" '' "$(contents "$out/containers.txt")"

	begin_case container-inspect-error
	: >"$state/inspect-fails"
	drive 3 SCENARIO=containers -- "${alpha_args[@]}"
	check "a Docker error is not taken for an absent container" has "cannot tell whether container" "$last_err"
	check_equal "docker run never ran" 0 "$(verb_count run "$state/docker.argv")"

	begin_case container-created-then-failed
	: >"$state/fail-after-create"
	drive 3 SCENARIO=containers -- "${alpha_args[@]}"
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check_equal "containers.txt lists the container Docker created" "$name" "$(contents "$out/containers.txt")"
	check "cleanup removes it by name" only_rm_of "$name" "$state/docker.argv"
	check "the fake no longer holds it" no_file "$state/containers/$name"
	check "Docker's error is saved" has "fake failure after create" "$out/containers/db.run.stderr"
	check "a harness failure writes no summary" no_file "$out/summary.json"

	begin_case container-start-failed
	: >"$state/fail-start"
	drive 3 SCENARIO=containers -- "${alpha_args[@]}"
	check_equal "a container Docker never created is not listed" '' "$(contents "$out/containers.txt")"
	check_equal "and nothing is removed" 0 "$(verb_count rm "$state/docker.argv")"

	begin_case container-run-interrupted
	: >"$state/hang-after-create"
	launch SCENARIO=containers -- "${alpha_args[@]}"
	if wait_for_container; then
		kill -TERM -- "-$launched"
	else
		problem "the fake docker run never created its container"
	fi
	collect 143
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check_equal "a container whose docker run was interrupted is listed" "$name" "$(contents "$out/containers.txt")"
	check "and removed" only_rm_of "$name" "$state/docker.argv"

	# Docker writes the cidfile only after the container exists, so an
	# interrupt can fall between the two.
	begin_case container-run-interrupted-before-cidfile
	: >"$state/hang-before-cidfile"
	launch SCENARIO=containers -- "${alpha_args[@]}"
	if wait_for_container; then
		kill -TERM -- "-$launched"
	else
		problem "the fake docker run never created its container"
	fi
	collect 143
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check_equal "a container created before its cidfile was written is found by its name and listed" \
		"$name" "$(contents "$out/containers.txt")"
	check "and removed" only_rm_of "$name" "$state/docker.argv"
	check "the fake no longer holds it" directory_empty "$state/containers"

	begin_case container-run-interrupted-unanswered
	: >"$state/hang-before-cidfile"
	launch SCENARIO=containers -- "${alpha_args[@]}"
	if wait_for_container; then
		: >"$state/inspect-fails"
		kill -TERM -- "-$launched"
	else
		problem "the fake docker run never created its container"
	fi
	collect 143
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check "a lookup Docker cannot answer is a cleanup failure that names the container" \
		has "cannot tell whether the interrupted docker run created $name" "$last_err"
	check_equal "run.json records it" 1 \
		"$(json '[.cleanup.failures[] | select(contains("cannot tell whether"))] | length' "$out/run.json")"
	check_equal "nothing is removed on a guess" 0 "$(verb_count rm "$state/docker.argv")"

	begin_case container-stopped
	: >"$state/stopped"
	drive 3 SCENARIO=containers -- "${alpha_args[@]}"
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check "a container that stops before it is ready is a harness failure" has "stopped before it was ready" "$last_err"
	check "its log is saved" has "fake log of $name" "$out/containers/db.log.stdout"
	check "it is removed" only_rm_of "$name" "$state/docker.argv"

	begin_case docker-daemon-down
	: >"$state/daemon-down"
	drive 2 SCENARIO=containers -- "${alpha_args[@]}"
	check "a missing Docker daemon is a missing prerequisite" has "needs a running Docker daemon" "$last_err"

	begin_case cleanup-failure
	: >"$state/rm-fails"
	drive 3 SCENARIO=containers -- "${alpha_args[@]}"
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check "the failed removal is reported with the name to remove" has "cleanup failure: docker rm --force --volumes $name failed" "$last_err"
	check_equal "run.json records it" 1 "$(json '.cleanup.failures | length' "$out/run.json")"
	check_equal "run.json records exit status 3" 3 "$(json '.exitStatus' "$out/run.json")"

	begin_case cleanup-failure-after-product-failure
	: >"$state/rm-fails"
	drive 3 SCENARIO=containers CELL_alpha=fail:call:product.call.refused -- "${alpha_args[@]}"
	check "a cleanup failure outranks a product failure" has "cleanup failure" "$last_err"
}

case_keep_and_take_over() {
	local name kept_run kept_state
	local -a alpha_args=(--product alpha --bin-dir "$work/bins/debug")

	begin_case keep
	drive 0 SCENARIO=containers START_SERVER=1 -- "${alpha_args[@]}" --keep
	kept_run=$out
	kept_state=$state
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check_equal "--keep leaves the container" 0 "$(verb_count rm "$state/docker.argv")"
	check "and names it" has "kept container $name" "$last_err"
	check "the kept marker is written" test -f "$kept_run/kept"
	check_equal "the kept secret keeps mode 600" 600 "$(mode_of "$kept_run/secrets/db-password")"
	check_equal "the kept secrets folder keeps mode 700" 700 "$(mode_of "$kept_run/secrets")"
	check "the server process is stopped all the same" process_gone "$(contents "$state/alpha.pid")"
	check_equal "run.json records --keep" true "$(json '.keep' "$kept_run/run.json")"
	check "saved output outside secrets/ holds no secret" no_secret_in "$kept_run"

	begin_case take-over-refusals
	drive 2 SCENARIO=takeover JOURNEY_CONTAINER_PREFIX=stackrun-m0-other -- "${alpha_args[@]}" --from "$kept_run"
	check "a run of another prefix is refused" has "used container prefix stackrun-m0-libtest" "$last_err"
	drive 2 SCENARIO=takeover -- "${alpha_args[@]}" --from "$finished_run"
	check "a run that did not end with --keep is refused" has "is not a run that ended with --keep" "$last_err"
	check "the kept run is untouched" test -f "$kept_run/secrets/db-password"

	begin_case take-over
	state=$kept_state
	cat -- "$work/patterns/keep" >>"$patterns"
	drive 0 SCENARIO=takeover -- "${alpha_args[@]}" --from "$kept_run"
	check "the later run removes the kept container" has "rm --force --volumes $name" "$state/docker.argv"
	check "the fake no longer holds it" no_file "$state/containers/$name"
	check "the kept secrets are deleted" no_file "$kept_run/secrets"
	check "the kept secret is redacted in the later run's output" has "[redacted:db-password]" "$out/alpha/prepare.stdout"
	check "no saved output of either run holds it" no_secret_in "$out" "$kept_run"
	check_equal "run.json names the run taken over" "$kept_run" "$(json '.takenOver' "$out/run.json")"
}

case_interrupts() {
	local signal want name
	local -a alpha_args=(--product alpha --bin-dir "$work/bins/debug")
	for signal in TERM INT; do
		case "$signal" in
		TERM) want=143 ;;
		INT) want=130 ;;
		esac
		begin_case "interrupt-$signal"
		launch SCENARIO=interrupt -- "${alpha_args[@]}"
		if wait_for_file "$state/alpha.pid"; then
			sleep 0.2
			kill "-$signal" "$launched"
		else
			problem "the step never started"
		fi
		collect "$want"
		name="stackrun-m0-libtest-sample-$(value run)-db"
		check "the step's process is stopped" process_gone "$(contents "$state/alpha.pid")"
		check "the container is removed" only_rm_of "$name" "$state/docker.argv"
		check "the secrets folder is deleted" no_file "$out/secrets"
		check "the journey went no further" lacks after-step "$report"
		check_equal "run.json records the signal's exit status" "$want" "$(json '.exitStatus' "$out/run.json")"
	done

	begin_case script-error
	drive 3 SCENARIO=error -- "${alpha_args[@]}"
	name="stackrun-m0-libtest-sample-$(value run)-db"
	check "an error in the journey script is a harness failure" has "stopped before journey_finish (exit status 1)" "$last_err"
	check "cleanup still removes the container" only_rm_of "$name" "$state/docker.argv"
	check_equal "run.json records it" 3 "$(json '.exitStatus' "$out/run.json")"
}

case_secrets() {
	local redacted marker
	local -a alpha_args=(--product alpha --bin-dir "$work/bins/debug")

	begin_case secrets
	drive 0 SCENARIO=secrets -- "${alpha_args[@]}"
	check_equal "a generated secret has mode 600" 600 "$(value secret-mode)"
	check_equal "it holds 24 random bytes as hexadecimal" 48 "$(value secret-length)"
	check_equal "an env file has mode 600" 600 "$(value env-mode)"
	check_equal "an env file sets the variable to the secret's value" ok "$(value env-file)"
	redacted="$(value redacted)"
	for marker in '[redacted:api-key]' '[redacted:access-token]' '[redacted:private-key]' '[redacted:jwt]' \
		'Authorization: [redacted]' '> Cookie: [redacted]' 'Bearer [redacted]' 'postgres://registry:[redacted]@127.0.0.1' \
		'"access_token": "[redacted]"' '"password": "[redacted]"' '"note": "kept"'; do
		check "redaction writes $marker" has "$marker" "$redacted"
	done
	check "the redacted copy holds no secret value" no_secret_in "$redacted"
	check "no saved output holds one" no_secret_in "$out"
	check "the secrets folder is gone after the run" no_file "$out/secrets"
	check "the raw folder is gone after the run" no_file "$out/.raw"
	check_equal "the final scan found nothing" clean "$(json '.secretScan' "$out/run.json")"

	begin_case secret-refusals
	drive 3 SCENARIO=secret-short -- --product alpha
	check "a secret of fewer than 16 bytes is refused" has "a secret needs at least 16 random bytes" "$last_err"
	drive 3 SCENARIO=register-short -- --product alpha
	check "a registered value of fewer than 8 characters is refused" has "shorter than 8 characters" "$last_err"

	begin_case leak-secret
	drive 3 SCENARIO=leak LEAK=secret -- "${alpha_args[@]}"
	check "a secret written past redaction is found and named by label" has "leak.txt: the value of secret api-key" "$last_err"
	check "the finding does not print the value" no_secret_in "$last_err" "$last_out"
	check_equal "run.json records the finding" found "$(json '.secretScan' "$out/run.json")"
	check_equal "a passing run that leaked exits 3" 3 "$(json '.exitStatus' "$out/run.json")"

	begin_case leak-jwt
	drive 3 SCENARIO=leak LEAK=jwt -- "${alpha_args[@]}"
	check "a compact JWT in saved output is found" has "leak.txt: a compact JWT" "$last_err"
}

case_http() {
	local token
	begin_case http
	token="tok$(random_hex 16)"
	printf '%s\n' "$token" >>"$patterns"
	printf 'Authorization: Bearer %s\n' "$token" >"$work/expected-header"
	printf '{"access_token": "%s", "token_type": "Bearer", "expires_in": 300}\n' "$token" >"$state/http-body.1"
	printf '401\n' >"$state/http-status.2"
	printf '{"type": "about:blank", "code": "auth.issuer-refused", "detail": "the issuer is not accepted"}\n' >"$state/http-body.2"
	drive 1 SCENARIO=http -- --product alpha
	check_equal "the captured token has its full length" "${#token}" "$(value token-length)"
	check_equal "the status is read" 401 "$(value http-status)"
	check_equal "the problem code is read from the body" auth.issuer-refused "$(value problem-code)"
	check "the token reached curl as a header read through a file descriptor" grep -qxF -f "$work/expected-header" "$state/curl.headers"
	check "the other header came the same way" grep -qxF 'Accept: application/json' "$state/curl.headers"
	check "the client secret reached curl as a form value read from its file" form_has_secret "$state/curl.form" client_secret
	check "no curl argument list holds the token or the client secret" no_secret_in "$state/curl.argv"
	check "no saved output holds them" no_secret_in "$out"
	check "the token in the saved body is redacted" has '"access_token": "[redacted]"' "$out/alpha/start.stdout"
	check "the response status line is saved" has "HTTP/1.1 401" "$out/alpha/call.http"
	check "request headers are never saved" lacks Authorization "$out/alpha/call.http"
	check "the failure is recorded with its code" has $'alpha\tcall\tfail\thttp.401.issuer' "$out/cells.tsv"
	check "a cookie jar is kept among the secrets and given to curl both ways" \
		has "--cookie $out/secrets/cookies-session --cookie-jar $out/secrets/cookies-session" "$state/curl.argv"
	check "and deleted with them" no_file "$out/secrets"

	begin_case step-and-http-options
	: >"$state/curl-fails"
	drive 1 SCENARIO=options -- --product alpha --bin-dir "$work/bins/debug"
	check "--cwd runs the command in that folder" has "cwd=$out/work/alpha" "$out/alpha/prepare.stdout"
	check "--stdin gives it the file as input" has "stdin=reader input" "$out/alpha/prepare.stdout"
	check_equal "--doc-words is counted" 40 "$(json '.total.documentationWords' "$out/alpha/cell.json")"
	check_equal "--typed replaces the command's own text (11) beside the request's default text (42)" \
		53 "$(json '.total.charactersTyped' "$out/alpha/cell.json")"
	check "--location reaches curl" has "--location" "$state/curl.argv"
	check "--data-file reaches curl as a file to read" has "--data-binary @$out/work/alpha/input.txt" "$state/curl.argv"
	check_equal "a request with no answer has status 000" 000 "$(value curl-status)"
	check "and fails with the journey's code" has $'alpha\tstart\tfail\tproduct.http.no-answer' "$out/cells.tsv"

	begin_case http-credential-header
	drive 3 SCENARIO=http-header -- --product alpha
	check "a credential passed as a header is refused" has "pass a token with --bearer VAR, never as a header" "$last_err"
	check "curl never ran" no_file "$state/curl.argv"
}

case_modes() {
	local table="$work/tables/expected-failures.yaml"
	local -a run_args=(--bin-dir "$work/bins/debug")

	begin_case acceptance-all-pass
	drive 0 CELL_beta=pass CELL_gamma=pass CELL_delta=pass -- "${run_args[@]}"
	check_equal "every cell is ok" 4 "$(json '[.cells[] | select(.verdict == "ok")] | length' "$out/summary.json")"

	begin_case acceptance-failures
	drive 1 -- "${run_args[@]}"
	check_equal "a failed cell is not-passed" not-passed "$(json '.cells[] | select(.product == "beta") | .verdict' "$out/summary.json")"
	check_equal "so is an unreached cell" not-passed "$(json '.cells[] | select(.product == "gamma") | .verdict' "$out/summary.json")"

	begin_case ratchet-equal
	drive 0 -- "${run_args[@]}" --expected "$table"
	check_equal "every cell equals its row" 4 "$(json '[.cells[] | select(.verdict == "ok")] | length' "$out/summary.json")"
	check_equal "summary.json names the mode" ratchet "$(json '.mode' "$out/summary.json")"
	check_equal "the printed table shows the cell, its row and the verdict" \
		"beta fail call http.401.issuer fail call http.401.issuer ok" "$(row_words beta "$last_out")"

	begin_case ratchet-equal-strict
	drive 0 -- "${run_args[@]}" --expected "$table" --strict

	begin_case ratchet-other-code
	drive 1 CELL_beta=fail:call:http.401.audience -- "${run_args[@]}" --expected "$table"
	check_equal "another code is a mismatch" mismatch "$(json '.cells[] | select(.product == "beta") | .verdict' "$out/summary.json")"

	begin_case ratchet-other-step
	drive 1 CELL_beta=fail:start:http.401.issuer -- "${run_args[@]}" --expected "$table"
	check_equal "another step is a mismatch" mismatch "$(json '.cells[] | select(.product == "beta") | .verdict' "$out/summary.json")"

	begin_case ratchet-unreached-elsewhere
	drive 1 CELL_gamma=unreached:start -- "${run_args[@]}" --expected "$table"
	check_equal "unreached at another step is a mismatch" mismatch "$(json '.cells[] | select(.product == "gamma") | .verdict' "$out/summary.json")"

	begin_case ratchet-stale
	drive 0 CELL_beta=pass -- "${run_args[@]}" --expected "$table"
	check "a listed failure that passes is a warning" has "warning: a listed failure no longer fails" "$last_err"
	check_equal "its verdict is stale" stale "$(json '.cells[] | select(.product == "beta") | .verdict' "$out/summary.json")"

	begin_case ratchet-stale-strict
	drive 1 CELL_beta=pass -- "${run_args[@]}" --expected "$table" --strict
	check "--strict makes it an error" has "a listed failure no longer fails: delete its row" "$last_err"

	begin_case ratchet-unlisted
	drive 1 -- "${run_args[@]}" --expected "$work/tables/expected-unlisted.yaml"
	check_equal "a cell with no row is unlisted" unlisted "$(json '.cells[] | select(.product == "delta") | .verdict' "$out/summary.json")"

	begin_case ratchet-listed-twice
	drive 1 -- "${run_args[@]}" --expected "$work/tables/expected-twice.yaml"
	check_equal "a cell with two rows is listed-twice" listed-twice "$(json '.cells[] | select(.product == "alpha") | .verdict' "$out/summary.json")"

	begin_case needs
	drive 1 CELL_alpha=needs:start:hand-written-sql -- --product alpha "${run_args[@]}"
	check "journey_needs records journey.needs.THING" has $'alpha\tstart\tfail\tjourney.needs.hand-written-sql' "$out/cells.tsv"

	begin_case poll-runs-out
	drive 1 CELL_alpha=poll:call -- --product alpha "${run_args[@]}"
	check "journey_poll gives up after its seconds and says so" has "did not succeed within 2 seconds" "$out/alpha/call.stderr"
	check "the step then fails with the journey's code" has $'alpha\tcall\tfail\tproduct.poll.timed-out' "$out/cells.tsv"

	begin_case harness-failure
	drive 3 CELL_beta=harness:call -- "${run_args[@]}" --expected "$table"
	check "a harness failure is named" has "harness failure: a harness failure the test asked for" "$last_err"
	check "and never recorded as a product outcome" no_file "$out/summary.json"
	check_equal "run.json records it" "a harness failure the test asked for" "$(json '.harnessFailure' "$out/run.json")"
}

case_discipline() {
	local violation
	begin_case cell-discipline
	for violation in pass-after-fail begin-twice end-without-last unknown-step unresolved unknown-concept \
		unknown-suffix unknown-stage bad-code after-stop unknown-counter library-name missing-cell; do
		drive 3 SCENARIO=discipline DISCIPLINE="$violation" -- --product alpha --bin-dir "$work/bins/debug"
		check "$violation is a journey script error" has "journey script error" "$last_err"
	done
}

case_steps_and_processes() {
	local mode pid
	local -a alpha_args=(--product alpha --bin-dir "$work/bins/debug")
	for mode in sleep stubborn; do
		begin_case "step-timeout-$mode"
		drive 3 SCENARIO=timeout TIMEOUT_MODE="$mode" -- "${alpha_args[@]}"
		check "a step past its deadline is a harness failure" has "did not finish within 1 seconds" "$last_err"
		check "its process is stopped" process_gone "$(contents "$state/alpha.pid")"
		check "its output so far is saved" test -f "$out/alpha/prepare.stdout"
	done

	begin_case processes
	drive 0 SCENARIO=processes -- "${alpha_args[@]}"
	pid="$(contents "$state/alpha.pid")"
	check_equal "the server runs between start and stop" yes "$(value running)"
	check_equal "it stops on SIGTERM with status 0" 0 "$(value stop-status)"
	check "processes.txt records it" has "$pid"$'\talpha\tserver' "$out/processes.txt"
	check "it is gone after the run" process_gone "$pid"
	check "its output is saved" has serving "$out/alpha/start.stdout"
	check "including what it printed on SIGTERM" has stopping "$out/alpha/start.stdout"
	check "a secret it printed is redacted" has "loaded key [redacted:server-key]" "$out/alpha/start.stderr"
	check "no saved output holds the secret" no_secret_in "$out"
	check_equal "journey_process_log names the redacted log" "$out/alpha/start.stderr" "$(value log)"

	begin_case process-ignores-term
	drive 1 SCENARIO=processes PROCESS_MODE=stubborn -- "${alpha_args[@]}"
	check "journey_stop reports a process that had to be killed" has $'alpha\tstop\tfail\tproduct.stop.ignored-signal' "$out/cells.tsv"
	check "it is gone" process_gone "$(contents "$state/alpha.pid")"

	begin_case process-exits-at-once
	drive 1 SCENARIO=processes PROCESS_MODE=exit-now -- "${alpha_args[@]}"
	check_equal "journey_start returns the exit status of a process that stopped" 5 "$(value start-status)"
	check "its output is saved" has "product.start.refused" "$out/alpha/start.stderr"
}

case_assists() {
	local -a alpha_args=(--product alpha --bin-dir "$work/bins/debug")
	local cell

	begin_case assist-used
	drive 1 JOURNEY_ASSISTS_FILE="$work/assists.sh" CELL_alpha=blocker:call:journey.needs.certificate:certificate -- \
		"${alpha_args[@]}" --assist certificate
	cell="$out/alpha/cell.json"
	check_equal "the assist ran with the journey's arguments" "$out/work" "$(contents "$state/assist-ran")"
	check_equal "an assisted cell is not a pass" assisted "$(json '.outcome' "$cell")"
	check_equal "the blocker is recorded" journey.needs.certificate "$(json '.blockers[0].code' "$cell")"
	check_equal "the assist is counted" 1 "$(json '.total.assistsUsed' "$cell")"
	check_equal "a certificate assist counts a certificate" 1 "$(json '.passRule."certificates-made"' "$cell")"
	check "cells.tsv records the step as assisted" has $'alpha\tcall\tassisted\tjourney.needs.certificate' "$out/cells.tsv"
	check_equal "acceptance mode does not pass it" not-passed "$(json '.cells[0].verdict' "$out/summary.json")"

	begin_case assist-not-enabled
	drive 1 JOURNEY_ASSISTS_FILE="$work/assists.sh" CELL_alpha=blocker:call:journey.needs.certificate:certificate -- "${alpha_args[@]}"
	check_equal "without --assist the blocker stops the cell" fail "$(json '.outcome' "$out/alpha/cell.json")"
	check "and the assist does not run" no_file "$state/assist-ran"

	begin_case assist-refusals
	drive 2 JOURNEY_ASSISTS_FILE="$work/assists.sh" -- "${alpha_args[@]}" --assist warp
	check "an assist the file does not define is refused" has "defines no journey_assist_warp" "$last_err"
	drive 2 JOURNEY_ASSISTS_FILE="$work/no-assists.sh" -- "${alpha_args[@]}" --assist certificate
	check "a missing assists file is refused" has "which does not exist" "$last_err"
}

case_files() {
	local cell
	begin_case files
	drive 0 SCENARIO=files -- --product alpha
	cell="$out/alpha/cell.json"
	check_equal "the written file is the reader's text with the edit" $'ab: 1\ncd: 20\nef: 3' "$(contents "$out/work/alpha/alpha.yaml")"
	check_equal "one file is touched" 1 "$(json '.total.filesTouched' "$cell")"
	check_equal "three lines written and one edited" 4 "$(json '.total.linesWritten' "$cell")"
	check_equal "18 characters written and 6 typed in the edit" 24 "$(json '.total.charactersTyped' "$cell")"
	check_equal "both concepts are counted" 'runtime-file issuer' "$(json '.total.concepts | join(" ")' "$cell")"
	check_equal "t1 snapshots the lines written by then" 3 "$(json '.passRule."lines-written-to-t1"' "$cell")"
	check_equal "and the concepts met by then" 1 "$(json '.passRule."concepts-met-to-t1"' "$cell")"
	check_equal "journey_count adds to the errors that say what to change" 2 "$(json '.passRule."errors-that-say-what-to-change"' "$cell")"
	check_equal "and to the identity-provider changes" 1 "$(json '.passRule."identity-provider-changes"' "$cell")"
	check_equal "the reader time to t1 follows the model (18/200 + 3*30/60 + 1*60/60)" 2.59 "$(json '.passRule."reader-time-to-t1-modelled"' "$cell")"
	check_equal "the reader time to t2 follows the model (24/200 + 4*30/60 + 2*60/60)" 4.12 "$(json '.passRule."reader-time-to-t2-modelled"' "$cell")"

	begin_case file-refusals
	drive 3 SCENARIO=files FILES_MODE=outside -- --product alpha
	check "a reader's file outside work/ is refused" has "must be under" "$last_err"
	drive 3 SCENARIO=files FILES_MODE=twice -- --product alpha
	check "an edit whose text occurs twice is refused" has "occurs 2 times" "$last_err"
}

# The tables beside the library, replayed row by row: every product of
# products.yaml has exactly one row per journey, every code is accepted and
# ratchet mode with --strict exits 0.
case_real_tables() {
	local journey
	for journey in own-provider rstack-dev promote; do
		begin_case "real-table-$journey"
		drive 0 TEST_JOURNEY="$journey" SCENARIO=replay JOURNEY_TABLES_DIR= -- --expected "$lib_dir/expected-failures.yaml" --strict
		check "the table names at least one product" test "$(value replayed)" -gt 0
		check_equal "every product has a cell" "$(value replayed)" "$(json '.cells | length' "$out/summary.json")"
		check_equal "every cell equals its row" 0 "$(json '[.cells[] | select(.verdict != "ok")] | length' "$out/summary.json")"
	done
}

cleanup_work() {
	local status=$?
	if [[ -n "$launched" ]]; then
		kill -KILL -- "-$launched" 2>/dev/null || :
	fi
	if [[ "${TEST_LIB_KEEP:-0}" == 1 ]]; then
		printf 'test_lib: kept %s\n' "$work" >&2
		exit "$status"
	fi
	case "$work" in
	"$tmp_root"/journey-lib-test.??????) ;;
	*)
		printf 'test_lib: refusing to delete %s\n' "$work" >&2
		exit 3
		;;
	esac
	if ! rm -r -- "$work"; then
		printf 'test_lib: could not delete %s; delete it by hand\n' "$work" >&2
		[[ $status -ne 0 ]] || status=3
	fi
	exit "$status"
}

test_main() {
	local tool
	lib="${JOURNEY_LIB_UNDER_TEST:-${self%/*}/lib.sh}"
	if [[ ! -f "$lib" ]]; then
		printf 'test_lib: no library at %s\n' "$lib" >&2
		exit 2
	fi
	lib="$(CDPATH='' cd -- "$(dirname -- "$lib")" && pwd -P)/${lib##*/}"
	lib_dir=${lib%/*}
	root="$(CDPATH='' cd -- "$lib_dir/../../.." && pwd -P)"
	for tool in jq perl python3; do
		if ! command -v "$tool" >/dev/null 2>&1; then
			printf 'test_lib: needs %s on PATH\n' "$tool" >&2
			exit 2
		fi
	done
	tmp_root="$(CDPATH='' cd -- "${TMPDIR:-/tmp}" && pwd -P)"
	work="$(mktemp -d "$tmp_root/journey-lib-test.XXXXXX")"
	trap cleanup_work EXIT
	chmod 700 "$work"
	test_path="$work/bin:$work/tools:/usr/bin:/bin:/usr/sbin:/sbin"
	write_fixtures
	# From here the test itself uses the same commands as the journeys it runs.
	PATH=$test_path
	printf 'test_lib: bash %s, library %s\n' "$BASH_VERSION" "$lib"
	case_usage
	case_binaries
	case_run_directories
	case_containers
	case_keep_and_take_over
	case_interrupts
	case_secrets
	case_http
	case_modes
	case_discipline
	case_steps_and_processes
	case_assists
	case_files
	case_real_tables
	finish_case
	if [[ $failed_checks -gt 0 ]]; then
		printf 'test_lib: %s of %s checks failed\n' "$failed_checks" "$checks"
		exit 1
	fi
	printf 'test_lib: all %s checks passed\n' "$checks"
}

case "${1:-}" in
--fake)
	shift
	fake_main "$@"
	;;
--driver)
	shift
	# shellcheck source=/dev/null
	source "${JOURNEY_LIB_UNDER_TEST:?}"
	driver_main "$@"
	;;
*)
	test_main "$@"
	;;
esac
