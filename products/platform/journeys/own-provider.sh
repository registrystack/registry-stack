#!/usr/bin/env bash
# The own-provider acceptance journey: each product from its starter to a first
# authenticated call against an identity provider and a PostgreSQL server the
# reader already runs. Here those are a stock Keycloak with the realm in
# keycloak/realm.json and a stock PostgreSQL with no TLS and no init SQL.
#
# Steps, as the pass rule counts them: prepare, issuer, database.provision,
# database.connect, start, ready, token, call, hook, stop. A cell is one
# product and stops at its first failing step. See README.md for the options,
# the two modes and the exit codes.
#
# What this script starts: two containers on the default bridge, named by
# lib.sh, with ports published on 127.0.0.1 only.
#   kc  Keycloak, the image products.yaml names (ownProviderIssuer), started
#       with `start-dev --import-realm` on keycloak/realm.json
#   pg  postgres:18.7 by digest, started only when a selected product keeps a
#       database
# Products run as host processes from --bin-dir. With JOURNEY_PORT_BASE the
# containers take the first ports and each product listens on base+4 (API) and
# base+5 (metrics), one product at a time.
#
# The reader's identity provider. realm.json holds, for every product that
# verifies a token, one confidential caller client with a service account, one
# API client whose client id is the product's audience, and the client role
# that makes Keycloak's stock audience resolution put that audience in `aud`.
# It holds no protocol mappers and no client scopes: an import that lists
# client scopes drops Keycloak's default ones. Each product's scope is created
# through the admin API at setup and made a default scope of its caller. A
# claim Keycloak gives only through a mapper is a journey.needs.claim-mapper
# stop, never a mapper here. Each product counts three identity-provider
# changes: its caller client, its audience and its scope.
#
# What the harness does that the reader does not type, and so is not counted:
# - the secret folder of every product is the run's secrets/ folder, so each
#   secret:file reference is renamed with the product id as a prefix, and a
#   secret root that init already placed beside the project is moved there
# - the secret files the runtime file names: random keys, the two PostgreSQL
#   URLs with their role passwords and the administrator URL. lib.sh counts
#   only files under work/, so these files are not counted; the step that
#   introduces them declares the secret-file concept
# - free ports, when JOURNEY_PORT_BASE is not set
#
# Assists (lib-assists.sh, --assist) are called with these arguments:
#   sql PRODUCT ADMIN_URL_FILE MIGRATION_URL_FILE RUNTIME_URL_FILE
#       at database.provision: make the database, the two roles and the grants
#       the two URLs name. The journey then goes on to database.connect.
#   certificate PRODUCT RUNTIME_FILE
#       at database.provision, database.connect or start, where the product
#       refuses PostgreSQL without TLS: give the pg container a certificate
#       and the runtime file its CA. The journey then runs the step again.
#   mapper PRODUCT CLIENT TOKEN_VARIABLE CLAIM...
#       at call: add the mappers for the claims the token lacks and set a
#       fresh token, registered as a secret, in TOKEN_VARIABLE. The journey
#       then makes the call again.
# keycloak_admin_login and keycloak_admin below are there for the assists.
#
# Run directory: everything lib.sh writes (run.json, cells.tsv, summary.json,
# <product>/cell.json and step output, containers.txt, processes.txt,
# containers/, work/, secrets/ and, with --keep, the kept marker). On top of
# it: work/<product>/<product>/ is the project, work/<product>/package/ its
# package and own-provider.json the issuer, realm, ports and container roles of
# the run. With --keep the containers, secrets/ and the files this script
# wrote there stay for `promote --from`, and so do the development keys
# evidencectl init writes into work/evidence/evidence/.generated/secrets/.
# Without --keep cleanup deletes those keys with the rest of the secrets.
#
# Run it from anywhere:
#   products/platform/journeys/own-provider.sh --bin-dir DIR [--product ID]...
#     [--issuer keycloak] [--out DIR] [--expected FILE [--strict]] [--keep]
#     [--assist LIST]

set -euo pipefail

# shellcheck disable=SC1091 # lib.sh is checked on its own
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

journey_init own-provider --value-option issuer -- "$@"

REALM=registry-journey
POSTGRES_IMAGE=postgres:18.7@sha256:2ea8630df176ad090ec92136dee850397c5af8781e4bcf2e4162593691c61bbc
PROJECTS_DIR=$JOURNEY_LIB_DIR/projects
SECRETS=$JOURNEY_OUT/secrets
# The stages the shared verifier logs (AuthenticationStage in
# registry-platform-oidc), the same list as authenticationStages in the table.
STAGES=' header algorithm token-type key signature issuer audience time client scope profile unavailable '
# Every product a token reaches. The realm names a caller client for each, so
# every one of their client secrets is generated even when fewer are selected.
TOKEN_PRODUCTS='breg casework messaging scheduling documents coordinator adapter evidence render'

# ---------------------------------------------------------------------------
# The issuer the run uses

journey_option_value issuer ISSUER_KIND
ISSUER_KIND=${ISSUER_KIND:-keycloak}
[[ "$ISSUER_KIND" == keycloak ]] ||
	journey_usage_error "--issuer $ISSUER_KIND: this journey starts only keycloak, the provider products.yaml names"

# products.yaml names the provider and its image at the top level, which
# journey_product_field does not read, so it is read here with the same core
# Perl YAML reader lib.sh uses.
ISSUER_LINE=$(perl -MCPAN::Meta::YAML -e '
	my $docs = CPAN::Meta::YAML->read($ARGV[0]) or die CPAN::Meta::YAML->errstr . "\n";
	my $issuer = $docs->[0]{ownProviderIssuer} or die "$ARGV[0] has no ownProviderIssuer\n";
	print "$issuer->{name}\t$issuer->{image}\n";' "$JOURNEY_TABLES_DIR/products.yaml") ||
	journey_usage_error "cannot read ownProviderIssuer from $JOURNEY_TABLES_DIR/products.yaml"
[[ "${ISSUER_LINE%%$'\t'*}" == "$ISSUER_KIND" ]] ||
	journey_usage_error "products.yaml names the provider ${ISSUER_LINE%%$'\t'*}, not $ISSUER_KIND"
KEYCLOAK_IMAGE=${ISSUER_LINE#*$'\t'}

journey_require_docker
journey_set_address_class loopback

# ---------------------------------------------------------------------------
# Small helpers

# field PRODUCT FIELD: a products.yaml field on stdout.
field() {
	local value
	journey_product_field "$1" "$2" value
	printf '%s' "$value"
}

upper() {
	printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_'
}

# free_port VAR: a loopback port nothing listens on now.
free_port() {
	local _kc_port
	_kc_port=$(perl -MIO::Socket::INET -e '
		my $socket = IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => 0, Proto => "tcp", Listen => 1)
		  or die "cannot bind a loopback port: $!\n";
		print $socket->sockport, "\n";') || journey_harness_failure "cannot find a free loopback port"
	printf -v "$1" '%s' "$_kc_port"
}

# port_is_free PORT
port_is_free() {
	perl -MIO::Socket::INET -e '
		IO::Socket::INET->new(LocalAddr => "127.0.0.1", LocalPort => $ARGV[0], Proto => "tcp", Listen => 1, ReuseAddr => 1)
		  or exit 1;' "$1"
}

# tcp_open PORT: something accepts a connection on 127.0.0.1:PORT.
tcp_open() {
	perl -MIO::Socket::INET -e '
		IO::Socket::INET->new(PeerAddr => "127.0.0.1", PeerPort => $ARGV[0], Proto => "tcp", Timeout => 2)
		  or exit 1;' "$1"
}

# copy_file SOURCE TARGET: what `cp` does for one text file, in bash.
copy_file() {
	local text
	text=$(<"$1")
	printf '%s\n' "$text" >"$2"
}

# copy_files DIRECTORY SOURCE...: `cp SOURCE... DIRECTORY` for text files.
copy_files() {
	local directory=$1 source
	shift
	mkdir -p -- "$directory"
	for source in "$@"; do
		copy_file "$source" "$directory/${source##*/}"
	done
}

# fill_template FILE NAME=VALUE...: FILE without its comment lines, with each
# @NAME@ replaced. A placeholder left unfilled is a journey script error.
fill_template() {
	perl -e '
		my ($path, @pairs) = @ARGV;
		my %value = map { my ($k, $v) = split /=/, $_, 2; ($k, $v) } @pairs;
		open my $in, "<", $path or die "cannot read $path: $!\n";
		while (my $line = <$in>) {
			next if $line =~ /^\s*#/;
			$line =~ s/\@([A-Z]+)\@/exists $value{$1} ? $value{$1} : die "$path: no value for \@$1\@\n"/ge;
			print $line;
		}' "$@" || journey_harness_failure "journey script error: cannot fill the template $1"
}

# edit FILE SEARCH REPLACE [CONCEPTS]: an edit the reader makes by hand.
edit() {
	if [[ -n "${4:-}" ]]; then
		journey_edit_file "$1" "$2" "$3" --concepts "$4"
	else
		journey_edit_file "$1" "$2" "$3"
	fi
}

# harness_edit FILE SEARCH REPLACE: an edit the harness makes for its own
# layout and does not count. SEARCH must occur exactly once.
harness_edit() {
	perl -e '
		my ($path, $search, $replace) = @ARGV;
		open my $in, "<:raw", $path or die "cannot read $path: $!\n";
		local $/; my $text = <$in>; close $in;
		my $count = () = $text =~ /\Q$search\E/g;
		die "the text to replace occurs $count times in $path; it must occur once\n" if $count != 1;
		substr($text, index($text, $search), length $search) = $replace;
		open my $out, ">:raw", $path or die "cannot write $path: $!\n";
		print {$out} $text; close $out or die "cannot write $path: $!\n";' "$@" ||
		journey_harness_failure "journey script error: cannot edit $1"
}

# prefix_secret_references PRODUCT FILE: rename every secret:file reference
# outside a comment to PRODUCT-NAME, so ten products share one secret folder.
prefix_secret_references() {
	perl -i -pe '
		BEGIN { $product = shift @ARGV }
		next if /^\s*#/;
		s{secret:file/(?!\Q$product\E-)}{secret:file/$product-}g;' "$1" "$2" ||
		journey_harness_failure "cannot rename the secret references in $2"
}

# secret_references FILE: the secret:file names FILE uses outside comments.
secret_references() {
	perl -ne 'next if /^\s*#/; print "$1\n" while m{secret:file/([A-Za-z0-9._-]+)}g' "$1" | sort -u
}

# ---------------------------------------------------------------------------
# Secret files this script writes itself

# lib.sh generates random secrets and deletes what it generated. A PostgreSQL
# URL is not random text, so this script writes those files into secrets/ and
# deletes them in its own cleanup hook, before lib.sh removes the folder. With
# --keep they stay, and the run that takes this one over adopts them.
OWN_SECRET_FILES=()

# write_own_secret NAME VALUE_VARIABLE: write the value of a shell variable
# into secrets/NAME with mode 0600. The value is read by name.
write_own_secret() {
	local name=$1 variable=$2 path
	path=$SECRETS/$name
	[[ ! -e "$path" ]] || journey_harness_failure "journey script error: secret file $name already exists"
	(
		umask 077
		printf '%s' "${!variable}" >"$path"
	) || journey_harness_failure "cannot write secret file $name"
	OWN_SECRET_FILES+=("$path")
}

remove_own_secret_files() {
	local path status=0
	[[ $JOURNEY_KEEP -eq 0 ]] || return 0
	for path in ${OWN_SECRET_FILES[@]+"${OWN_SECRET_FILES[@]}"}; do
		if [[ -e "$path" ]] && ! rm -- "$path"; then
			printf 'cannot delete %s\n' "$path" >&2
			status=1
		fi
	done
	return "$status"
}
journey_at_cleanup remove_own_secret_files

# Key folders a product's own init writes inside the reader's project
# (evidencectl init --profile local generates its development keys into
# .generated/secrets/). lib.sh's secret scan skips work/, so cleanup deletes
# the files of each folder named here and the folder itself, as it does the
# run's secrets/. With --keep they stay.
PRODUCT_KEY_DIRS=()

remove_product_key_dirs() {
	local directory path status=0
	[[ $JOURNEY_KEEP -eq 0 ]] || return 0
	for directory in ${PRODUCT_KEY_DIRS[@]+"${PRODUCT_KEY_DIRS[@]}"}; do
		[[ -d "$directory" ]] || continue
		for path in "$directory"/* "$directory"/.[!.]*; do
			[[ -e "$path" || -L "$path" ]] || continue
			if [[ -d "$path" && ! -L "$path" ]]; then
				printf 'cannot delete %s: a folder inside a product key folder\n' "$path" >&2
				status=1
			elif ! rm -- "$path"; then
				printf 'cannot delete %s\n' "$path" >&2
				status=1
			fi
		done
		if ! rmdir -- "$directory"; then
			printf 'cannot delete %s\n' "$directory" >&2
			status=1
		fi
	done
	return "$status"
}
journey_at_cleanup remove_product_key_dirs

# read_secret NAME VAR: the value of a generated secret into VAR.
read_secret() {
	local _kc_path
	journey_secret_path "$1" _kc_path
	IFS= read -r "$2" <"$_kc_path" || [[ -n "${!2}" ]] || journey_harness_failure "cannot read secret $1"
}

# ---------------------------------------------------------------------------
# The reader's identity provider and PostgreSQL server

KC_PORT=''
KC_URL=''
KC_ISSUER=''
PG_PORT=''
ADMIN_URL_FILE=''
KC_ADMIN_TOKEN=''
KC_STATUS=''
KC_BODY=''
COORDINATOR_SUBJECT=''

# keycloak_admin_login: an administrator token of the master realm into
# KC_ADMIN_TOKEN, registered as a secret. The password reaches curl as a file.
keycloak_admin_login() {
	local password_file response token
	journey_secret_path keycloak-admin password_file
	response=$(curl --silent --show-error --max-time 30 \
		--data grant_type=password --data client_id=admin-cli --data username=admin \
		--data-urlencode "password@$password_file" \
		"$KC_URL/realms/master/protocol/openid-connect/token") ||
		journey_harness_failure "the Keycloak administrator login did not answer"
	token=$(printf '%s' "$response" | jq -r '.access_token // empty') ||
		journey_harness_failure "the Keycloak administrator login answered something that is not JSON"
	if [[ -z "$token" ]]; then
		journey_harness_failure "the Keycloak administrator login was refused: $(printf '%s' "$response" | jq -c '{error, error_description}')"
	fi
	KC_ADMIN_TOKEN=$token
	journey_secret_register keycloak-admin-token KC_ADMIN_TOKEN
}

# keycloak_admin METHOD PATH [JSON]: one admin API request on the journey's
# realm. Sets KC_STATUS and KC_BODY. The token reaches curl through a file
# descriptor.
keycloak_admin() {
	local method=$1 path=$2 body=${3:-} response
	local -a data=()
	if [[ -n "$body" ]]; then
		data=(--header 'Content-Type: application/json' --data-binary "$body")
	fi
	response=$(curl --silent --show-error --max-time 30 -X "$method" \
		-H "@"<(printf 'Authorization: Bearer %s\n' "$KC_ADMIN_TOKEN") \
		${data[@]+"${data[@]}"} --write-out '\n%{http_code}' \
		"$KC_URL/admin/realms/$REALM$path") ||
		journey_harness_failure "the Keycloak admin API did not answer $method $path"
	KC_STATUS=${response##*$'\n'}
	KC_BODY=${response%$'\n'*}
}

# keycloak_client_uuid CLIENT_ID VAR. Its locals start with _kc_ so that a
# caller's VAR is never one of them.
keycloak_client_uuid() {
	local _kc_encoded _kc_uuid
	_kc_encoded=$(jq -rn --arg value "$1" '$value | @uri')
	keycloak_admin GET "/clients?clientId=$_kc_encoded"
	[[ "$KC_STATUS" == 200 ]] || journey_harness_failure "Keycloak cannot list client $1 (HTTP $KC_STATUS)"
	_kc_uuid=$(printf '%s' "$KC_BODY" | jq -r --arg id "$1" 'first(.[] | select(.clientId == $id) | .id) // empty')
	[[ -n "$_kc_uuid" ]] || journey_harness_failure "the realm has no client $1; see keycloak/realm.json"
	printf -v "$2" '%s' "$_kc_uuid"
}

# keycloak_default_scope CLIENT_ID SCOPE: create SCOPE, included in the
# token's scope claim, and make it a default scope of CLIENT_ID.
keycloak_default_scope() {
	local client=$1 scope=$2 uuid scope_id body
	body=$(jq -cn --arg name "$scope" \
		'{name: $name, protocol: "openid-connect", attributes: {"include.in.token.scope": "true", "display.on.consent.screen": "false"}}')
	keycloak_admin POST /client-scopes "$body"
	[[ "$KC_STATUS" == 201 || "$KC_STATUS" == 409 ]] ||
		journey_harness_failure "Keycloak refused to create client scope $scope (HTTP $KC_STATUS)"
	keycloak_admin GET /client-scopes
	[[ "$KC_STATUS" == 200 ]] || journey_harness_failure "Keycloak cannot list client scopes (HTTP $KC_STATUS)"
	scope_id=$(printf '%s' "$KC_BODY" | jq -r --arg name "$scope" 'first(.[] | select(.name == $name) | .id) // empty')
	[[ -n "$scope_id" ]] || journey_harness_failure "Keycloak lists no client scope $scope after creating it"
	keycloak_client_uuid "$client" uuid
	keycloak_admin PUT "/clients/$uuid/default-client-scopes/$scope_id"
	[[ "$KC_STATUS" == 204 ]] ||
		journey_harness_failure "Keycloak refused to add scope $scope to client $client (HTTP $KC_STATUS)"
}

# keycloak_service_account_subject CLIENT_ID VAR: the `sub` of the client's
# service account, which a Coordinator policy names.
keycloak_service_account_subject() {
	local _kc_client _kc_subject
	keycloak_client_uuid "$1" _kc_client
	keycloak_admin GET "/clients/$_kc_client/service-account-user"
	[[ "$KC_STATUS" == 200 ]] || journey_harness_failure "Keycloak has no service account for $1 (HTTP $KC_STATUS)"
	_kc_subject=$(printf '%s' "$KC_BODY" | jq -r '.id // empty')
	[[ -n "$_kc_subject" ]] || journey_harness_failure "the service account of $1 has no id"
	printf -v "$2" '%s' "$_kc_subject"
}

start_keycloak() {
	local product env_name
	local -a secret_envs=()
	journey_secret_new keycloak-admin 24
	for product in $TOKEN_PRODUCTS; do
		journey_secret_new "client-$product" 24
		env_name="JOURNEY_CLIENT_SECRET_$(upper "$product")"
		secret_envs+=(--secret-env "$env_name=client-$product")
	done
	journey_container_run kc --port 8080 \
		--env=KC_BOOTSTRAP_ADMIN_USERNAME=admin \
		--secret-env KC_BOOTSTRAP_ADMIN_PASSWORD=keycloak-admin "${secret_envs[@]}" \
		-v "$JOURNEY_LIB_DIR/keycloak:/opt/keycloak/data/import:ro" -- \
		"$KEYCLOAK_IMAGE" start-dev --import-realm
	journey_container_port kc 8080 KC_PORT
	KC_URL=http://127.0.0.1:$KC_PORT
	KC_ISSUER=$KC_URL/realms/$REALM
	journey_container_wait kc 240 -- curl --silent --fail --output /dev/null \
		"$KC_ISSUER/.well-known/openid-configuration"
}

start_postgres() {
	# shellcheck disable=SC2034 # url is read by name in write_own_secret
	local password url
	journey_secret_new postgres-password 24
	journey_container_run pg --port 5432 --secret-env POSTGRES_PASSWORD=postgres-password -- "$POSTGRES_IMAGE"
	journey_container_port pg 5432 PG_PORT
	journey_container_wait pg 90 -- tcp_open "$PG_PORT"
	read_secret postgres-password password
	url="postgresql://postgres:$password@127.0.0.1:$PG_PORT/postgres"
	write_own_secret postgres-admin-url url
	ADMIN_URL_FILE=$SECRETS/postgres-admin-url
}

# ---------------------------------------------------------------------------
# Recipes: what each product's reader uses

# recipe PRODUCT: sets TOOL (the product's tool), SERVER (its runtime binary),
# CLIENT, AUDIENCE and SCOPE (the reader's provider), READY_PATH, CALL_METHOD
# and CALL_PATH (the first authenticated request) and CLAIMS (claims beyond the
# OIDC core the product reads from a service token).
recipe() {
	local product=$1
	SERVER=$(field "$product" binary)
	CLAIMS=''
	READY_PATH=/ready
	CALL_METHOD=GET
	case "$product" in
	breg)
		TOOL=bregctl CLIENT=directory-client AUDIENCE=urn:breg:local-directory SCOPE=registry:directory:write
		CALL_PATH=/v1/records/contacts CLAIMS='registry_principal registry_purpose'
		;;
	casework)
		TOOL=caseworkctl CLIENT=casework-client AUDIENCE=urn:example:casework SCOPE=casework:staff
		CALL_PATH=/v1/review-policies
		;;
	messaging)
		TOOL=messagingctl CLIENT=case-system AUDIENCE=urn:example:messaging SCOPE=messaging:send
		CALL_METHOD=POST CALL_PATH=/v1/messages
		;;
	scheduling)
		TOOL=schedulingctl CLIENT=scheduling-booking-agent AUDIENCE=urn:example:scheduling SCOPE=scheduling:read
		READY_PATH=/readyz CALL_PATH=/v1/locations CLAIMS=registry_actor_kind
		;;
	documents)
		TOOL=documentsctl CLIENT=case-portal AUDIENCE=urn:example:documents SCOPE=documents:read
		CALL_PATH=/v1/document-policies
		;;
	coordinator)
		TOOL=coordinatorctl CLIENT=coordinator-producer AUDIENCE=urn:example:coordinator SCOPE=coordinator:start
		CALL_PATH=/v1/workflows/coordinator
		;;
	adapter)
		TOOL=adapterctl CLIENT=registry-adapter-example-client AUDIENCE=registry-adapter-example SCOPE=records.write
		CALL_PATH=/v1/records/person
		;;
	evidence)
		TOOL=evidencectl CLIENT=evidence-client AUDIENCE=urn:example:audience:local-evidence SCOPE=evidence:request
		CALL_PATH=/v1/evidence-definitions CLAIMS='evidence_audience evidence_tags'
		;;
	render)
		TOOL=registry-render CLIENT=portal AUDIENCE=urn:example:render SCOPE=render:render
		CALL_METHOD=POST CALL_PATH=/v1/render/letter
		;;
	*) journey_harness_failure "no recipe is written for product $product; add one to recipe in own-provider.sh" ;;
	esac
	journey_bin "$TOOL" TOOL_BIN
	journey_bin "$SERVER" SERVER_BIN
}

# ---------------------------------------------------------------------------
# Outcomes

# The open cell's product, its folders and its runtime file, and whether the
# cell has stopped.
CELL=''
CELL_OVER=0
WORK=''
PROJECT=''
RUNTIME_FILE=''
PORT=''
METRICS_PORT=''
ACCESS_TOKEN=''
MIGRATION_URL_FILE=''
RUNTIME_URL_FILE=''
SERVER_LOG_OUT=''
SERVER_LOG_ERR=''

# harness_places_secrets PRODUCT: the harness puts the product's secret files in
# secrets/. Evidence's init generates its own local keys beside the project and
# its target names them there, so they are left where init put them.
harness_places_secrets() {
	[[ "$1" != evidence ]]
}

# diagnostic_code FILE...: the code a product printed in any FILE: the code
# nested in the first diagnostic's message as error[code], else that
# diagnostic's code, else a JSON error code, else a human error[code] line.
diagnostic_code() {
	local file code=''
	for file in "$@"; do
		[[ -s "$file" ]] || continue
		code=$(jq -r '(first(.diagnostics[]?)
			| ((.message // "") | [match("error\\[([a-z0-9._-]+)\\]").captures[0].string] | first) // .code)
			// .error.code // empty' "$file" 2>/dev/null) || code=''
		if [[ -z "$code" ]]; then
			code=$(perl -ne 'if (/^error\[([a-z0-9._-]+)\]/) { print $1; last }' "$file")
		fi
		[[ -z "$code" ]] || break
	done
	printf '%s' "$code"
}

# stop_with_product_code STEP FILE...: the cell stops at STEP with the code the
# product printed. A refusal that prints no code is a harness failure: the
# journey would otherwise invent one.
stop_with_product_code() {
	local step=$1 code
	shift
	code=$(diagnostic_code "$@")
	[[ -n "$code" ]] || journey_harness_failure "step $step of $CELL failed and printed no diagnostic code; see $*"
	[[ "$code" =~ ^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)*$ ]] ||
		journey_harness_failure "step $step of $CELL printed the code '$code', which no table code form can hold; see $*"
	journey_fail "$step" "product.$code"
	CELL_OVER=1
}

# reader_command STEP [STEP OPTIONS] -- COMMAND...: one command of STEP. A
# refusal stops the cell with the product's code.
reader_command() {
	local step=$1 status=0
	shift
	journey_step "$step" "$@" || status=$?
	if [[ $status -ne 0 ]]; then
		stop_with_product_code "$step" "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"
	fi
}

# mentions_tls FILE...: the output names TLS, SSL or a certificate.
mentions_tls() {
	perl -e '
		local $/;
		for my $path (@ARGV) {
			open my $fh, "<", $path or next;
			my $text = <$fh>;
			exit 0 if defined $text && $text =~ /\b(?:tls|ssl|sslmode)\b|certificate/i;
		}
		exit 1;' "$@"
}

# unrecognized_subcommand FILE...: the tool has no such command, in clap's
# words or in a tool's own usage diagnostic.
unrecognized_subcommand() {
	perl -e '
		local $/;
		for my $path (@ARGV) {
			open my $fh, "<", $path or next;
			my $text = <$fh>;
			exit 0 if defined $text && $text =~ /unrecognized (?:sub)?command/;
		}
		exit 1;' "$@"
}

# ---------------------------------------------------------------------------
# The steps

# prepare: the product's starter, its package and its runtime file, with the
# paths and ports of this machine.
step_prepare() {
	local product=$1 package=$WORK/package digest workflow block
	case "$product" in
	breg)
		reader_command prepare --concepts project -- "$TOOL_BIN" init "$PROJECT"
		[[ $CELL_OVER -eq 0 ]] || return 0
		RUNTIME_FILE=$PROJECT/runtime.yaml
		reader_command prepare --concepts runtime-file --typed "cp runtime.example.yaml runtime.yaml" -- \
			copy_file "$PROJECT/runtime.example.yaml" "$RUNTIME_FILE"
		[[ $CELL_OVER -eq 0 ]] || return 0
		edit "$RUNTIME_FILE" "  bind: 127.0.0.1:8080" "  bind: 127.0.0.1:$PORT" listener-bind
		edit "$RUNTIME_FILE" "    root: /var/lib/breg/secrets" "    root: $SECRETS" secret-file
		edit "$RUNTIME_FILE" "  root: /var/lib/breg/package" "  root: $package" package
		edit "$RUNTIME_FILE" "  path: /var/log/breg/audit.jsonl" "  path: $WORK/audit.jsonl"
		;;
	casework)
		reader_command prepare --concepts project -- "$TOOL_BIN" init "$PROJECT"
		[[ $CELL_OVER -eq 0 ]] || return 0
		reader_command prepare --concepts package -- "$TOOL_BIN" package --output "$PROJECT/.casework/package" "$PROJECT"
		[[ $CELL_OVER -eq 0 ]] || return 0
		RUNTIME_FILE=$PROJECT/runtime.yaml
		reader_command prepare --concepts runtime-file --typed "cp runtime.example.yaml runtime.yaml" -- \
			copy_file "$PROJECT/runtime.example.yaml" "$RUNTIME_FILE"
		[[ $CELL_OVER -eq 0 ]] || return 0
		edit "$RUNTIME_FILE" "  bind: 127.0.0.1:8100" "  bind: 127.0.0.1:$PORT" listener-bind
		harness_edit "$RUNTIME_FILE" "    root: $PROJECT/secrets" "    root: $SECRETS"
		;;
	messaging | scheduling | documents)
		if [[ "$product" == scheduling ]]; then
			reader_command prepare --concepts project -- "$TOOL_BIN" init --template standalone-exact-time "$PROJECT"
		else
			reader_command prepare --concepts project -- "$TOOL_BIN" init "$PROJECT"
		fi
		[[ $CELL_OVER -eq 0 ]] || return 0
		reader_command prepare --concepts package -- "$TOOL_BIN" package --output "$package" "$PROJECT"
		[[ $CELL_OVER -eq 0 ]] || return 0
		RUNTIME_FILE=$PROJECT/runtime.yaml
		reader_command prepare --concepts runtime-file --typed "cp runtime.example.yaml runtime.yaml" -- \
			copy_file "$PROJECT/runtime.example.yaml" "$RUNTIME_FILE"
		[[ $CELL_OVER -eq 0 ]] || return 0
		local api metrics
		case "$product" in
		messaging) api=8107 metrics=9107 ;;
		scheduling) api=8105 metrics=9105 ;;
		documents) api=8116 metrics=9116 ;;
		esac
		edit "$RUNTIME_FILE" "  root: /srv/registry-$product/package" "  root: $package" package
		edit "$RUNTIME_FILE" "  bind: 127.0.0.1:$api" "  bind: 127.0.0.1:$PORT" listener-bind
		edit "$RUNTIME_FILE" "  bind: 127.0.0.1:$metrics" "  bind: 127.0.0.1:$METRICS_PORT"
		edit "$RUNTIME_FILE" "    root: /run/secrets/registry-$product" "    root: $SECRETS" secret-file
		edit "$RUNTIME_FILE" "  path: /var/lib/registry-$product/audit.ndjson" "  path: $WORK/audit.ndjson"
		if [[ "$product" == documents ]]; then
			# The starter's listener is the production one, which refuses a
			# loopback HTTP issuer; local development is development-loopback.
			edit "$RUNTIME_FILE" "  tlsTermination: operator-controlled-upstream" "  tlsTermination: development-loopback" \
				tls-termination,posture
		fi
		;;
	coordinator)
		reader_command prepare --concepts project -- "$TOOL_BIN" init --directory "$PROJECT"
		[[ $CELL_OVER -eq 0 ]] || return 0
		reader_command prepare --concepts package -- "$TOOL_BIN" --format json package --project "$PROJECT" --output "$package"
		[[ $CELL_OVER -eq 0 ]] || return 0
		digest=$(jq -er '.packageDigest' "$JOURNEY_STEP_STDOUT") ||
			journey_harness_failure "the coordinatorctl package report names no packageDigest; see $JOURNEY_STEP_STDOUT"
		workflow=$(perl -ne 'if (/^  id: (\S+)/) { print $1; last }' "$PROJECT/workflow.yaml")
		[[ -n "$workflow" ]] || journey_harness_failure "cannot read the workflow id from $PROJECT/workflow.yaml"
		RUNTIME_FILE=$PROJECT/runtime.yaml
		harness_edit "$RUNTIME_FILE" "    root: $PROJECT/.coordinator/secrets" "    root: $SECRETS"
		edit "$RUNTIME_FILE" "  runtimeUrlRef: secret:env/COORDINATOR_TEST_DATABASE_URL" \
			"  runtimeUrlRef: secret:file/runtime-database-url" database-url,secret-file
		edit "$RUNTIME_FILE" "  migrationUrlRef: secret:env/COORDINATOR_TEST_DATABASE_URL" \
			"  migrationUrlRef: secret:file/migration-database-url"
		block=$(fill_template "$PROJECTS_DIR/coordinator/deployment.yaml" \
			"PACKAGE=$package" "DIGEST=$digest" "PORT=$PORT" "SUBJECT=$COORDINATOR_SUBJECT" \
			"WORKFLOW=$workflow" "WORK=$WORK")
		edit "$RUNTIME_FILE" $'\nconnections:\n' $'\n'"$block"$'\nconnections:\n' \
			package,listener-bind,tls-termination,audience,scope-claim,access-profile,required-scopes,database-role
		;;
	adapter)
		local example=$JOURNEY_ROOT/products/adapter/examples/facade-recovery
		reader_command prepare --concepts project --typed "cp products/adapter/examples/facade-recovery/*.yaml $PROJECT" -- \
			copy_files "$PROJECT" "$example/project.yaml" "$example/pack.yaml" "$example/fixture.yaml" "$example/runtime.example.yaml"
		[[ $CELL_OVER -eq 0 ]] || return 0
		RUNTIME_FILE=$PROJECT/runtime.yaml
		reader_command prepare --concepts runtime-file --typed "cp runtime.example.yaml runtime.yaml" -- \
			copy_file "$PROJECT/runtime.example.yaml" "$RUNTIME_FILE"
		[[ $CELL_OVER -eq 0 ]] || return 0
		edit "$RUNTIME_FILE" "  bind: 127.0.0.1:8080" "  bind: 127.0.0.1:$PORT" listener-bind
		;;
	evidence)
		PRODUCT_KEY_DIRS+=("$PROJECT/.generated/secrets")
		reader_command prepare --concepts project -- "$TOOL_BIN" init --profile local --transport sqlite-extract "$PROJECT"
		[[ $CELL_OVER -eq 0 ]] || return 0
		RUNTIME_FILE=$PROJECT/local-target.yaml
		;;
	render)
		reader_command prepare --concepts project -- "$TOOL_BIN" init "$PROJECT"
		[[ $CELL_OVER -eq 0 ]] || return 0
		reader_command prepare --concepts package -- "$TOOL_BIN" package --bundle "$PROJECT" --output "$package"
		[[ $CELL_OVER -eq 0 ]] || return 0
		RUNTIME_FILE=$WORK/runtime.yaml
		journey_write_file "$RUNTIME_FILE" --concepts runtime-file,listener-bind,package,audience,allowed-clients < <(
			fill_template "$PROJECTS_DIR/render/runtime.yaml" "PORT=$PORT" "WORK=$WORK"
		)
		;;
	esac
	if harness_places_secrets "$product"; then
		prefix_secret_references "$product" "$RUNTIME_FILE"
	fi
	journey_pass prepare
}

# issuer: point the runtime file at the reader's own provider, then the
# product's offline check.
step_issuer() {
	local product=$1
	journey_count identity-provider-changes 3
	case "$product" in
	breg)
		edit "$RUNTIME_FILE" "    issuer: https://issuer.example.com" "    issuer: $KC_ISSUER" issuer-url
		edit "$RUNTIME_FILE" "    allowedAlgorithm: EdDSA" "    allowedAlgorithm: RS256"
		reader_command issuer -- "$TOOL_BIN" --format json check "$PROJECT" --runtime-config "$RUNTIME_FILE"
		;;
	casework)
		edit "$RUNTIME_FILE" "    issuer: https://identity.example.test" "    issuer: $KC_ISSUER" issuer-url
		reader_command issuer -- "$TOOL_BIN" --format json check "$PROJECT" --runtime-config "$RUNTIME_FILE"
		;;
	messaging | documents)
		edit "$RUNTIME_FILE" "    issuer: https://identity.example.test/realms/registry" "    issuer: $KC_ISSUER" issuer-url
		reader_command issuer -- "$TOOL_BIN" --format json check --runtime-config "$RUNTIME_FILE"
		;;
	scheduling)
		edit "$RUNTIME_FILE" "    issuer: https://identity.example.test/realms/registry" "    issuer: $KC_ISSUER" issuer-url
		reader_command issuer -- "$TOOL_BIN" --format json check "$PROJECT" --runtime-config "$RUNTIME_FILE"
		;;
	coordinator)
		edit "$RUNTIME_FILE" "    issuer: https://identity.example.test/realms/registry" "    issuer: $KC_ISSUER" issuer-url
		reader_command issuer -- "$TOOL_BIN" --format json --runtime-config "$RUNTIME_FILE" check --project "$PROJECT"
		;;
	adapter)
		edit "$RUNTIME_FILE" "  issuer: https://issuer.example.invalid" "  issuer: $KC_ISSUER" issuer-url
		reader_command issuer -- "$TOOL_BIN" --format json check "$PROJECT/project.yaml" \
			--profile "$JOURNEY_ROOT/products/adapter/profiles/breg-records/profile.yaml" \
			--pack "$PROJECT/pack.yaml" --runtime "$RUNTIME_FILE"
		;;
	evidence)
		edit "$RUNTIME_FILE" "    issuer: http://127.0.0.1:8081" "    issuer: $KC_ISSUER" issuer-url
		edit "$RUNTIME_FILE" "      uri: http://127.0.0.1:8081/oauth2/jwks" \
			"      uri: $KC_ISSUER/protocol/openid-connect/certs" jwks-uri
		edit "$RUNTIME_FILE" "      - ES256" "      - RS256"
		reader_command issuer -- "$TOOL_BIN" check "$PROJECT" --target "$RUNTIME_FILE" --format json
		;;
	render)
		edit "$RUNTIME_FILE" "    issuer: https://identity.example.test/realms/registry" "    issuer: $KC_ISSUER" issuer-url
		reader_command issuer -- "$TOOL_BIN" check --runtime-config "$RUNTIME_FILE" --format json
		;;
	esac
	[[ $CELL_OVER -eq 0 ]] || return 0
	journey_pass issuer
}

# write_product_secrets PRODUCT: the secret files the runtime file names. The
# two PostgreSQL URLs carry role names, passwords and the database the
# product's provisioning makes; every other reference gets random bytes.
write_product_secrets() {
	# shellcheck disable=SC2034 # url is read by name in write_own_secret
	local product=$1 name password url bytes
	harness_places_secrets "$product" || return 0
	if [[ "$(field "$product" usesPostgres)" == true ]]; then
		journey_secret_new "$product-migration-password" 24
		journey_secret_new "$product-runtime-password" 24
		read_secret "$product-migration-password" password
		url="postgresql://${product}_migration:$password@127.0.0.1:$PG_PORT/$product"
		write_own_secret "$product-migration-database-url" url
		read_secret "$product-runtime-password" password
		# shellcheck disable=SC2034 # read by name in write_own_secret
		url="postgresql://${product}_runtime:$password@127.0.0.1:$PG_PORT/$product"
		write_own_secret "$product-runtime-database-url" url
		MIGRATION_URL_FILE=$SECRETS/$product-migration-database-url
		RUNTIME_URL_FILE=$SECRETS/$product-runtime-database-url
	fi
	while IFS= read -r name; do
		[[ -n "$name" && ! -e "$SECRETS/$name" ]] || continue
		[[ "$name" == "$product-"* ]] ||
			journey_harness_failure "journey script error: the secret reference $name of $product was not renamed"
		bytes=32
		# Coordinator keys are exactly 32 bytes in a file: 16 random bytes
		# written as 32 hexadecimal characters.
		if [[ "$product" == coordinator ]]; then
			bytes=16
		fi
		journey_secret_new "$name" "$bytes"
	done < <(secret_references "$RUNTIME_FILE")
}

# database_step STEP TYPED -- COMMAND...: a database step and its blockers.
database_step() {
	local step=$1 typed=$2 status=0
	shift 3
	journey_step "$step" --concepts database-url,database-role,secret-file --typed "$typed" -- "$@" || status=$?
	if [[ $status -eq 0 ]]; then
		journey_pass "$step"
		return 0
	fi
	if [[ "$step" == database.provision ]] && unrecognized_subcommand "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"; then
		# No provisioning command: the reader's way on is the CREATE ROLE,
		# CREATE DATABASE and GRANT statements of the operate page.
		if ! journey_blocker "$step" journey.needs.hand-written-sql sql \
			"$CELL" "$ADMIN_URL_FILE" "$MIGRATION_URL_FILE" "$RUNTIME_URL_FILE"; then
			CELL_OVER=1
		fi
		return 0
	fi
	if mentions_tls "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"; then
		if ! journey_blocker "$step" journey.needs.certificate certificate "$CELL" "$RUNTIME_FILE"; then
			CELL_OVER=1
			return 0
		fi
		reader_command "$step" --concepts database-tls --typed "$typed" -- "$@"
		return 0
	fi
	stop_with_product_code "$step" "$JOURNEY_STEP_STDOUT" "$JOURNEY_STEP_STDERR"
}

# database.provision and database.connect: the product's roles and database on
# the reader's PostgreSQL, then its schema. A product with no database has no
# command for either step.
step_database() {
	local product=$1
	write_product_secrets "$product"
	if [[ "$(field "$product" usesPostgres)" != true ]]; then
		journey_pass database.provision
		journey_pass database.connect
		return 0
	fi
	database_step database.provision "$TOOL provision --runtime-config $RUNTIME_FILE --admin-url-file $ADMIN_URL_FILE" -- \
		"$TOOL_BIN" provision --runtime-config "$RUNTIME_FILE" --admin-url-file "$ADMIN_URL_FILE"
	[[ $CELL_OVER -eq 0 ]] || return 0
	case "$product" in
	casework | messaging | scheduling | documents | coordinator)
		database_step database.connect "$TOOL apply --runtime-config $RUNTIME_FILE" -- \
			"$TOOL_BIN" apply --runtime-config "$RUNTIME_FILE" --format json
		;;
	breg)
		journey_harness_failure "no database.connect recipe is written for breg: bregctl apply needs the package bregctl package builds from a bregctl test receipt, and bregctl test needs a schema-test credential binding document; extend step_database in own-provider.sh"
		;;
	adapter)
		journey_harness_failure "no database.connect recipe is written for adapter: it has no apply command, and its runtime reads the database URLs from secret:env references; extend step_database in own-provider.sh"
		;;
	esac
}

# The command that starts the product's runtime, as the reader types it.
serve_command() {
	local product=$1
	case "$product" in
	breg | coordinator) SERVE_COMMAND=("$SERVER_BIN" --runtime-config "$RUNTIME_FILE") ;;
	casework | messaging | scheduling | documents) SERVE_COMMAND=("$SERVER_BIN" --runtime-config "$RUNTIME_FILE" serve) ;;
	render) SERVE_COMMAND=("$SERVER_BIN" serve --runtime-config "$RUNTIME_FILE") ;;
	*) journey_harness_failure "no start recipe is written for $product; add one to serve_command in own-provider.sh" ;;
	esac
}

# server_gone: the open cell's server is no longer running.
server_gone() {
	! journey_process_running server
}

# refresh_server_log: bring the saved, redacted log of the open cell's server
# (SERVER_LOG_OUT and SERVER_LOG_ERR, set at start) up to date. A server that
# has exited was saved by lib.sh when it stopped.
refresh_server_log() {
	# shellcheck disable=SC2034 # journey_process_log sets it; only the refresh matters here
	local ignored
	if journey_process_running server; then
		journey_process_log server ignored
	fi
}

# stop_server_after_failure: a cell that stopped after its server started
# cannot take the stop step, and the next cell needs the port, so the server
# is sent SIGTERM here by the process id lib.sh recorded in processes.txt.
# lib.sh's cleanup then collects its exit status and saves its log.
stop_server_after_failure() {
	local pid='' product name
	journey_process_running server || return 0
	while IFS=$'\t' read -r pid product name; do
		[[ "$product" == "$CELL" && "$name" == server ]] && break
		pid=''
	done <"$JOURNEY_OUT/processes.txt"
	[[ -n "$pid" ]] || journey_harness_failure "processes.txt has no server of $CELL"
	kill -TERM "$pid" || journey_harness_failure "cannot send SIGTERM to the server of $CELL (pid $pid)"
	if ! journey_poll 30 -- server_gone; then
		kill -KILL "$pid" || journey_harness_failure "cannot stop the server of $CELL (pid $pid)"
		journey_poll 10 -- server_gone || journey_harness_failure "the server of $CELL (pid $pid) is still running after SIGKILL"
	fi
}

# start and ready: the product's runtime, until it answers its readiness
# route.
step_start() {
	local product=$1 status=0 ready_url
	serve_command "$product"
	port_is_free "$PORT" || journey_harness_failure "port $PORT is in use; the journey cannot start $product on it"
	journey_start start server --settle 3 -- "${SERVE_COMMAND[@]}" || status=$?
	SERVER_LOG_OUT=$JOURNEY_STEP_STDOUT
	SERVER_LOG_ERR=$JOURNEY_STEP_STDERR
	if [[ $status -ne 0 ]]; then
		if mentions_tls "$SERVER_LOG_OUT" "$SERVER_LOG_ERR"; then
			if ! journey_blocker start journey.needs.certificate certificate "$CELL" "$RUNTIME_FILE"; then
				CELL_OVER=1
				return 0
			fi
			status=0
			journey_start start server --settle 3 -- "${SERVE_COMMAND[@]}" || status=$?
			SERVER_LOG_OUT=$JOURNEY_STEP_STDOUT
			SERVER_LOG_ERR=$JOURNEY_STEP_STDERR
		fi
		if [[ $status -ne 0 ]]; then
			stop_with_product_code start "$SERVER_LOG_OUT" "$SERVER_LOG_ERR"
			return 0
		fi
	fi
	journey_pass start
	ready_url=http://127.0.0.1:$PORT$READY_PATH
	status=0
	journey_ready ready server --timeout 90 -- curl --silent --show-error --fail --output /dev/null "$ready_url" || status=$?
	if [[ $status -ne 0 ]]; then
		refresh_server_log
		if [[ -z "${JOURNEY_PROCESS_STATUS:-}" ]]; then
			journey_harness_failure "$product kept running but $ready_url did not answer 2xx within 90 seconds; see $SERVER_LOG_ERR"
		fi
		stop_with_product_code ready "$SERVER_LOG_OUT" "$SERVER_LOG_ERR"
		return 0
	fi
	journey_pass ready
}

# token: a client-credentials token from the reader's provider.
step_token() {
	local token_url=$KC_ISSUER/protocol/openid-connect/token status=0
	journey_http token --concepts client,grant,scopes \
		--typed "curl -X POST $token_url -d grant_type=client_credentials -d client_id=$CLIENT -d client_secret=\$SECRET" \
		--form grant_type=client_credentials --form "client_id=$CLIENT" --form-secret "client_secret=client-$CELL" \
		--capture-secret .access_token ACCESS_TOKEN POST "$token_url" || status=$?
	if [[ $status -ne 0 ]]; then
		journey_harness_failure "Keycloak refused the client credentials of $CLIENT (HTTP $JOURNEY_HTTP_STATUS); the realm is the journey's own setup, see $JOURNEY_STEP_STDOUT"
	fi
	# The audience and the scope come from the realm, the journey's own setup:
	# a token without them would turn a realm mistake into a product refusal.
	token_has_audience_and_scope ACCESS_TOKEN "$AUDIENCE" "$SCOPE" ||
		journey_harness_failure "the token Keycloak issued to $CLIENT lacks audience $AUDIENCE or scope $SCOPE; check keycloak/realm.json and the scope setup"
	journey_pass token
}

# token_has_audience_and_scope TOKEN_VARIABLE AUDIENCE SCOPE
token_has_audience_and_scope() {
	local variable=$1
	shift
	printf '%s' "${!variable}" | perl -MMIME::Base64 -MJSON::PP -e '
		local $/; my $token = <STDIN>;
		my $payload = (split /\./, $token)[1] // "";
		$payload =~ tr{-_}{+/};
		$payload .= "=" x ((4 - length($payload) % 4) % 4);
		my $claims = decode_json(decode_base64($payload));
		my ($audience, $scope) = @ARGV;
		my @aud = ref $claims->{aud} eq "ARRAY" ? @{ $claims->{aud} } : ($claims->{aud} // ());
		exit 1 unless grep { $_ eq $audience } @aud;
		exit 1 unless grep { $_ eq $scope } split / /, ($claims->{scope} // "");
		exit 0;' "$@"
}

# missing_claims TOKEN_VARIABLE CLAIM...: the CLAIMs the token's payload lacks,
# one per line. The token reaches perl through a pipe.
missing_claims() {
	local variable=$1
	shift
	[[ $# -gt 0 ]] || return 0
	printf '%s' "${!variable}" | perl -MMIME::Base64 -MJSON::PP -e '
		local $/; my $token = <STDIN>;
		my $payload = (split /\./, $token)[1] // "";
		$payload =~ tr{-_}{+/};
		$payload .= "=" x ((4 - length($payload) % 4) % 4);
		my $claims = decode_json(decode_base64($payload));
		for my $name (@ARGV) { print "$name\n" unless exists $claims->{$name} }' "$@" ||
		journey_harness_failure "cannot read the claims of the token of $CELL"
}

# logged_stage FILE...: the last authentication stage the product logged.
logged_stage() {
	perl -e '
		my $stage = "";
		local $/;
		for my $path (@ARGV) {
			open my $fh, "<", $path or next;
			my $text = <$fh>;
			next unless defined $text;
			while ($text =~ /"stage"\s*:\s*"([a-z]+(?:-[a-z]+)*)"|\bstage=("?)([a-z]+(?:-[a-z]+)*)\2/g) {
				$stage = defined $1 ? $1 : $3;
			}
		}
		print $stage;' "$@"
}

# call_request: the first authenticated request, made once more after an
# assist.
call_request() {
	local -a options=(--bearer ACCESS_TOKEN)
	case "$CELL" in
	messaging)
		options+=(--header 'Content-Type: application/json' --header 'Idempotency-Key: journey-first-call'
			--data-file "$WORK/call-body.json")
		;;
	render)
		options+=(--header 'Content-Type: application/json' --data-file "$WORK/request.json")
		;;
	esac
	journey_http call "${options[@]}" "$CALL_METHOD" "http://127.0.0.1:$PORT$CALL_PATH"
}

# render_request DATA TARGET: the request body of the Render tutorial.
render_request() {
	jq -c '{issuedAt: "2026-09-16T10:32:00Z", data: .}' "$1" >"$2"
}

# call: the first authenticated request. A refusal is named by the HTTP status
# and the stage the product logged, by the problem code it answered when its
# log names no stage, or is a claim-mapper stop when the token lacks a claim
# the product reads.
step_call() {
	local status=0 stage='' missing attempt
	case "$CELL" in
	messaging)
		journey_write_file "$WORK/call-body.json" < <(printf '%s\n' \
			'{"senderProfile":"reminders-sms","to":{"phone":"+15555550100"},"template":{"id":"appointment-reminder-sms","version":"1"},"locale":"en","data":{"name":"Ada Lovelace","day":"2026-10-01","office":"Central Registry Office"}}')
		;;
	render)
		journey_step call --typed "jq -c '{issuedAt: \"2026-09-16T10:32:00Z\", data: .}' fixtures/data.json > request.json" -- \
			render_request "$PROJECT/fixtures/data.json" "$WORK/request.json" ||
			journey_harness_failure "cannot build the Render request body; see $JOURNEY_STEP_STDERR"
		;;
	esac
	call_request || status=$?
	if [[ $status -eq 0 ]]; then
		journey_pass call
		journey_reached t1
		return 0
	fi
	[[ "$JOURNEY_HTTP_STATUS" != 000 ]] ||
		journey_harness_failure "the call to $CELL got no answer; see $JOURNEY_STEP_STDERR"
	[[ -z "${JOURNEY_HTTP_CAPTURE_FAILED:-}" ]] ||
		journey_harness_failure "the call to $CELL answered 2xx without what the journey reads; see $JOURNEY_STEP_STDOUT"
	# The refusal is logged as the response is written; wait a moment for it.
	for attempt in 1 2 3; do
		refresh_server_log
		stage=$(logged_stage "$SERVER_LOG_OUT" "$SERVER_LOG_ERR")
		[[ -z "$stage" ]] || break
		[[ $attempt -eq 3 ]] || sleep 1
	done
	# shellcheck disable=SC2086 # CLAIMS is a list of words
	missing=$(missing_claims ACCESS_TOKEN $CLAIMS)
	if [[ -n "$missing" && (-z "$stage" || "$stage" == profile) ]]; then
		# shellcheck disable=SC2086 # missing is a list of words
		if ! journey_blocker call journey.needs.claim-mapper mapper "$CELL" "$CLIENT" ACCESS_TOKEN $missing; then
			CELL_OVER=1
			return 0
		fi
		status=0
		call_request || status=$?
		if [[ $status -eq 0 ]]; then
			journey_reached t1
			return 0
		fi
		refresh_server_log
		stage=$(logged_stage "$SERVER_LOG_OUT" "$SERVER_LOG_ERR")
	fi
	if [[ -z "$stage" ]]; then
		# A product whose log names no stage still names its refusal in the
		# problem body. That code is recorded rather than a stage the journey
		# would have to guess.
		if [[ "${JOURNEY_HTTP_PROBLEM_CODE:-}" =~ ^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)*$ ]]; then
			journey_fail call "product.$JOURNEY_HTTP_PROBLEM_CODE"
			CELL_OVER=1
			return 0
		fi
		journey_harness_failure "the call to $CELL answered HTTP $JOURNEY_HTTP_STATUS with problem code '${JOURNEY_HTTP_PROBLEM_CODE:-none}', and its log names no authentication stage; see $SERVER_LOG_ERR and extend own-provider.sh"
	fi
	if [[ "$STAGES" != *" $stage "* ]]; then
		journey_harness_failure "the call to $CELL answered HTTP $JOURNEY_HTTP_STATUS and its log names the stage '$stage', which the table does not list; see $SERVER_LOG_ERR"
	fi
	journey_fail call "http.$JOURNEY_HTTP_STATUS.$stage"
	CELL_OVER=1
}

# hook: the products whose runtime format has hook destinations need the
# receiver container the hook milestone adds; the others deliver nothing, so
# the step has no command for them.
step_hook() {
	case "$CELL" in
	breg | scheduling | documents)
		journey_unreached hook "The product delivers hooks, and the journey has no receiver for them until the hook milestone (M8) adds one."
		CELL_OVER=1
		;;
	*) journey_pass hook ;;
	esac
}

step_stop() {
	if journey_stop stop server; then
		journey_pass stop
	else
		journey_fail stop product.stop.ignored-signal
		CELL_OVER=1
	fi
}

# walk_product PRODUCT: walk one product through the steps.
walk_product() {
	local product=$1 step
	CELL=$product
	CELL_OVER=0
	RUNTIME_FILE=''
	# shellcheck disable=SC2034 # read by name through journey_http --bearer
	ACCESS_TOKEN=''
	MIGRATION_URL_FILE=''
	RUNTIME_URL_FILE=''
	SERVER_LOG_OUT=''
	SERVER_LOG_ERR=''
	journey_cell_begin "$product"
	if [[ "$(field "$product" tier)" == supporting ]]; then
		journey_unreached prepare "Supporting runtime. It starts beside its parent and is added to the journey when the parent's cell passes."
		journey_cell_end
		return 0
	fi
	if [[ "$(field "$product" verifiesTokens)" != true && "$(field "$product" usesPostgres)" != true ]]; then
		journey_unreached prepare "The product verifies no token and keeps no database, so the reader's own provider and PostgreSQL have nothing to serve it, and its tutorial's publication server is Python, which a journey does not run."
		journey_cell_end
		return 0
	fi
	journey_workdir "$product" WORK
	PROJECT=$WORK/$product
	recipe "$product"
	for step in prepare issuer database start token call hook stop; do
		"step_$step" "$product"
		[[ $CELL_OVER -eq 0 ]] || break
	done
	stop_server_after_failure
	journey_cell_end
}

# ---------------------------------------------------------------------------
# Setup and the cells

NEEDS_ISSUER=0
NEEDS_POSTGRES=0
PRIMARY=()
for product in "${JOURNEY_PRODUCTS[@]}"; do
	[[ "$(field "$product" tier)" == primary ]] || continue
	[[ "$(field "$product" verifiesTokens)" == true || "$(field "$product" usesPostgres)" == true ]] || continue
	PRIMARY+=("$product")
	[[ "$(field "$product" verifiesTokens)" != true ]] || NEEDS_ISSUER=1
	[[ "$(field "$product" usesPostgres)" != true ]] || NEEDS_POSTGRES=1
done

if [[ ${#PRIMARY[@]} -gt 0 ]]; then
	journey_resolve_binaries "${PRIMARY[@]}"
	[[ $NEEDS_ISSUER -eq 0 ]] || start_keycloak
	[[ $NEEDS_POSTGRES -eq 0 ]] || start_postgres
	if [[ $NEEDS_ISSUER -eq 1 ]]; then
		keycloak_admin_login
		for product in "${PRIMARY[@]}"; do
			recipe "$product"
			keycloak_default_scope "$CLIENT" "$SCOPE"
			if [[ "$product" == coordinator ]]; then
				keycloak_service_account_subject "$CLIENT" COORDINATOR_SUBJECT
			fi
		done
	fi
	if [[ -n "$JOURNEY_PORT_BASE" ]]; then
		PORT=$((JOURNEY_PORT_BASE + 4))
		METRICS_PORT=$((JOURNEY_PORT_BASE + 5))
	else
		free_port PORT
		free_port METRICS_PORT
		[[ "$PORT" != "$METRICS_PORT" ]] || free_port METRICS_PORT
	fi
	jq -n --arg issuer "$ISSUER_KIND" --arg image "$KEYCLOAK_IMAGE" --arg realm "$REALM" \
		--arg issuerUrl "$KC_ISSUER" --arg postgres "$POSTGRES_IMAGE" --arg pgPort "$PG_PORT" \
		--arg port "$PORT" --arg metricsPort "$METRICS_PORT" \
		'def opt: if . == "" then null else . end;
		 {schema: "registry.journey-own-provider/v1", issuer: $issuer, issuerImage: $image, realm: $realm,
		  issuerUrl: ($issuerUrl | opt), postgresImage: $postgres, postgresPort: ($pgPort | opt | if . == null then null else tonumber end),
		  productPort: ($port | tonumber), productMetricsPort: ($metricsPort | tonumber),
		  containers: {issuer: "kc", postgres: "pg"}}' >"$JOURNEY_OUT/own-provider.json" ||
		journey_harness_failure "cannot write $JOURNEY_OUT/own-provider.json"
fi

for product in "${JOURNEY_PRODUCTS[@]}"; do
	walk_product "$product"
done

journey_finish
