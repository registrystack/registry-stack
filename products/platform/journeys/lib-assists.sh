#!/usr/bin/env bash
# Assists for the acceptance journeys: what a developer must do by hand today
# where a product offers no command. This is the one journey file allowed to
# call psql, openssl and docker exec, which the pass rule forbids the reader.
# lib.sh sources it only when --assist names an assist, and each use is counted
# there as a pass-rule violation.
#
# Written for the products the baseline run meets on main (Scheduling and the
# other PostgreSQL products that share the operate pages' provisioning SQL).
# The assists are sourced into the journey's shell: they read JOURNEY_OUT and
# JOURNEY_CONTAINER_PREFIX from lib.sh and call its secret and container
# helpers.
#
#   journey_assist_sql PRODUCT ADMIN_URL_FILE MIGRATION_URL_FILE RUNTIME_URL_FILE
#       The statements of the product's operate page: two login roles, the
#       database, the connect grants and the schema handed to the migration
#       role. Run with psql as the administrator.
#   journey_assist_certificate PRODUCT RUNTIME_FILE
#       A private CA and a server certificate for 127.0.0.1, installed into the
#       journey's pg container, TLS switched on, and the runtime file's
#       database.caBundleRef set to the CA.
#   journey_assist_mapper PRODUCT CLIENT TOKEN_VARIABLE CLAIM...
#       A hardcoded-claim mapper on the caller's client in Keycloak for each
#       missing claim, then a fresh client-credentials token in TOKEN_VARIABLE.
#       Written for registry_actor_kind, the one claim Scheduling needs.
#   journey_assist_token_type PRODUCT CLIENT TOKEN_VARIABLE
#       Keycloak's setting that makes the client's access tokens carry the
#       at+jwt header type, then a fresh token in TOKEN_VARIABLE. The shared
#       verifier refuses every other type.
#
# shellcheck disable=SC2034 # the assist variables are read by the sourcing shell
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	printf 'lib-assists.sh is sourced by lib.sh; it does nothing on its own.\n' >&2
	exit 2
fi

_assist_identifier='^[a-z][a-z0-9_]*$'

# _assist_url_part FILE PART: user, password, port or database of the
# PostgreSQL URL in FILE, on stdout. The URL is the journey's own shape,
# postgresql://USER:PASSWORD@127.0.0.1:PORT/DATABASE with a hexadecimal password.
_assist_url_part() {
	perl -e '
		my ($path, $part) = @ARGV;
		open my $fh, "<", $path or die "cannot read $path: $!\n";
		my $url = <$fh>;
		chomp $url;
		my %p;
		@p{qw(user password port database)} =
			$url =~ m{^postgresql://([a-z][a-z0-9_]*):([0-9a-f]+)\@127\.0\.0\.1:([0-9]+)/([a-z][a-z0-9_]*)$}
			or die "$path does not hold a PostgreSQL URL of the journey shape\n";
		print $p{$part};' "$1" "$2"
}

# _assist_psql PGPASS_FILE PORT DATABASE: psql as the administrator, the
# statements on standard input. The password reaches psql as a pgpass file.
_assist_psql() {
	PGPASSFILE=$1 psql --no-psqlrc --quiet --set ON_ERROR_STOP=1 \
		--host 127.0.0.1 --port "$2" --username postgres --dbname "$3" --file -
}

# _assist_wait_for_postgres PGPASS_FILE PORT: the container's TCP port opens
# while the image's entrypoint is still initialising, so wait until the final
# server answers a query.
_assist_wait_for_postgres() {
	local attempt
	for attempt in $(seq 1 60); do
		if printf 'SELECT 1;\n' | _assist_psql "$1" "$2" postgres >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	printf 'assist: PostgreSQL on port %s did not answer within 60 seconds\n' "$2" >&2
	return 1
}

_assist_admin_pgpass() {
	local admin_file=$1 port password pgpass=$JOURNEY_OUT/secrets/assist-pgpass
	port=$(_assist_url_part "$admin_file" port)
	password=$(_assist_url_part "$admin_file" password)
	(
		umask 077
		printf '127.0.0.1:%s:*:postgres:%s\n' "$port" "$password" >"$pgpass"
	)
	chmod 600 "$pgpass"
	printf '%s' "$pgpass"
}

journey_assist_sql() {
	local product=$1 admin_file=$2 migration_file=$3 runtime_file=$4
	local port database migration_role runtime_role migration_password runtime_password pgpass status=0
	port=$(_assist_url_part "$admin_file" port)
	database=$(_assist_url_part "$migration_file" database)
	migration_role=$(_assist_url_part "$migration_file" user)
	migration_password=$(_assist_url_part "$migration_file" password)
	runtime_role=$(_assist_url_part "$runtime_file" user)
	runtime_password=$(_assist_url_part "$runtime_file" password)
	[[ "$database" =~ $_assist_identifier && "$migration_role" =~ $_assist_identifier && "$runtime_role" =~ $_assist_identifier ]] || {
		printf 'assist sql: %s has a name psql would need quoted\n' "$product" >&2
		return 1
	}
	pgpass=$(_assist_admin_pgpass "$admin_file")
	_assist_wait_for_postgres "$pgpass" "$port" || return 1
	_assist_psql "$pgpass" "$port" postgres <<SQL || status=$?
CREATE ROLE "$migration_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$migration_password';
CREATE ROLE "$runtime_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '$runtime_password';
CREATE DATABASE "$database";
SQL
	if [[ $status -eq 0 ]]; then
		_assist_psql "$pgpass" "$port" "$database" <<SQL || status=$?
REVOKE ALL ON DATABASE "$database" FROM PUBLIC;
GRANT CONNECT ON DATABASE "$database" TO "$migration_role", "$runtime_role";
ALTER SCHEMA public OWNER TO "$migration_role";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
	fi
	command rm -f "$pgpass"
	return "$status"
}

journey_assist_certificate() {
	local product=$1 runtime_file=$2 tls_dir=$JOURNEY_OUT/work/pg-tls container admin_file port pgpass status=0
	admin_file=$JOURNEY_OUT/secrets/postgres-admin-url
	port=$(_assist_url_part "$admin_file" port)
	journey_container_name pg container
	mkdir -p "$tls_dir"
	chmod 700 "$tls_dir"
	(
		umask 077
		openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=journey-postgres-ca' \
			-keyout "$tls_dir/ca.key" -out "$JOURNEY_OUT/secrets/postgres-ca.pem" 2>/dev/null
		openssl req -newkey rsa:2048 -nodes -subj '/CN=127.0.0.1' \
			-keyout "$tls_dir/server.key" -out "$tls_dir/server.csr" 2>/dev/null
		printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' >"$tls_dir/san.ext"
		openssl x509 -req -days 2 -in "$tls_dir/server.csr" -CA "$JOURNEY_OUT/secrets/postgres-ca.pem" \
			-CAkey "$tls_dir/ca.key" -CAcreateserial -CAserial "$tls_dir/ca.srl" -extfile "$tls_dir/san.ext" \
			-out "$tls_dir/server.crt" 2>/dev/null
	)
	docker exec --user root "$container" mkdir -p /var/lib/postgresql/journey-tls >/dev/null
	docker cp "$tls_dir/server.crt" "$container:/var/lib/postgresql/journey-tls/server.crt" >/dev/null
	docker cp "$tls_dir/server.key" "$container:/var/lib/postgresql/journey-tls/server.key" >/dev/null
	docker exec --user root "$container" sh -c \
		'chown postgres:postgres /var/lib/postgresql/journey-tls/server.crt /var/lib/postgresql/journey-tls/server.key && chmod 600 /var/lib/postgresql/journey-tls/server.key' >/dev/null
	pgpass=$(_assist_admin_pgpass "$admin_file")
	_assist_wait_for_postgres "$pgpass" "$port" || return 1
	_assist_psql "$pgpass" "$port" postgres >/dev/null <<'SQL' || status=$?
ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/journey-tls/server.crt';
ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/journey-tls/server.key';
ALTER SYSTEM SET ssl = on;
SELECT pg_reload_conf();
SQL
	command rm -f "$pgpass" "$tls_dir/ca.key" "$tls_dir/ca.srl" "$tls_dir/server.key" "$tls_dir/server.crt" \
		"$tls_dir/server.csr" "$tls_dir/san.ext" "$JOURNEY_OUT/secrets/postgres-ca.srl"
	rmdir "$tls_dir"
	[[ $status -eq 0 ]] || return "$status"
	# The CA certificate sits in the secret folder because the runtime file
	# resolves it there. own-provider.sh deletes it with its other files.
	OWN_SECRET_FILES+=("$JOURNEY_OUT/secrets/postgres-ca.pem")
	perl -i -pe 's{^(\s*)#\s*(caBundleRef: secret:file/)postgres-ca\.pem\s*$}{$1$2postgres-ca.pem\n}' "$runtime_file"
	grep -q '^[[:space:]]*caBundleRef: secret:file/postgres-ca.pem$' "$runtime_file" || {
		printf 'assist certificate: %s has no caBundleRef line to set in %s\n' "$product" "$runtime_file" >&2
		return 1
	}
}

# _assist_claim_value CLAIM: the value a service caller's token carries.
_assist_claim_value() {
	case "$1" in
	registry_actor_kind) printf 'service' ;;
	*)
		printf 'assist mapper: no value is written for the claim %s\n' "$1" >&2
		return 1
		;;
	esac
}

journey_assist_mapper() {
	local product=$1 client=$2 token_variable=$3 claim value uuid body secret_file response token
	shift 3
	# The administrator token the journey took at setup lives 60 seconds.
	keycloak_admin_login
	keycloak_client_uuid "$client" uuid
	for claim in "$@"; do
		value=$(_assist_claim_value "$claim") || return 1
		body=$(jq -cn --arg claim "$claim" --arg value "$value" \
			'{name: $claim, protocol: "openid-connect", protocolMapper: "oidc-hardcoded-claim-mapper",
			  config: {"claim.name": $claim, "claim.value": $value, "jsonType.label": "String",
			           "access.token.claim": "true", "id.token.claim": "false", "userinfo.token.claim": "false"}}')
		keycloak_admin POST "/clients/$uuid/protocol-mappers/models" "$body"
		[[ "$KC_STATUS" == 201 ]] || {
			printf 'assist mapper: Keycloak refused the mapper for %s (HTTP %s)\n' "$claim" "$KC_STATUS" >&2
			return 1
		}
	done
	_assist_fresh_token "$product" "$client" "$token_variable"
}

journey_assist_token_type() {
	local product=$1 client=$2 token_variable=$3 uuid body
	keycloak_admin_login
	keycloak_client_uuid "$client" uuid
	keycloak_admin GET "/clients/$uuid"
	[[ "$KC_STATUS" == 200 ]] || {
		printf 'assist token-type: Keycloak cannot read client %s (HTTP %s)\n' "$client" "$KC_STATUS" >&2
		return 1
	}
	body=$(printf '%s' "$KC_BODY" | jq -c '.attributes["access.token.header.type.rfc9068"] = "true"')
	keycloak_admin PUT "/clients/$uuid" "$body"
	[[ "$KC_STATUS" == 204 ]] || {
		printf 'assist token-type: Keycloak refused the client update for %s (HTTP %s)\n' "$client" "$KC_STATUS" >&2
		return 1
	}
	_assist_fresh_token "$product" "$client" "$token_variable"
}

# _assist_fresh_token PRODUCT CLIENT TOKEN_VARIABLE: a client-credentials
# token from the journey's Keycloak into TOKEN_VARIABLE, registered as a secret.
_assist_fresh_token() {
	local product=$1 client=$2 token_variable=$3 secret_file response token
	journey_secret_path "client-$product" secret_file
	response=$(curl --silent --show-error --max-time 30 \
		--data grant_type=client_credentials --data-urlencode "client_id=$client" \
		--data-urlencode "client_secret@$secret_file" \
		"$KC_ISSUER/protocol/openid-connect/token") || return 1
	token=$(printf '%s' "$response" | jq -r '.access_token // empty') || return 1
	[[ -n "$token" ]] || {
		printf 'assist mapper: Keycloak issued no token after the client change\n' >&2
		return 1
	}
	printf -v "$token_variable" '%s' "$token"
	journey_secret_register "$product-access-token" "$token_variable"
}
