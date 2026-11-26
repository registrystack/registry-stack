#!/usr/bin/env bash
set -euo pipefail

readonly default_openbao_image='ghcr.io/openbao/openbao:2.6.5@sha256:09f1eaaee351c329d75a5a89654d6e1ad4792998650c3cbf0c3513a76d9d9b6e'
readonly openbao_image="${OPENBAO_IMAGE:-$default_openbao_image}"

if [[ ! "$openbao_image" =~ @sha256:[[:xdigit:]]{64}$ ]]; then
	printf 'OPENBAO_IMAGE must be pinned by repository digest\n' >&2
	exit 2
fi
if [[ "${OPENBAO_PREFLIGHT_ONLY:-false}" != true ]] &&
	[[ -z "${CARGO_TARGET_DIR:-}" || "$CARGO_TARGET_DIR" != /* ]]; then
	printf 'CARGO_TARGET_DIR must be an absolute path outside the worktree\n' >&2
	exit 2
fi
for command in curl docker jq openssl; do
	if ! command -v "$command" >/dev/null 2>&1; then
		printf 'required command is unavailable: %s\n' "$command" >&2
		exit 2
	fi
done
if [[ "${OPENBAO_PREFLIGHT_ONLY:-false}" != true ]] && ! command -v cargo >/dev/null 2>&1; then
	printf 'required command is unavailable: cargo\n' >&2
	exit 2
fi
if ! docker image inspect "$openbao_image" >/dev/null 2>&1; then
	if [[ "${OPENBAO_PULL:-false}" != true ]]; then
		printf 'pinned OpenBao image is not local; rerun with OPENBAO_PULL=true: %s\n' "$openbao_image" >&2
		exit 2
	fi
	docker pull "$openbao_image" >/dev/null
fi

script_directory="$(dirname -- "$(realpath "${BASH_SOURCE[0]}")")"
readonly script_directory
repository_root="$(git --no-optional-locks -C "$script_directory" rev-parse --show-toplevel)"
readonly repository_root
scratch="$(mktemp -d "${TMPDIR:-/tmp}/registry-payments-openbao.XXXXXX")"
readonly scratch
chmod 0700 "$scratch"
host_uid="$(id -u)"
readonly host_uid
host_gid="$(id -g)"
readonly host_gid
suffix="$(basename "$scratch" | tr -cd '[:alnum:]')"
readonly suffix
readonly server_name="registry-payments-openbao-server-$suffix"
readonly proxy_name="registry-payments-openbao-proxy-$suffix"
server_started=false
proxy_started=false

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	if [[ "$proxy_started" == true ]]; then
		docker container rm --force "$proxy_name" >/dev/null 2>&1 || true
	fi
	if [[ "$server_started" == true ]]; then
		docker container rm --force "$server_name" >/dev/null 2>&1 || true
	fi
	rm -r "$scratch"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
umask 077

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
	-out "$scratch/response-private.pem" >/dev/null 2>&1
openssl pkey -in "$scratch/response-private.pem" -pubout \
	-out "$scratch/response-public.pem" >/dev/null 2>&1

cat >"$scratch/adapter-payments.hcl" <<'POLICY'
path "transit/keys/mifos-request" {
  capabilities = ["read"]
}
path "transit/sign/mifos-request/none" {
  capabilities = ["update"]
}
path "transit/verify/mifos-request/none" {
  capabilities = ["update"]
}
path "transit/keys/mifos-response" {
  capabilities = ["read"]
}
path "transit/verify/mifos-response/none" {
  capabilities = ["update"]
}
POLICY

root_token="$(openssl rand -hex 32)"
readonly root_token
BAO_DEV_ROOT_TOKEN_ID="$root_token" docker run --detach --rm --pull=never \
	--name "$server_name" \
	--network none \
	--log-driver none \
	--user "$host_uid:$host_gid" \
	--cap-drop ALL \
	--env BAO_DEV_ROOT_TOKEN_ID \
	--env BAO_DEV_LISTEN_ADDRESS=127.0.0.1:8200 \
	--volume "$scratch:/fixtures" \
	"$openbao_image" server -dev -dev-no-store-token >/dev/null
server_started=true

openbao() {
	BAO_TOKEN="$root_token" docker exec \
		--env BAO_ADDR=http://127.0.0.1:8200 \
		--env BAO_TOKEN \
		"$server_name" bao "$@"
}

ready=false
for _ in {1..50}; do
	if openbao status >/dev/null 2>&1; then
		ready=true
		break
	fi
	sleep 0.1
done
if [[ "$ready" != true ]]; then
	printf 'OpenBao development server did not become ready\n' >&2
	exit 1
fi

cat >"$scratch/proxy.hcl" <<'CONFIG'
auto_auth {
  method "token_file" {
    config = {
      token_file_path = "/fixtures/proxy-token"
    }
  }
  sink "file" {
    config = {
      path = "/fixtures/proxy-sink-token"
    }
  }
}

api_proxy {
  use_auto_auth_token = "force"
}

# Adapter's Transit client uses HTTP over this private Unix socket.
listener "unix" {
  address                = "/fixtures/transit.sock"
  tls_disable            = true
  require_request_header = true
}

listener "tcp" {
  address                = "127.0.0.1:8300"
  tls_disable            = true
  require_request_header = true
}

vault {
  address = "http://127.0.0.1:8200"
}
CONFIG

openbao secrets enable -path=transit transit >/dev/null
openbao write transit/keys/mifos-request \
	type=rsa-2048 exportable=false allow_plaintext_backup=false >/dev/null
openbao write transit/keys/mifos-response/import \
	type=rsa-2048 public_key=@/fixtures/response-public.pem >/dev/null
openbao read -format=json transit/keys/mifos-request |
	jq -er '.data.keys["1"].public_key' >"$scratch/request-public.pem"
openbao policy write adapter-payments /fixtures/adapter-payments.hcl >/dev/null
openbao token create -format=json -orphan -policy=adapter-payments -ttl=15m |
	jq -er '.auth.client_token' >"$scratch/proxy-token"

docker run --detach --rm --pull=never \
	--name "$proxy_name" \
	--network "container:$server_name" \
	--log-driver none \
	--user "$host_uid:$host_gid" \
	--cap-drop ALL \
	--volume "$scratch:/fixtures" \
	"$openbao_image" proxy -config=/fixtures/proxy.hcl -log-level=warn >/dev/null
proxy_started=true

proxy_tcp_read() {
	docker exec "$server_name" wget -qO- \
		--header='X-Vault-Request: true' \
		"http://127.0.0.1:8300/v1/transit/keys/$1"
}

proxy_unix_read() {
	curl --disable --fail --silent --show-error --noproxy '*' --max-time 5 \
		--unix-socket "$scratch/transit.sock" \
		--header 'X-Vault-Request: true' \
		"http://localhost/v1/transit/keys/$1"
}

ready=false
for _ in {1..50}; do
	if request_metadata="$(proxy_tcp_read mifos-request 2>/dev/null)"; then
		ready=true
		break
	fi
	sleep 0.1
done
if [[ "$ready" != true ]]; then
	printf 'OpenBao Proxy did not serve request-key metadata\n' >&2
	exit 1
fi
if [[ ! -S "$scratch/transit.sock" ]]; then
	printf 'OpenBao Proxy did not create its Unix socket\n' >&2
	exit 1
fi
chmod 0600 "$scratch/transit.sock"

host_unix_socket=true
if unix_request_metadata="$(proxy_unix_read mifos-request 2>"$scratch/unix-read-error")"; then
	request_metadata="$unix_request_metadata"
	if ! response_metadata="$(proxy_unix_read mifos-response)"; then
		printf 'OpenBao Proxy Unix listener did not serve response-key metadata\n' >&2
		exit 1
	fi
elif [[ "${OPENBAO_PREFLIGHT_ONLY:-false}" == true ]]; then
	host_unix_socket=false
	if ! response_metadata="$(proxy_tcp_read mifos-response 2>/dev/null)"; then
		printf 'OpenBao Proxy did not serve response-key metadata\n' >&2
		exit 1
	fi
else
	printf 'OpenBao Proxy Unix listener did not serve request-key metadata\n%s\n' \
		"$(<"$scratch/unix-read-error")" >&2
	exit 1
fi
jq -e '.data.imported_key == false
  and .data.derived == false
  and .data.exportable == false
  and .data.allow_plaintext_backup == false
  and .data.supports_signing == true
  and .data.type == "rsa-2048"
  and .data.keys["1"].public_key != null' \
	<<<"$request_metadata" >/dev/null
jq -e '.data.imported_key == true
  and .data.derived == false
  and .data.exportable == false
  and .data.allow_plaintext_backup == false
  and .data.supports_signing == true
  and .data.type == "rsa-2048"
  and .data.keys["1"].public_key != null' \
	<<<"$response_metadata" >/dev/null

if [[ "${OPENBAO_PREFLIGHT_ONLY:-false}" == true ]]; then
	if [[ "$host_unix_socket" == true ]]; then
		printf 'real OpenBao Transit and Unix Proxy preflight passed\n'
	else
		printf 'real OpenBao Transit and TCP Proxy preflight passed (host Unix listener unverified)\n'
	fi
	exit 0
fi

REGISTRY_PAYMENTS_OPENBAO_SOCKET="$scratch/transit.sock" \
	REGISTRY_PAYMENTS_OPENBAO_REQUEST_PUBLIC_KEY="$scratch/request-public.pem" \
	REGISTRY_PAYMENTS_OPENBAO_RESPONSE_PRIVATE_KEY="$scratch/response-private.pem" \
	REGISTRY_PAYMENTS_OPENBAO_RESPONSE_PUBLIC_KEY="$scratch/response-public.pem" \
	CARGO_INCREMENTAL=0 \
	CARGO_PROFILE_DEV_DEBUG=0 \
	CARGO_PROFILE_TEST_DEBUG=0 \
	PATH="$HOME/.cargo/bin:$PATH" \
	cargo test --locked --manifest-path "$repository_root/Cargo.toml" \
	-p registry-adapter --test g2p_provider \
	real_openbao_transit_signs_requests_and_refuses_a_changed_response \
	-- --exact --ignored
