#!/usr/bin/env bash
set -euo pipefail

# Reproduce the registered output example with explicitly synthetic bindings.
# No listener, issuer, database, or source is contacted by the export command.
repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
check=false
if [[ "${1:-}" == --check ]] && [[ $# == 1 ]]; then
	check=true
elif [[ $# != 0 ]]; then
	printf 'Usage: %s [--check]\n' "$0" >&2
	exit 2
fi
: "${CARGO_TARGET_DIR:?Set CARGO_TARGET_DIR to the worktree build directory.}"

# shellcheck source=scripts/cargo-runtime-library-path.sh
source "$repo_root/scripts/cargo-runtime-library-path.sh"
registry_prepare_cargo_runtime "$repo_root" --locked -p registry-adapter \
	--manifest-path "$repo_root/Cargo.toml" --target-dir "$CARGO_TARGET_DIR"
adapter_bin="${ADAPTER_BIN:-${CARGO_TARGET_DIR}/debug/adapter}"
if [[ ! -x "$adapter_bin" ]]; then
	printf 'No Adapter executable at %s.\n' "$adapter_bin" >&2
	exit 2
fi

example_scratch=$(mktemp -d "${CARGO_TARGET_DIR}/effective-contract-example.XXXXXX")
cleanup() {
	rm -f -- "$example_scratch/runtime.yaml" "$example_scratch/effective-contract.json"
	rmdir -- "$example_scratch"
}
trap cleanup EXIT
cat >"$example_scratch/runtime.yaml" <<'YAML'
apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: effective-contract-example
endpoints:
  - endpoint: tracker
    baseUrl: https://tracker.example.invalid
    credential:
      type: basic
      usernameRef: secret:env/ADAPTER_EXAMPLE_USERNAME
      passwordRef: secret:env/ADAPTER_EXAMPLE_PASSWORD
listener:
  bind: 127.0.0.1:8080
database:
  runtimeUrlRef: secret:env/ADAPTER_EXAMPLE_DATABASE
  migrationUrlRef: secret:env/ADAPTER_EXAMPLE_DATABASE
oidc:
  issuer: https://issuer.example.invalid
  audience: adapter-example
allowedClients: [adapter-example-client]
allowedPrivateCidrs: [192.168.0.0/16]
audit:
  retentionDays: 90
idempotency:
  responseRetentionSeconds: 86400
cursorKeyRef: secret:env/ADAPTER_EXAMPLE_CURSOR_KEY
YAML

ADAPTER_EXAMPLE_USERNAME=synthetic-reader \
	ADAPTER_EXAMPLE_PASSWORD=synthetic-password \
	ADAPTER_EXAMPLE_DATABASE=postgresql://unused.invalid/test \
	ADAPTER_EXAMPLE_CURSOR_KEY='synthetic-cursor-key-0123456789!' \
	"$adapter_bin" effective-contract \
	--runtime-config "$example_scratch/runtime.yaml" \
	--project "$repo_root/products/adapter/examples/dhis2-tracker" \
	--profile "$repo_root/products/adapter/profiles/breg-records/profile.yaml" \
	--pack "$repo_root/products/adapter/packs/dhis2-tracker/pack.yaml" \
	>"$example_scratch/effective-contract.json"

example="$repo_root/products/adapter/examples/formats/effective-contract.json"
if [[ "$check" == true ]]; then
	if ! cmp -s "$example_scratch/effective-contract.json" "$example"; then
		printf 'Effective-contract example drifted; run %s.\n' "${BASH_SOURCE[0]}" >&2
		exit 1
	fi
	printf 'Effective-contract example matches the real CLI export.\n'
else
	mkdir -p -- "$(dirname -- "$example")"
	cp -- "$example_scratch/effective-contract.json" "$example"
	printf 'Generated %s.\n' "$example"
fi
