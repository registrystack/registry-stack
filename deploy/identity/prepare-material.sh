#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
	printf 'usage: %s GENERATED_DIR POSTGRES_CA_PEM ABSENT_OUTPUT_DIR\n' "$0" >&2
	exit 2
fi

generated_dir="$1"
postgres_ca="$2"
output_dir="$3"
namespace=registry-identity-qualification

if [[ ! -f "$generated_dir/identity-receipt.json" ]]; then
	printf 'generated directory is incomplete: identity-receipt.json is absent\n' >&2
	exit 1
fi
if [[ ! -f "$generated_dir/resources/resources.app-kit.yaml" ]]; then
	printf 'generated directory is incomplete: augmented App Kit resources are absent\n' >&2
	exit 1
fi
if [[ ! -f "$postgres_ca" ]]; then
	printf 'PostgreSQL CA file is absent\n' >&2
	exit 1
fi
if [[ -e "$output_dir" ]]; then
	printf 'output directory already exists\n' >&2
	exit 1
fi
if [[ ! -d "$(dirname "$output_dir")" ]]; then
	printf 'parent of the output directory does not exist\n' >&2
	exit 1
fi

# The schema Job mounts one machine-client agent document. The generator names
# it after an identifier derived from the issuer and client, so copy it under
# the fixed key `agent.yaml` that the Job expects.
shopt -s nullglob
agent_files=("$generated_dir"/registry-schema/agents/*.yaml)
shopt -u nullglob
if [[ "${#agent_files[@]}" -ne 1 ]]; then
	printf 'expected exactly one agent document in registry-schema/agents, found %s\n' "${#agent_files[@]}" >&2
	exit 1
fi

if command -v k3s >/dev/null 2>&1; then
	kubectl_command=(sudo -n k3s kubectl)
else
	kubectl_command=(kubectl)
fi
command -v "${kubectl_command[0]}" >/dev/null 2>&1 || {
	printf 'kubectl or k3s is required\n' >&2
	exit 1
}

# Write into a private temporary folder beside the target and move it into
# place only when every manifest was written. A failed run leaves the target
# absent, so the command can be run again.
staging="$(mktemp -d "$output_dir.partial.XXXXXX")"
report_partial() {
	local status=$?
	if [[ "$status" -ne 0 ]]; then
		printf 'failed. Partial output remains in %s. Delete it, because it may contain secrets.\n' "$staging" >&2
	fi
}
trap report_partial EXIT

"${kubectl_command[@]}" create configmap registry-identity-material \
	--namespace "$namespace" \
	--from-file="resources=$generated_dir/resources/resources.app-kit.yaml" \
	--from-file="postgres-ca.pem=$postgres_ca" \
	--dry-run=client -o yaml >"$staging/material.yaml"
"${kubectl_command[@]}" create configmap registry-identity-postgres-ca \
	--namespace "$namespace" \
	--from-file="postgres-ca.pem=$postgres_ca" \
	--dry-run=client -o yaml >"$staging/postgres-ca.yaml"
"${kubectl_command[@]}" create secret generic registry-identity-agent-type \
	--namespace "$namespace" \
	--from-file="$generated_dir/registry-schema/agent-type.yaml" \
	--dry-run=client -o yaml >"$staging/agent-type.yaml"
"${kubectl_command[@]}" create secret generic registry-identity-agents \
	--namespace "$namespace" \
	--from-file="agent.yaml=${agent_files[0]}" \
	--dry-run=client -o yaml >"$staging/agents.yaml"
chmod 0600 "$staging"/*.yaml
mv "$staging" "$output_dir"
trap - EXIT

printf 'Prepared generated identity material in %s.\n' "$output_dir"
