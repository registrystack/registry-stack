#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
	printf 'usage: %s GENERATED_DIR POSTGRES_CA_PEM ABSENT_OUTPUT_DIR\n' "$0" >&2
	exit 2
fi

generated_dir="$1"
postgres_ca="$2"
output_dir="$3"

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

if command -v k3s >/dev/null 2>&1; then
	kubectl_command=(sudo -n k3s kubectl)
else
	kubectl_command=(kubectl)
fi
command -v "${kubectl_command[0]}" >/dev/null 2>&1 || {
	printf 'kubectl or k3s is required\n' >&2
	exit 1
}

mkdir -m 0700 "$output_dir"
"${kubectl_command[@]}" create configmap registry-identity-material \
	--namespace registry-identity-qualification \
	--from-file="resources=$generated_dir/resources/resources.app-kit.yaml" \
	--from-file="postgres-ca.pem=$postgres_ca" \
	--dry-run=client -o yaml >"$output_dir/material.yaml"
"${kubectl_command[@]}" create secret generic registry-identity-agent-type \
	--namespace registry-identity-qualification \
	--from-file="$generated_dir/registry-schema/agent-type.yaml" \
	--dry-run=client -o yaml >"$output_dir/agent-type.yaml"
"${kubectl_command[@]}" create secret generic registry-identity-agents \
	--namespace registry-identity-qualification \
	--from-file="$generated_dir/registry-schema/agents" \
	--dry-run=client -o yaml >"$output_dir/agents.yaml"
chmod 0600 "$output_dir"/*.yaml

printf 'Prepared generated identity material in %s.\n' "$output_dir"
