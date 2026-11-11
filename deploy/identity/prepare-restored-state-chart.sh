#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
	printf 'usage: %s RESTRICTED_THUNDERID_CHART_DIR ABSENT_OUTPUT_DIR\n' "$0" >&2
	exit 2
fi

source_chart="$1"
output_dir="$2"
source_deployment="$source_chart/templates/thunderid-deployment.yaml"
source_pvc="$source_chart/templates/pvc.yaml"
source_setup="$source_chart/templates/setup-job.yaml"

for required in "$source_chart/Chart.yaml" "$source_deployment" "$source_pvc" "$source_setup"; do
	if [[ ! -f "$required" ]]; then
		printf 'required Restricted chart file is missing: %s\n' "$required" >&2
		exit 1
	fi
done
if [[ -e "$output_dir" ]]; then
	printf 'output directory already exists\n' >&2
	exit 1
fi

mount_gate_count="$({ rg -n '^\s*\{\{- if \.Values\.setup\.enabled \}\}$' "$source_deployment" "$source_pvc" || true; } | wc -l | tr -d ' ')"
if [[ "$mount_gate_count" != "3" ]]; then
	printf 'expected exactly three setup-gated state mounts in chart 1.0.1\n' >&2
	exit 1
fi
if ! rg -q '^\{\{- if \.Values\.setup\.enabled \}\}$' "$source_setup"; then
	printf 'setup Job condition changed unexpectedly\n' >&2
	exit 1
fi

mkdir -m 0700 "$output_dir"
cp -R "$source_chart"/. "$output_dir"/
deployment_template="$output_dir/templates/thunderid-deployment.yaml"
pvc_template="$output_dir/templates/pvc.yaml"
setup_template="$output_dir/templates/setup-job.yaml"
perl -pi -e 's/\{\{- if \.Values\.setup\.enabled \}\}/{{- if or .Values.setup.enabled .Values.restoreExistingState }}/' \
	"$deployment_template" "$pvc_template"

restored_gate_count="$({ rg -n '^\s*\{\{- if or \.Values\.setup\.enabled \.Values\.restoreExistingState \}\}$' "$deployment_template" "$pvc_template" || true; } | wc -l | tr -d ' ')"
if [[ "$restored_gate_count" != "3" ]]; then
	printf 'restored-state condition was not applied to exactly three state mounts\n' >&2
	exit 1
fi
if rg -q 'restoreExistingState' "$setup_template" || ! rg -q '^\{\{- if \.Values\.setup\.enabled \}\}$' "$setup_template"; then
	printf 'setup Job condition changed unexpectedly\n' >&2
	exit 1
fi

printf 'Prepared a setup-disabled restored-state chart under %s.\n' "$output_dir"
