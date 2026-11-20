#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
	printf 'usage: %s RESTRICTED_THUNDERID_CHART_DIR ABSENT_OUTPUT_DIR\n' "$0" >&2
	exit 2
fi
command -v grep >/dev/null 2>&1 || {
	printf 'grep is required\n' >&2
	exit 1
}

source_chart="$1"
output_dir="$2"
source_deployment="$source_chart/templates/thunderid-deployment.yaml"
source_pvc="$source_chart/templates/pvc.yaml"
source_setup="$source_chart/templates/setup-job.yaml"

# Count lines matching an extended regular expression across files. grep exits
# 1 for no match, which is a count of zero. Any higher status is a tool failure.
count_matches() {
	local pattern="$1" file status total=0 count
	shift
	for file in "$@"; do
		status=0
		count="$(grep -c -E -e "$pattern" "$file")" || status=$?
		if [[ "$status" -gt 1 ]]; then
			printf 'grep failed on %s\n' "$file" >&2
			return 1
		fi
		total=$((total + count))
	done
	printf '%s' "$total"
}

# Succeed when a fixed string occurs in a file. Fail on a grep tool error.
contains() {
	local status=0
	grep -F -q -e "$1" "$2" || status=$?
	if [[ "$status" -gt 1 ]]; then
		printf 'grep failed on %s\n' "$2" >&2
		exit 1
	fi
	return "$status"
}

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
if [[ ! -d "$(dirname "$output_dir")" ]]; then
	printf 'parent of the output directory does not exist\n' >&2
	exit 1
fi

setup_gate='^[[:space:]]*\{\{- if \.Values\.setup\.enabled \}\}$'
restored_gate='^[[:space:]]*\{\{- if or \.Values\.setup\.enabled \.Values\.restoreExistingState \}\}$'

mount_gate_count="$(count_matches "$setup_gate" "$source_deployment" "$source_pvc")" || exit 1
if [[ "$mount_gate_count" != "3" ]]; then
	printf 'expected exactly three setup-gated state mounts in chart 1.0.1, found %s\n' "$mount_gate_count" >&2
	exit 1
fi
if [[ "$(count_matches "$setup_gate" "$source_setup")" == "0" ]]; then
	printf 'setup Job condition changed unexpectedly\n' >&2
	exit 1
fi

# Build in a private temporary folder beside the target and move it into place
# only when every check has passed. A failed run leaves the target absent.
staging="$(mktemp -d "$output_dir.partial.XXXXXX")"
report_partial() {
	local status=$?
	if [[ "$status" -ne 0 ]]; then
		printf 'failed. Partial output remains in %s. Delete it, because it may contain secrets.\n' "$staging" >&2
	fi
}
trap report_partial EXIT

cp -R "$source_chart"/. "$staging"/
deployment_template="$staging/templates/thunderid-deployment.yaml"
pvc_template="$staging/templates/pvc.yaml"
setup_template="$staging/templates/setup-job.yaml"
perl -pi -e 's/\{\{- if \.Values\.setup\.enabled \}\}/{{- if or .Values.setup.enabled .Values.restoreExistingState }}/' \
	"$deployment_template" "$pvc_template"

restored_gate_count="$(count_matches "$restored_gate" "$deployment_template" "$pvc_template")" || exit 1
if [[ "$restored_gate_count" != "3" ]]; then
	printf 'restored-state condition was not applied to exactly three state mounts\n' >&2
	exit 1
fi
if contains 'restoreExistingState' "$setup_template" || [[ "$(count_matches "$setup_gate" "$setup_template")" == "0" ]]; then
	printf 'setup Job condition changed unexpectedly\n' >&2
	exit 1
fi

mv "$staging" "$output_dir"
trap - EXIT
printf 'Prepared a setup-disabled restored-state chart under %s.\n' "$output_dir"
