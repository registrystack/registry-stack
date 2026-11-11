#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
	printf 'usage: %s THUNDERID_1_0_1_TGZ ABSENT_OUTPUT_DIR\n' "$0" >&2
	exit 2
fi

chart_archive="$1"
output_dir="$2"
expected_digest="f6fd424047932405d3d8f50d6ef69798f10626563828c1d1bed186efba99dc4d"
actual_digest="$(shasum -a 256 "$chart_archive" | awk '{print $1}')"

if [[ "$actual_digest" != "$expected_digest" ]]; then
	printf 'ThunderID chart content digest does not match beta-58\n' >&2
	exit 1
fi
if [[ -e "$output_dir" ]]; then
	printf 'output directory already exists\n' >&2
	exit 1
fi

mkdir -m 0700 "$output_dir"
tar -xzf "$chart_archive" -C "$output_dir"
deployment_template="$output_dir/thunderid/templates/thunderid-deployment.yaml"
setup_template="$output_dir/thunderid/templates/setup-job.yaml"
lowercase_count="$({ rg -n '^\s*- all$' "$deployment_template" "$setup_template" || true; } | wc -l | tr -d ' ')"
if [[ "$lowercase_count" != "2" ]]; then
	printf 'expected exactly two lowercase capability entries in chart 1.0.1\n' >&2
	exit 1
fi
perl -pi -e 's/^(\s*)- all$/$1- ALL/' "$deployment_template" "$setup_template"
if rg -q '^\s*- all$' "$deployment_template" "$setup_template"; then
	printf 'lowercase capability entry remains after patch\n' >&2
	exit 1
fi

printf 'Prepared the verified chart with only drop: [all] normalized to drop: [ALL] under %s.\n' "$output_dir/thunderid"
