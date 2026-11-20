#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
	printf 'usage: %s THUNDERID_1_0_1_TGZ ABSENT_OUTPUT_DIR\n' "$0" >&2
	exit 2
fi
for tool in grep shasum tar perl mktemp; do
	command -v "$tool" >/dev/null 2>&1 || {
		printf '%s is required\n' "$tool" >&2
		exit 1
	}
done

chart_archive="$1"
output_dir="$2"
expected_digest="f6fd424047932405d3d8f50d6ef69798f10626563828c1d1bed186efba99dc4d"
actual_digest="$(shasum -a 256 "$chart_archive" | awk '{print $1}')"

if [[ "$actual_digest" != "$expected_digest" ]]; then
	printf 'ThunderID chart archive digest does not match the pinned 1.0.1 archive\n' >&2
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

# Build in a private temporary folder beside the target and move it into place
# only when every check has passed. A failed run leaves the target absent.
staging="$(mktemp -d "$output_dir.partial.XXXXXX")"
report_partial() {
	local status=$?
	if [[ "$status" -ne 0 ]]; then
		printf 'failed. Partial output remains in %s. Delete it before rerunning.\n' "$staging" >&2
	fi
}
trap report_partial EXIT

tar -xzf "$chart_archive" -C "$staging"
deployment_template="$staging/thunderid/templates/thunderid-deployment.yaml"
setup_template="$staging/thunderid/templates/setup-job.yaml"
lowercase='^[[:space:]]*- all$'
lowercase_count="$(count_matches "$lowercase" "$deployment_template" "$setup_template")" || exit 1
if [[ "$lowercase_count" != "2" ]]; then
	printf 'expected exactly two lowercase capability entries in chart 1.0.1, found %s\n' "$lowercase_count" >&2
	exit 1
fi
perl -pi -e 's/^(\s*)- all$/$1- ALL/' "$deployment_template" "$setup_template"
if [[ "$(count_matches "$lowercase" "$deployment_template" "$setup_template")" != "0" ]]; then
	printf 'lowercase capability entry remains after patch\n' >&2
	exit 1
fi

mv "$staging" "$output_dir"
trap - EXIT
printf 'Prepared the verified chart with only drop: [all] normalised to drop: [ALL] under %s.\n' "$output_dir/thunderid"
