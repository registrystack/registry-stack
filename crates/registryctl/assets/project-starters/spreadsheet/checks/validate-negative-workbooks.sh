#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Exercise maintained invalid workbooks against temporary copies of this
# canonical project. The source project and its positive workbook are read-only
# inputs to this check.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
REGISTRYCTL="${REGISTRYCTL_BIN:-registryctl}"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/registryctl-spreadsheet-negatives.XXXXXX")"

cleanup() {
	rm -rf -- "$WORK_ROOT"
}
trap cleanup EXIT HUP INT TERM

fail() {
	printf 'spreadsheet negative checks: FAIL (%s)\n' "$1" >&2
	exit 1
}

snapshot_project() {
	(
		cd "$PROJECT_ROOT"
		find . -type f -print0 |
			LC_ALL=C sort -z |
			xargs -0 sha256sum
	) | sha256sum | awk '{print $1}'
}

assert_value_free() {
	local output=$1
	if grep -Eq 'PW-1000|PW-001|D-01|roads|active|calculated|1\+1' "$output"; then
		fail 'a workbook value or formula appeared in diagnostics'
	fi
}

run_rejected_case() {
	local case_name=$1
	local fixture_name=$2
	local relay_category=$3
	local case_root="$WORK_ROOT/$case_name/project"
	local init_log="$WORK_ROOT/$case_name/init.log"
	local preflight_log="$WORK_ROOT/$case_name/preflight.log"
	local check_log="$WORK_ROOT/$case_name/check.log"
	local status

	mkdir -p "$WORK_ROOT/$case_name"
	"$REGISTRYCTL" init \
		--from spreadsheet \
		--project-dir "$case_root" >"$init_log" 2>&1 ||
		fail "$case_name canonical project initialization failed"
	[[ -f "$case_root/checks/fixtures/$fixture_name" &&
		! -L "$case_root/checks/fixtures/$fixture_name" ]] ||
		fail "$case_name canonical fixture is missing or unsafe"
	cp "$case_root/checks/fixtures/$fixture_name" \
		"$case_root/data/public_works_projects.xlsx"

	set +e
	"$REGISTRYCTL" preflight \
		--project-dir "$case_root" \
		--environment local \
		--format json >"$preflight_log" 2>&1
	status=$?
	set -e
	if ((status == 0)); then
		fail "$case_name preflight accepted an invalid workbook"
	fi
	grep -Fq 'registryctl.preflight.runtime_file_content_invalid' "$preflight_log" ||
		fail "$case_name preflight omitted its stable content category"
	assert_value_free "$preflight_log"

	set +e
	"$REGISTRYCTL" check \
		--project-dir "$case_root" \
		--environment local >"$check_log" 2>&1
	status=$?
	set -e
	if ((status == 0)); then
		fail "$case_name check accepted an invalid workbook"
	fi
	grep -Fq "workbook validation failed ($relay_category)" "$check_log" ||
		fail "$case_name check omitted its stable Relay category"
	assert_value_free "$check_log"
}

command -v "$REGISTRYCTL" >/dev/null 2>&1 ||
	fail 'registryctl is not available'

export REGISTRYCTL_NO_UPDATE_CHECK=1
before="$(snapshot_project)"
run_rejected_case \
	'duplicate-primary-key' \
	'duplicate_primary_key_after_1000.xlsx' \
	'ingest.schema_mismatch'
run_rejected_case \
	'formula-source' \
	'formula_outside_projection.xlsx' \
	'ingest.source_unreadable'
after="$(snapshot_project)"
[[ "$before" == "$after" ]] ||
	fail 'the source project changed'

printf '%s\n' \
	'spreadsheet negative checks: PASS' \
	'  duplicate primary key: registryctl.preflight.runtime_file_content_invalid; ingest.schema_mismatch' \
	'  formula source: registryctl.preflight.runtime_file_content_invalid; ingest.source_unreadable' \
	'  source project: unchanged'
