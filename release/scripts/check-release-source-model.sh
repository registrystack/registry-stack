#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_dir="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${release_dir}/.." && pwd)"
# REGISTRY_LAB_RELEASE_SOURCE_MODE is the deprecated name for
# REGISTRY_RELEASE_SOURCE_MODE, kept as a fallback until callers migrate.
mode="${1:-${REGISTRY_RELEASE_SOURCE_MODE:-${REGISTRY_LAB_RELEASE_SOURCE_MODE:-monorepo}}}"
allow_pending_pins="${REGISTRY_LAB_ALLOW_PENDING_PINS:-0}"

resolve_dir() {
	local raw="$1"
	local candidate
	if [[ "${raw}" = /* ]]; then
		candidate="${raw}"
	else
		candidate="${release_dir}/${raw}"
	fi
	python3 - "${candidate}" <<'PY'
import sys
from pathlib import Path

print(Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
}

repo_head() {
	git -C "$1" rev-parse HEAD
}

dirty_count() {
	git -C "$1" status --short | wc -l | tr -d ' '
}

relative_to_release_dir() {
	local path="$1"
	local resolved_release_dir
	resolved_release_dir="$(resolve_dir "${release_dir}")"
	case "${path}" in
	"${resolved_release_dir}"/*)
		printf '%s\n' "${path#"${resolved_release_dir}/"}"
		;;
	*)
		echo "release source model failed: ${path} is outside ${resolved_release_dir}" >&2
		exit 2
		;;
	esac
}

gitlink_head() {
	local name="$1"
	local rel_path="$2"
	local entry
	local mode
	local object
	entry="$(git -C "${release_dir}" ls-files -s -- "${rel_path}")"
	if [[ -z "${entry}" ]]; then
		echo "release source model failed: ${name} has no committed gitlink at ${rel_path}" >&2
		exit 2
	fi
	read -r mode object _ <<<"${entry}"
	if [[ "${mode}" != "160000" ]]; then
		echo "release source model failed: ${name} at ${rel_path} is not a submodule gitlink" >&2
		exit 2
	fi
	printf '%s\n' "${object}"
}

require_clean_committed_submodule() {
	local name="$1"
	local path="$2"
	local rel_path
	local status_line
	local status_prefix
	local expected_head
	local actual_head
	local dirty_paths
	rel_path="$(relative_to_release_dir "${path}")"
	expected_head="$(gitlink_head "${name}" "${rel_path}")"
	status_line="$(git -C "${release_dir}" submodule status -- "${rel_path}")"
	if [[ -z "${status_line}" ]]; then
		echo "release source model failed: ${name} has no submodule status at ${rel_path}" >&2
		exit 2
	fi
	status_prefix="${status_line:0:1}"
	case "${status_prefix}" in
	-)
		echo "release source model failed: ${name} submodule is not initialized at ${rel_path}" >&2
		exit 1
		;;
	+)
		echo "release source model failed: ${name} submodule HEAD does not match committed gitlink at ${rel_path}" >&2
		exit 1
		;;
	U)
		echo "release source model failed: ${name} submodule has merge conflicts at ${rel_path}" >&2
		exit 1
		;;
	esac
	require_cargo_repo "${name}" "${path}"
	actual_head="$(repo_head "${path}")"
	dirty_paths="$(dirty_count "${path}")"
	printf 'release-source %s %s %s gitlink=%s dirty=%s\n' "${name}" "${path}" "${actual_head}" "${expected_head}" "${dirty_paths}"
	if [[ "${actual_head}" != "${expected_head}" ]]; then
		echo "release source model failed: ${name} checkout ${actual_head} does not match committed gitlink ${expected_head}" >&2
		exit 1
	fi
	if [[ "${dirty_paths}" != "0" ]]; then
		echo "release source model failed: ${name} vendor checkout has ${dirty_paths} dirty path(s)" >&2
		exit 1
	fi
}

require_cargo_repo() {
	local name="$1"
	local path="$2"
	if [[ ! -f "${path}/Cargo.toml" ]]; then
		echo "release source model failed: ${name} checkout not found at ${path}" >&2
		exit 2
	fi
}

require_path() {
	local name="$1"
	local path="$2"
	if [[ ! -e "${path}" ]]; then
		echo "release source model failed: ${name} not found at ${path}" >&2
		exit 2
	fi
}

expect_path() {
	local name="$1"
	local configured="$2"
	local expected="$3"
	local resolved_configured
	local resolved_expected
	resolved_configured="$(resolve_dir "${configured}")"
	resolved_expected="$(resolve_dir "${expected}")"
	if [[ "${resolved_configured}" != "${resolved_expected}" ]]; then
		echo "release source model failed: ${name} must use ${resolved_expected}, got ${resolved_configured}" >&2
		exit 2
	fi
	require_cargo_repo "${name}" "${resolved_configured}"
	printf 'release-source %s %s %s\n' "${name}" "${resolved_configured}" "$(repo_head "${resolved_configured}")"
}

expect_vendor_path() {
	local name="$1"
	local configured="$2"
	local expected="$3"
	local resolved_configured
	local resolved_expected
	resolved_configured="$(resolve_dir "${configured}")"
	resolved_expected="$(resolve_dir "${expected}")"
	if [[ "${resolved_configured}" != "${resolved_expected}" ]]; then
		echo "release source model failed: ${name} must use ${resolved_expected}, got ${resolved_configured}" >&2
		exit 2
	fi
	require_clean_committed_submodule "${name}" "${resolved_configured}"
}

compare_pin() {
	local name="$1"
	local source_dir="$2"
	local vendor_dir="$3"
	local source_head
	local vendor_head
	local source_dirty
	source_head="$(repo_head "${source_dir}")"
	vendor_head="$(repo_head "${vendor_dir}")"
	source_dirty="$(dirty_count "${source_dir}")"
	printf 'release-source %s source %s %s dirty=%s\n' "${name}" "${source_dir}" "${source_head}" "${source_dirty}"
	printf 'release-source %s vendor %s %s\n' "${name}" "${vendor_dir}" "${vendor_head}"
	if [[ "${source_head}" != "${vendor_head}" ]]; then
		pending=1
		echo "pending-pin ${name}: vendor ${vendor_head} does not match source ${source_head}" >&2
	fi
	if [[ "${source_dirty}" != "0" ]]; then
		pending=1
		echo "pending-source-clean ${name}: source checkout has ${source_dirty} dirty path(s)" >&2
	fi
}

has_custom_cel_mapping_source_dir() {
	case "${CEL_MAPPING_SOURCE_DIR:-}" in
	"" | "./vendor/cel-mapping" | "vendor/cel-mapping" | "${release_dir}/vendor/cel-mapping")
		return 1
		;;
	esac
	[[ -d "${CEL_MAPPING_SOURCE_DIR}" ]]
}

# Legacy Lab checkouts still keep the Crosswalk submodule at lab/vendor/crosswalk;
# a fresh release/ checkout has no vendor/ directory of its own. Prefer the Lab
# checkout while it exists so in-place upgrades keep working, and fall back to
# a release/-relative default once lab/ is gone.
default_crosswalk_dir() {
	local legacy_lab_crosswalk="${repo_root}/lab/vendor/crosswalk"
	if [[ -d "${legacy_lab_crosswalk}" ]]; then
		printf '%s\n' "${legacy_lab_crosswalk}"
	else
		printf '%s\n' "${release_dir}/vendor/crosswalk"
	fi
}

vendor_platform="${release_dir}/vendor/registry-platform"
vendor_relay="${release_dir}/vendor/registry-relay"
vendor_notary="${release_dir}/vendor/registry-notary"
vendor_manifest="${release_dir}/vendor/registry-manifest"
vendor_crosswalk="${release_dir}/vendor/crosswalk"
# CEL_MAPPING_SOURCE_DIR is the deprecated name for CROSSWALK_SOURCE_DIR; the
# fallback keeps old operator environments working until they migrate.
if [[ -n "${CROSSWALK_SOURCE_DIR:-}" ]]; then
	crosswalk_source_dir="${CROSSWALK_SOURCE_DIR}"
elif has_custom_cel_mapping_source_dir; then
	crosswalk_source_dir="${CEL_MAPPING_SOURCE_DIR}"
else
	crosswalk_source_dir="${vendor_crosswalk}"
fi

case "${mode}" in
vendor)
	expect_vendor_path "registry-platform" "${REGISTRY_PLATFORM_SOURCE_DIR:-${vendor_platform}}" "${vendor_platform}"
	expect_vendor_path "registry-relay-platform" "${REGISTRY_RELAY_PLATFORM_SOURCE_DIR:-${REGISTRY_PLATFORM_SOURCE_DIR:-${vendor_platform}}}" "${vendor_platform}"
	expect_vendor_path "registry-notary-platform" "${REGISTRY_NOTARY_PLATFORM_SOURCE_DIR:-${REGISTRY_PLATFORM_SOURCE_DIR:-${vendor_platform}}}" "${vendor_platform}"
	expect_vendor_path "registry-relay" "${REGISTRY_RELAY_SOURCE_DIR:-${vendor_relay}}" "${vendor_relay}"
	expect_vendor_path "registry-notary" "${REGISTRY_NOTARY_SOURCE_DIR:-${vendor_notary}}" "${vendor_notary}"
	expect_vendor_path "registry-openfn-notary" "${REGISTRY_OPENFN_NOTARY_SOURCE_DIR:-${REGISTRY_NOTARY_SOURCE_DIR:-${vendor_notary}}}" "${vendor_notary}"
	expect_vendor_path "registry-manifest" "${REGISTRY_MANIFEST_REPO:-${vendor_manifest}}" "${vendor_manifest}"
	expect_vendor_path "crosswalk" "${crosswalk_source_dir}" "${vendor_crosswalk}"
	;;
source)
	platform_dir="$(resolve_dir "${REGISTRY_PLATFORM_SOURCE_DIR:-../registry-platform}")"
	relay_dir="$(resolve_dir "${REGISTRY_RELAY_SOURCE_DIR:-../registry-relay}")"
	notary_dir="$(resolve_dir "${REGISTRY_NOTARY_SOURCE_DIR:-../registry-notary}")"
	relay_platform_dir="$(resolve_dir "${REGISTRY_RELAY_PLATFORM_SOURCE_DIR:-${platform_dir}}")"
	notary_platform_dir="$(resolve_dir "${REGISTRY_NOTARY_PLATFORM_SOURCE_DIR:-${platform_dir}}")"
	openfn_notary_dir="$(resolve_dir "${REGISTRY_OPENFN_NOTARY_SOURCE_DIR:-${notary_dir}}")"
	manifest_dir="$(resolve_dir "${REGISTRY_MANIFEST_REPO:-${vendor_manifest}}")"
	if [[ -n "${CROSSWALK_SOURCE_DIR:-}" ]]; then
		crosswalk_dir="$(resolve_dir "${crosswalk_source_dir}")"
	else
		crosswalk_dir="$(resolve_dir "$(default_crosswalk_dir)")"
	fi

	require_cargo_repo "registry-platform" "${platform_dir}"
	require_cargo_repo "registry-relay" "${relay_dir}"
	require_cargo_repo "registry-notary" "${notary_dir}"
	expect_path "registry-relay-platform" "${relay_platform_dir}" "${platform_dir}"
	expect_path "registry-notary-platform" "${notary_platform_dir}" "${platform_dir}"
	expect_path "registry-openfn-notary" "${openfn_notary_dir}" "${notary_dir}"
	require_cargo_repo "registry-manifest" "${manifest_dir}"
	require_cargo_repo "crosswalk" "${crosswalk_dir}"

	pending=0
	compare_pin "registry-platform" "${platform_dir}" "${vendor_platform}"
	compare_pin "registry-relay" "${relay_dir}" "${vendor_relay}"
	compare_pin "registry-notary" "${notary_dir}" "${vendor_notary}"
	printf 'release-source registry-manifest %s %s\n' "${manifest_dir}" "$(repo_head "${manifest_dir}")"
	printf 'release-source crosswalk %s %s\n' "${crosswalk_dir}" "$(repo_head "${crosswalk_dir}")"

	if [[ "${pending}" != "0" && "${allow_pending_pins}" != "1" ]]; then
		echo "release source model failed: source proof has pending Lab pin or dirty source state; set REGISTRY_LAB_ALLOW_PENDING_PINS=1 only before the final Lab pin/tag update" >&2
		exit 1
	fi
	;;
monorepo)
	stack_root="$(resolve_dir "${REGISTRY_STACK_SOURCE_DIR:-..}")"
	stack_git_root="$(git -C "${stack_root}" rev-parse --show-toplevel)"
	stack_head="$(repo_head "${stack_root}")"
	stack_dirty="$(dirty_count "${stack_root}")"
	require_cargo_repo "registry-stack" "${stack_root}"
	require_path "registry-platform crates" "${stack_root}/crates/registry-platform-authcommon"
	require_path "registry-manifest crates" "${stack_root}/crates/registry-manifest-core"
	require_path "registry-notary crates" "${stack_root}/crates/registry-notary-server"
	require_path "registry-relay crate" "${stack_root}/crates/registry-relay"
	require_path "registryctl crate" "${stack_root}/crates/registryctl"
	if [[ "${stack_git_root}" != "${stack_root}" ]]; then
		echo "release source model failed: registry-stack source dir must be the monorepo root, got ${stack_root} inside ${stack_git_root}" >&2
		exit 2
	fi
	printf 'release-source registry-stack %s %s dirty=%s\n' "${stack_root}" "${stack_head}" "${stack_dirty}"
	# Crosswalk, registry-atlas, and the eSignet Relay authenticator pins are
	# release provenance, not proven here: release/manifests/registry-stack-*.yaml
	# records them and `registry-release validate`/`validate-source` checks them.
	;;
*)
	echo "usage: REGISTRY_RELEASE_SOURCE_MODE=vendor|source|monorepo scripts/check-release-source-model.sh [vendor|source|monorepo]" >&2
	exit 2
	;;
esac
