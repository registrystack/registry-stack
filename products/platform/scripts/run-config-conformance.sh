#!/usr/bin/env bash
# Run the configuration conformance corpus against built check commands.
#
#   products/platform/scripts/run-config-conformance.sh [--bin-dir DIR] [--strict] [--matrix] ...
#
# Every option is the Python runner's; see run-config-conformance.py.
#
# The adapterctl binary comes from, most explicit first:
#   1. the --bin-dir option,
#   2. the ADAPTERCTL_BIN environment variable (the adapterctl binary; the
#      file must be named adapterctl),
#   3. a build under the exported CARGO_TARGET_DIR,
# and the wrapper refuses otherwise. A repo-local target/ directory is
# never used: a stale binary there once checked green against the wrong
# reader, which passed the corpus silently.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${script_dir}/../../.." && pwd)"

bin_dir=''
previous=''
for argument in "$@"; do
	case "$argument" in
	--bin-dir=*) bin_dir="${argument#--bin-dir=}" ;;
	*)
		if [[ "$previous" == '--bin-dir' ]]; then
			bin_dir="$argument"
		fi
		;;
	esac
	previous="$argument"
done

if [[ -z "$bin_dir" ]]; then
	if [[ -n "${ADAPTERCTL_BIN:-}" ]]; then
		if [[ ! -x "${ADAPTERCTL_BIN}" ]]; then
			printf 'run-config-conformance: ADAPTERCTL_BIN names no executable: %s\n' "${ADAPTERCTL_BIN}" >&2
			printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR.\n' >&2
			exit 2
		fi
		if [[ "${ADAPTERCTL_BIN##*/}" != "adapterctl" ]]; then
			printf 'run-config-conformance: ADAPTERCTL_BIN must name a file called adapterctl: %s\n' "${ADAPTERCTL_BIN}" >&2
			printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR.\n' >&2
			exit 2
		fi
		bin_dir="$(cd "$(dirname "${ADAPTERCTL_BIN}")" && pwd -P)"
	elif [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
		command -v cargo >/dev/null 2>&1 || {
			printf 'run-config-conformance: CARGO_TARGET_DIR is set but cargo is not on PATH.\n' >&2
			exit 2
		}
		cargo build --locked -p registry-adapterctl --manifest-path "${root}/Cargo.toml" --target-dir "${CARGO_TARGET_DIR}"
		bin_dir="${CARGO_TARGET_DIR}/debug"
	else
		printf 'run-config-conformance: no adapterctl binary found.\n' >&2
		printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR; the repository target/ directory is never used.\n' >&2
		exit 2
	fi
fi

if [[ ! -x "${bin_dir}/adapterctl" ]]; then
	printf 'run-config-conformance: no adapterctl binary in %s.\n' "${bin_dir}" >&2
	printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR.\n' >&2
	exit 2
fi

# A debug build that links aws-lc-fips-sys dynamically on macOS needs its
# library at each check-command launch. Keep the directory in the non-DYLD
# carrier that survives uv's protected /usr/bin/env launcher; the Python runner
# restores DYLD_LIBRARY_PATH on the check child itself.
if [[ -z "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
	for artifacts in "${bin_dir}"/build/aws-lc-fips-sys-*/out/build/artifacts; do
		if [[ -d "$artifacts" ]]; then
			REGISTRY_CARGO_RUNTIME_LIBRARY_PATH="$(cd "$artifacts" && pwd -P)"
			export REGISTRY_CARGO_RUNTIME_LIBRARY_PATH
			break
		fi
	done
fi
if [[ -n "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
	export DYLD_FALLBACK_LIBRARY_PATH="${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
fi

exec uv run --no-project --with PyYAML==6.0.2 python "${script_dir}/run-config-conformance.py" "$@"
