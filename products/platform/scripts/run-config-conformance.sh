#!/usr/bin/env bash
# Run the configuration conformance corpus against built check commands.
#
#   products/platform/scripts/run-config-conformance.sh [--bin-dir DIR] [--strict] [--matrix] ...
#
# Every option is the Python runner's; see run-config-conformance.py.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${script_dir}/../../.." && pwd)"

bin_dir="${CARGO_TARGET_DIR:-${root}/target}/debug"
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

# A debug build that links aws-lc-fips-sys dynamically on macOS needs its
# library at each check-command launch. Keep the directory in the non-DYLD
# carrier that survives uv's protected /usr/bin/env launcher; the Python runner
# restores DYLD_LIBRARY_PATH on the check child itself.
if [[ -z "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
	for artifacts in "${bin_dir}"/build/aws-lc-fips-sys-*/out/build/artifacts; do
		if [[ -d "$artifacts" ]]; then
			export REGISTRY_CARGO_RUNTIME_LIBRARY_PATH="$(cd "$artifacts" && pwd -P)"
			break
		fi
	done
fi
if [[ -n "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
	export DYLD_FALLBACK_LIBRARY_PATH="${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
fi

exec uv run --no-project --with PyYAML==6.0.2 python "${script_dir}/run-config-conformance.py" "$@"
