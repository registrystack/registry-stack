#!/usr/bin/env bash
# Run the configuration conformance corpus against built check commands.
#
#   products/platform/scripts/run-config-conformance.sh [--bin-dir DIR] [--strict] [--matrix] ...
#
# Every option is the Python runner's; see run-config-conformance.py.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "${script_dir}/../../.." && pwd)"

bin_dir="${root}/target/debug"
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

# A debug build that links aws-lc-fips-sys dynamically on macOS finds its
# library through this path; elsewhere the variable has no effect.
if [[ -z "${DYLD_FALLBACK_LIBRARY_PATH:-}" ]]; then
	for artifacts in "${bin_dir}"/build/aws-lc-fips-sys-*/out/build/artifacts; do
		if [[ -d "$artifacts" ]]; then
			export DYLD_FALLBACK_LIBRARY_PATH="$artifacts"
			break
		fi
	done
fi

exec uv run --no-project --with PyYAML==6.0.2 python "${script_dir}/run-config-conformance.py" "$@"
