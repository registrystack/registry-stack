#!/usr/bin/env bash
set -euo pipefail

# Refuse a Linux binary that needs a newer glibc than the supported floor.
#
# A binary records the highest versioned glibc symbol it imports, and the
# dynamic linker refuses to start it on any system whose glibc is older. That
# refusal happens at first run, long after an installer reported success, so
# the release build checks it here instead.
#
# The floor lives in release/glibc-floor.env and is read, never repeated.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
floor_file="${script_dir}/../glibc-floor.env"

usage() {
  cat <<'USAGE'
usage: check-glibc-floor.sh <binary>...

Fails when any named binary requires a glibc newer than the release floor,
or when a binary imports a strong symbol no library version can satisfy.
USAGE
}

if [[ "$#" -eq 0 ]]; then
  usage >&2
  exit 2
fi
if [[ "${1}" == "--help" || "${1}" == "-h" ]]; then
  usage
  exit 0
fi

# shellcheck source-path=SCRIPTDIR
# shellcheck source=../glibc-floor.env
. "${floor_file}"
floor="${REGISTRY_GLIBC_FLOOR:?REGISTRY_GLIBC_FLOOR is required}"
if [[ ! "${floor}" =~ ^[0-9]+\.[0-9]+$ ]]; then
  printf '%s must name a MAJOR.MINOR glibc version, got %s\n' \
    "${floor_file}" "${floor}" >&2
  exit 2
fi
floor_symbol="GLIBC_${floor}"

failures=0
for binary in "$@"; do
  if [[ ! -f "${binary}" ]]; then
    printf '%s is not a file\n' "${binary}" >&2
    failures=$((failures + 1))
    continue
  fi

  # readelf is read into a variable first so a file it cannot parse reports the
  # reason instead of ending the run through pipefail with nothing on stderr.
  if ! version_info="$(readelf --version-info "${binary}" 2>&1)"; then
    printf '%s could not be read by readelf:\n%s\n' "${binary}" "${version_info}" >&2
    failures=$((failures + 1))
    continue
  fi
  highest_glibc="$(
    printf '%s\n' "${version_info}" \
      | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' \
      | sort -Vu \
      | tail -1 \
      || true
  )"
  if [[ -z "${highest_glibc}" ]]; then
    printf '%s imports no versioned glibc symbol, so its floor cannot be read\n' \
      "${binary}" >&2
    failures=$((failures + 1))
    continue
  fi

  # An import with no version and no weak marker binds to whatever the host
  # happens to export, which is how a binary passes a version check and still
  # fails to start. Report it beside the floor rather than after a release.
  if ! dynamic_symbols="$(readelf --wide --dyn-syms "${binary}" 2>&1)"; then
    printf '%s could not be read by readelf:\n%s\n' "${binary}" "${dynamic_symbols}" >&2
    failures=$((failures + 1))
    continue
  fi
  unversioned_imports="$(
    printf '%s\n' "${dynamic_symbols}" \
      | awk '$7 == "UND" && $5 != "WEAK" && $8 !~ /@/ { print $8 }' \
      | sort -u
  )"
  if [[ -n "${unversioned_imports}" ]]; then
    printf '%s has strong unversioned imports:\n%s\n' \
      "${binary}" "${unversioned_imports}" >&2
    failures=$((failures + 1))
    continue
  fi

  if [[ "$(printf '%s\n' "${floor_symbol}" "${highest_glibc}" | sort -V | tail -1)" != \
        "${floor_symbol}" ]]; then
    printf '%s requires %s above the %s floor\n' \
      "${binary}" "${highest_glibc}" "${floor_symbol}" >&2
    failures=$((failures + 1))
    continue
  fi

  printf '%s requires %s, at or below the %s floor\n' \
    "${binary}" "${highest_glibc}" "${floor_symbol}"
done

if [[ "${failures}" -ne 0 ]]; then
  printf 'glibc floor check failed for %d of %d binaries\n' \
    "${failures}" "$#" >&2
  exit 1
fi
