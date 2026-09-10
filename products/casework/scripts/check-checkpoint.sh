#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
caseworkctl_bin=${CASEWORKCTL_BIN:-"$repo_root/target/debug/caseworkctl"}

cd "$repo_root"
python3 products/casework/scripts/generate_openapi.py --check
python3 products/casework/scripts/check_dependency_direction.py
python3 -m unittest discover -s products/casework/scripts -p 'test_*.py'

if [ ! -x "$caseworkctl_bin" ]; then
  echo "build caseworkctl first or set CASEWORKCTL_BIN" >&2
  exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/casework-checkpoint.XXXXXX")
cleanup() {
  case "$work" in
    "${TMPDIR:-/tmp}"/casework-checkpoint.*) rm -rf -- "$work" ;;
    *) exit 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

"$caseworkctl_bin" init "$work/project" --template professional-review >/dev/null
"$caseworkctl_bin" check "$work/project" >/dev/null
"$caseworkctl_bin" test "$work/project" >/dev/null
"$caseworkctl_bin" init "$work/standalone" --template standalone-decision >/dev/null
"$caseworkctl_bin" check "$work/standalone" >/dev/null
"$caseworkctl_bin" test "$work/standalone" >/dev/null
echo "Casework product contracts and offline authoring journey passed."
