#!/bin/sh
set -eu

# shellcheck disable=SC1007  # the space after CDPATH= is the POSIX empty-assignment idiom the sibling products use
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
schedulingctl_bin=${SCHEDULINGCTL_BIN:-"$repo_root/target/debug/schedulingctl"}

cd "$repo_root"
python3 products/scheduling/scripts/generate_openapi.py --check
python3 products/scheduling/scripts/check_dependency_direction.py
python3 -m unittest discover -s products/scheduling/scripts -p 'test_*.py'

if [ ! -x "$schedulingctl_bin" ]; then
  echo "build schedulingctl first or set SCHEDULINGCTL_BIN" >&2
  exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/scheduling-checkpoint.XXXXXX")
cleanup() {
  case "$work" in
    "${TMPDIR:-/tmp}"/scheduling-checkpoint.*) rm -rf -- "$work" ;;
    *) exit 1 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

for template in standalone-exact-time standalone-arrival-window; do
  "$schedulingctl_bin" init "$work/$template" --template "$template" >/dev/null
  "$schedulingctl_bin" check "$work/$template" >/dev/null
  "$schedulingctl_bin" test "$work/$template" >/dev/null
  "$schedulingctl_bin" explain "$work/$template" >/dev/null
done

# The package journey on a fresh project: the manifest the runtime verifies.
"$schedulingctl_bin" init "$work/package" --template standalone-exact-time >/dev/null
"$schedulingctl_bin" package "$work/package" >/dev/null

# The committed example is the starter template's output, so it can never
# drift from what an adopter initializes.
example="$repo_root/products/scheduling/examples/standalone-exact-time"
"$schedulingctl_bin" init "$work/example" --template standalone-exact-time >/dev/null
diff -r "$work/example" "$example" >/dev/null
"$schedulingctl_bin" check "$example" >/dev/null
"$schedulingctl_bin" test "$example" >/dev/null

echo "Scheduling product contracts and offline authoring journey passed."
