#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

features="${1-}"

fail() {
  printf 'invalid Registry Relay feature profile: %s\n' "$1" >&2
  exit 1
}

case "$features" in
  *[!a-z0-9,-]*)
    fail "use comma-separated Cargo feature names"
    ;;
  ,*|*,|*,,*)
    fail "feature list must not contain empty entries"
    ;;
esac

has_feature() {
  case ",$features," in
    *,"$1",*) return 0 ;;
    *) return 1 ;;
  esac
}

seen=","
if [ -n "$features" ]; then
  previous_ifs=$IFS
  IFS=,
  for feature in $features; do
    case "$seen" in
      *,"$feature",*) fail "duplicate feature: $feature" ;;
    esac
    seen="${seen}${feature},"
  done
  IFS=$previous_ifs
fi

for feature in attribute-release standards-cel-mapping; do
  if has_feature "$feature" && ! has_feature crosswalk-runtime; then
    fail "$feature requires crosswalk-runtime"
  fi
done
