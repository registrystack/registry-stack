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

seen=","
previous=""
if [ -n "$features" ]; then
  previous_ifs=$IFS
  IFS=,
  for feature in $features; do
    case "$seen" in
      *,"$feature",*) fail "duplicate feature: $feature" ;;
    esac
    seen="${seen}${feature},"
    if [ -n "$previous" ] && [ "$previous" \> "$feature" ]; then
      fail "feature list must use canonical alphabetical order"
    fi
    previous=$feature
  done
  IFS=$previous_ifs
fi
