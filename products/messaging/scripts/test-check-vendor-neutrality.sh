#!/usr/bin/env bash
set -euo pipefail

# `check-vendor-neutrality.sh` is a text sweep, so nothing else in the tree
# proves it can still fail. This exercises it against a disposable sandbox
# shaped the way it expects, planting one violation at a time, and throws the
# sandbox away afterwards: the real tree is never modified.
#
# Two cases below plant a vendor name inside a `#[cfg(test)]` module and a
# doc comment. Both must still fail: unlike a gate that exempts test-only
# code, this one reads every .rs file whole, so a vendor name is not allowed
# even to name a test fixture.

CDPATH=''
scripts_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
gate_under_test="$scripts_directory/check-vendor-neutrality.sh"
sandbox_root=$(mktemp -d)
trap 'rm -rf "$sandbox_root"' EXIT HUP INT TERM

failures=0

swept_crates=(
  registry-messaging
  registry-messaging-core
  registry-messaging-client
  registry-messagingctl
)

build_pristine_tree() {
  local root="$sandbox_root/pristine"
  rm -rf "$root"
  mkdir -p "$root/products/messaging/scripts" "$root/products/messaging/generated"

  cp "$gate_under_test" "$root/products/messaging/scripts/check-vendor-neutrality.sh"

  local crate
  for crate in "${swept_crates[@]}"; do
    mkdir -p "$root/crates/$crate/src"
    printf '/// Sends one message through the configured provider.\npub fn dispatch() -> bool {\n    true\n}\n' \
      >"$root/crates/$crate/src/lib.rs"
  done

  printf '{"openapi": "3.1.0", "info": {"title": "Registry Messaging", "version": "1"}}\n' \
    >"$root/products/messaging/generated/registry-messaging.openapi.json"
}

run_case() {
  local name=$1 expectation=$2 plant=$3
  build_pristine_tree
  local root="$sandbox_root/case"
  rm -rf "$root"
  cp -R "$sandbox_root/pristine" "$root"
  "$plant" "$root"

  local status=0 output
  output=$("$root/products/messaging/scripts/check-vendor-neutrality.sh" 2>&1) || status=$?

  case "$expectation" in
  pass)
    if [[ "$status" -ne 0 ]]; then
      printf 'FAIL %s: expected the gate to pass, got status %s:\n%s\n' \
        "$name" "$status" "$output" >&2
      failures=$((failures + 1))
      return
    fi
    if [[ "$output" != *'vendor neutrality checks passed'* ]]; then
      printf 'FAIL %s: the gate passed without reporting that it did:\n%s\n' \
        "$name" "$output" >&2
      failures=$((failures + 1))
      return
    fi
    ;;
  fail)
    if [[ "$status" -eq 0 ]]; then
      printf 'FAIL %s: expected the gate to fail, it passed:\n%s\n' "$name" "$output" >&2
      failures=$((failures + 1))
      return
    fi
    ;;
  *)
    printf 'FAIL %s: unknown expectation %s\n' "$name" "$expectation" >&2
    failures=$((failures + 1))
    return
    ;;
  esac
  printf 'ok   %s\n' "$name"
}

plant_nothing() { :; }

plant_vendor_name_in_production_code() {
  printf 'pub const PROVIDER: &str = "twilio";\n' >>"$1/crates/registry-messaging-core/src/lib.rs"
}

plant_vendor_name_in_a_test_module() {
  printf '\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn sends_through_twilio() {\n        assert!(true);\n    }\n}\n' \
    >>"$1/crates/registry-messaging/src/lib.rs"
}

plant_vendor_name_in_a_doc_comment() {
  printf '\n/// Mirrors Vonage'"'"'s status callback shape.\npub fn note() {}\n' \
    >>"$1/crates/registry-messagingctl/src/lib.rs"
}

plant_vendor_name_in_generated_configuration() {
  printf '{"kind": "sendgrid"}\n' >>"$1/products/messaging/generated/registry-messaging.openapi.json"
}

plant_mixed_case_vendor_name() {
  printf 'pub const PROVIDER: &str = "SENDGRID";\n' >>"$1/crates/registry-messaging-client/src/lib.rs"
}

plant_vendor_word_as_a_substring() {
  # "sinch" is a vendor name; "sinchronize" is not, and must not false-positive.
  printf 'pub fn sinchronize() -> bool {\n    true\n}\n' >>"$1/crates/registry-messaging/src/lib.rs"
}

remove_a_named_source_root() {
  rm -rf "$1/crates/registry-messaging-client"
}

empty_every_source_root() {
  local crate
  for crate in "${swept_crates[@]}"; do
    rm -f "$1/crates/$crate/src/lib.rs"
  done
}

empty_the_published_configuration() {
  rm -f "$1/products/messaging/generated/registry-messaging.openapi.json"
}

run_case 'a clean tree passes' pass plant_nothing
run_case 'a vendor name in production code fails' \
  fail plant_vendor_name_in_production_code
run_case 'a vendor name in a #[cfg(test)] module fails' \
  fail plant_vendor_name_in_a_test_module
run_case 'a vendor name in a doc comment fails' \
  fail plant_vendor_name_in_a_doc_comment
run_case 'a vendor name in generated configuration fails' \
  fail plant_vendor_name_in_generated_configuration
run_case 'a mixed-case vendor name fails' \
  fail plant_mixed_case_vendor_name
run_case 'a vendor name embedded in a longer identifier passes' \
  pass plant_vendor_word_as_a_substring
run_case 'a named source root that no longer exists fails' \
  fail remove_a_named_source_root
run_case 'a tree with no runtime Rust left to search fails' \
  fail empty_every_source_root
run_case 'a tree with no published configuration left to search fails' \
  fail empty_the_published_configuration

if [[ "$failures" -ne 0 ]]; then
  printf '%s vendor-neutrality gate case(s) failed.\n' "$failures" >&2
  exit 1
fi

printf 'The Messaging vendor-neutrality gate reports every planted violation.\n'
