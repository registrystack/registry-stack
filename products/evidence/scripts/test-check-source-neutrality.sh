#!/usr/bin/env bash
set -euo pipefail

# `check-source-neutrality.sh` is the only Evidence gate whose subject is text
# rather than a program's behavior, so nothing else in the tree proves it can
# still fail. It once could not: an earlier version searched with ripgrep, which
# the hosted runner does not have, so every run reported a clean tree without
# reading a byte of it.
#
# This exercises the gate against a sandbox tree it can be pointed at, in the
# shape it expects, planting one violation at a time. Each case asserts an
# outcome the gate must produce, and the sandbox is thrown away afterwards, so
# the real tree is never modified.

CDPATH=''
scripts_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
gate_under_test="$scripts_directory/check-source-neutrality.sh"
sandbox_root=$(mktemp -d)
trap 'rm -rf "$sandbox_root"' EXIT HUP INT TERM

failures=0

# The sandbox mirrors only what the gate reads: every production source root, the
# shipped binding surface, the Cargo and package manifests, and the published
# configuration. `pristine` is rebuilt for every case, so no case can see
# another's planting.
#
# One list drives both the directories and the manifests, because the gate hard
# fails on a named path that is not there: a crate added to the gate and not here
# fails every case at once rather than the one it belongs to.
swept_crates=(
  registry-evidence
  registry-evidence-authoring
  registry-evidence-client
  registry-evidence-client-node
  registry-evidence-client-py
  registry-evidence-oid4vci
  registry-evidence-verifier
  registry-evidencectl
  registry-language-server
)

build_pristine_tree() {
  local root="$sandbox_root/pristine"
  rm -rf "$root"
  mkdir -p \
    "$root/products/evidence/scripts" \
    "$root/products/evidence/generated" \
    "$root/products/evidence/contracts" \
    "$root/crates/registry-evidence-client-py/python/registry_evidence_client"

  cp "$gate_under_test" "$root/products/evidence/scripts/check-source-neutrality.sh"

  local crate
  for crate in "${swept_crates[@]}"; do
    mkdir -p "$root/crates/$crate/src"
    printf 'pub fn evaluate() -> bool {\n    true\n}\n' >"$root/crates/$crate/src/lib.rs"
    printf '[package]\nname = "%s"\nlicense = "Apache-2.0"\n' "$crate" >"$root/crates/$crate/Cargo.toml"
  done
  printf '[workspace]\nmembers = ["crates/*"]\n' >"$root/Cargo.toml"

  local node_root="$root/crates/registry-evidence-client-node"
  printf 'module.exports = {};\n' >"$node_root/client.js"
  printf 'export declare class EvidenceClient {}\n' >"$node_root/client.d.ts"
  printf 'module.exports = require("./client.js");\n' >"$node_root/index.js"
  printf 'export * from "./client";\n' >"$node_root/index.d.ts"
  # A real package manifest carries an SPDX license field, which matches the
  # acceptance-vocabulary pattern's `licen[cs]e` alternative. The gate excludes
  # the two package manifests from that sweep for exactly this reason, so the
  # sandbox keeps the field that makes the exclusion load-bearing.
  printf '{\n  "name": "@registrystack/evidence-client",\n  "license": "Apache-2.0"\n}\n' \
    >"$node_root/package.json"

  local python_root="$root/crates/registry-evidence-client-py"
  printf '[project]\nname = "registry-evidence-client"\nlicense = "Apache-2.0"\n' \
    >"$python_root/pyproject.toml"
  printf 'from .registry_evidence_client import EvidenceClient\n' \
    >"$python_root/python/registry_evidence_client/__init__.py"
  printf 'class EvidenceClient: ...\n' \
    >"$python_root/python/registry_evidence_client/__init__.pyi"

  printf '{\n  "requirements": []\n}\n' >"$root/products/evidence/generated/requirements.json"
  printf 'type: object\n' >"$root/products/evidence/contracts/bundle.schema.yaml"
}

# Copy the pristine tree, hand it to the case body to plant in, and run the gate.
run_case() {
  local name=$1 expectation=$2 plant=$3
  build_pristine_tree
  local root="$sandbox_root/case"
  rm -rf "$root"
  cp -R "$sandbox_root/pristine" "$root"
  "$plant" "$root"

  local status=0 output
  output=$("$root/products/evidence/scripts/check-source-neutrality.sh" 2>&1) || status=$?

  case "$expectation" in
  pass)
    if [[ "$status" -ne 0 ]]; then
      printf 'FAIL %s: expected the gate to pass, got status %s:\n%s\n' \
        "$name" "$status" "$output" >&2
      failures=$((failures + 1))
      return
    fi
    if [[ "$output" != *'neutrality checks passed'* ]]; then
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

plant_source_product_in_production_code() {
  printf 'pub fn dhis2_tracked_entity() -> bool {\n    true\n}\n' \
    >>"$1/crates/registry-evidence/src/lib.rs"
}

plant_source_product_in_a_comment() {
  printf '// Proven against a sanitized DHIS2 mock in the tests.\n' \
    >>"$1/crates/registry-evidence/src/lib.rs"
}

plant_source_product_in_a_string_literal() {
  printf 'pub const MOCK: &str = "dhis2 mock";\n' \
    >>"$1/crates/registry-evidence/src/lib.rs"
}

plant_source_product_in_a_test_module() {
  cat >>"$1/crates/registry-evidence/src/lib.rs" <<'RUST'
#[cfg(test)]
mod tests {
    fn opencrvs_record() -> bool {
        true
    }
}
RUST
}

plant_source_product_in_a_tests_file() {
  printf 'fn dhis2_fixture() -> bool {\n    true\n}\n' \
    >"$1/crates/registry-evidence/src/source_tests.rs"
}

plant_acceptance_vocabulary_in_production_code() {
  printf 'pub fn adult_status() -> bool {\n    true\n}\n' \
    >>"$1/crates/registry-evidence-verifier/src/lib.rs"
}

plant_generic_synthetic_vocabulary_in_source_mock() {
  mkdir -p "$1/crates/registry-evidencectl/src/source_mock"
  printf 'pub const GENERATORS: &[&str] = &["given_name", "family_name", "birth_date"];\n' \
    >"$1/crates/registry-evidencectl/src/source_mock/generator.rs"
}

plant_acceptance_vocabulary_in_source_mock() {
  mkdir -p "$1/crates/registry-evidencectl/src/source_mock"
  printf 'pub fn adult_status() -> bool {\n    true\n}\n' \
    >"$1/crates/registry-evidencectl/src/source_mock/generator.rs"
}

plant_acceptance_vocabulary_in_evidencectl_sibling() {
  printf 'pub fn adult_status() -> bool {\n    true\n}\n' \
    >>"$1/crates/registry-evidencectl/src/lib.rs"
}

plant_source_product_in_source_mock() {
  mkdir -p "$1/crates/registry-evidencectl/src/source_mock"
  printf 'pub const SOURCE: &str = "dhis2";\n' \
    >"$1/crates/registry-evidencectl/src/source_mock/generator.rs"
}

plant_acceptance_vocabulary_in_the_binding_surface() {
  printf 'export declare function legalParentOf(subject: string): string;\n' \
    >>"$1/crates/registry-evidence-client-node/index.d.ts"
}

plant_source_product_in_the_binding_surface() {
  printf 'export declare const DHIS2_BASE_URL: string;\n' \
    >>"$1/crates/registry-evidence-client-node/index.d.ts"
}

plant_source_product_in_a_cargo_manifest() {
  printf 'dhis2-connector = "1"\n' >>"$1/crates/registry-evidence/Cargo.toml"
}

plant_source_product_in_generated_configuration() {
  printf '{\n  "source": "opencrvs"\n}\n' >"$1/products/evidence/generated/source.json"
}

plant_source_product_in_a_contract() {
  printf 'title: dhis2 bundle\n' >>"$1/products/evidence/contracts/bundle.schema.yaml"
}

remove_a_named_binding_file() {
  rm "$1/crates/registry-evidence-client-node/index.d.ts"
}

remove_a_named_source_root() {
  rm -rf "$1/crates/registry-evidencectl/src"
}

empty_every_source_root() {
  find "$1/crates" -name '*.rs' -delete
}

empty_the_published_configuration() {
  rm -f "$1/products/evidence/generated/requirements.json" \
    "$1/products/evidence/contracts/bundle.schema.yaml"
}

run_case 'a clean tree passes' pass plant_nothing
run_case 'a source-product name in production code fails' \
  fail plant_source_product_in_production_code
# Only test-only code is exempt. A comment or a literal in a production source
# file is searched like the code around it, so these two are failures, and the
# `#[cfg(test)]` and `_tests.rs` cases below are where a name is allowed.
run_case 'a source-product name in a production comment fails' \
  fail plant_source_product_in_a_comment
run_case 'a source-product name in a production string literal fails' \
  fail plant_source_product_in_a_string_literal
run_case 'a source-product name in a #[cfg(test)] module passes' \
  pass plant_source_product_in_a_test_module
run_case 'a source-product name in a _tests.rs file passes' \
  pass plant_source_product_in_a_tests_file
run_case 'acceptance vocabulary in production code fails' \
  fail plant_acceptance_vocabulary_in_production_code
run_case 'generic synthetic vocabulary in the authoring source mock passes' \
  pass plant_generic_synthetic_vocabulary_in_source_mock
run_case 'acceptance behavior in the authoring source mock fails' \
  fail plant_acceptance_vocabulary_in_source_mock
run_case 'acceptance vocabulary in an evidencectl sibling fails' \
  fail plant_acceptance_vocabulary_in_evidencectl_sibling
run_case 'a source-product name in the authoring source mock fails' \
  fail plant_source_product_in_source_mock
run_case 'acceptance vocabulary in the shipped binding surface fails' \
  fail plant_acceptance_vocabulary_in_the_binding_surface
run_case 'a source-product name in the shipped binding surface fails' \
  fail plant_source_product_in_the_binding_surface
run_case 'a source-product name in Cargo metadata fails' \
  fail plant_source_product_in_a_cargo_manifest
run_case 'a source-product name in generated configuration fails' \
  fail plant_source_product_in_generated_configuration
run_case 'a source-product name in a published contract fails' \
  fail plant_source_product_in_a_contract
run_case 'a named binding file that no longer exists fails' \
  fail remove_a_named_binding_file
run_case 'a named source root that no longer exists fails' \
  fail remove_a_named_source_root
run_case 'a tree with no production Rust left to search fails' \
  fail empty_every_source_root
run_case 'a tree with no published configuration left to search fails' \
  fail empty_the_published_configuration

# The gate must not depend on any tool the hosted runner lacks. Re-run the clean
# tree with a PATH holding only the system directories, which is where the
# ripgrep regression would have surfaced.
build_pristine_tree
status=0
output=$(PATH='/usr/bin:/bin' "$sandbox_root/pristine/products/evidence/scripts/check-source-neutrality.sh" 2>&1) ||
  status=$?
if [[ "$status" -eq 0 && "$output" == *'neutrality checks passed'* ]]; then
  printf 'ok   a clean tree passes with only the system PATH\n'
else
  printf 'FAIL a clean tree passes with only the system PATH: status %s:\n%s\n' \
    "$status" "$output" >&2
  failures=$((failures + 1))
fi

# And it must still fail there: a gate that passes only because its search tool
# is missing is the defect this file exists to catch.
build_pristine_tree
plant_source_product_in_production_code "$sandbox_root/pristine"
status=0
output=$(PATH='/usr/bin:/bin' "$sandbox_root/pristine/products/evidence/scripts/check-source-neutrality.sh" 2>&1) ||
  status=$?
if [[ "$status" -ne 0 ]]; then
  printf 'ok   a violation still fails with only the system PATH\n'
else
  printf 'FAIL a violation still fails with only the system PATH: the gate passed:\n%s\n' \
    "$output" >&2
  failures=$((failures + 1))
fi

if [[ "$failures" -ne 0 ]]; then
  printf '%s neutrality gate case(s) failed.\n' "$failures" >&2
  exit 1
fi

printf 'The Evidence neutrality gate reports every planted violation.\n'
