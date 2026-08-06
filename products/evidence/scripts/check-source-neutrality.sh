#!/usr/bin/env bash
set -euo pipefail

# Evidence production code, adopter tooling, the shipped binding surface, and the
# public configuration stay free of source-product names and of acceptance-case
# or jurisdiction-specific vocabulary. DHIS2 and OpenCRVS names, and the words
# each acceptance definition happens to use, are test-only.
#
# A source-product name may still appear where it belongs: in test-only code.
# `#[cfg(test)]` items are cut out of the Rust text before it is searched, and
# `*_tests.rs` files are skipped entirely. Everything else in a production source
# file is searched, comments and string literals included. The inline masking
# below is how the cut is made reliable, not an exemption: it blanks comments and
# literals only to find the braces that really close a `#[cfg(test)]` item,
# then emits the unmasked text between those spans.
#
# `grep -E` rather than ripgrep, for the reason its sibling
# `check-verifier-portability.sh` states: the hosted runner that gates this has
# no ripgrep, and an absent search command exits 127, which reads as "found
# nothing" in any construct that only distinguishes match from no match. Every
# path this gate names is checked to exist and every search status above 1 is a
# failure, because a gate that cannot fail is not a gate.

CDPATH=''
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
production_text="$temporary_root/production-rust.txt"

source_roots=(
  "$repository_root/crates/registry-evidence/src"
  "$repository_root/crates/registry-evidence-client/src"
  "$repository_root/crates/registry-evidence-client-node/src"
  "$repository_root/crates/registry-evidence-client-py/src"
  "$repository_root/crates/registry-evidence-verifier/src"
  "$repository_root/crates/registry-evidencectl/src"
)

# The two bindings ship a non-Rust surface that the Rust sweep cannot see.
# Enumerate exactly those shipped files: a sweep of the binding crate
# directories would also reach their tests, fixtures, and installed
# dependencies, where a source-product name is allowed.
shipped_binding_surface=(
  "$repository_root/crates/registry-evidence-client-node/client.js"
  "$repository_root/crates/registry-evidence-client-node/client.d.ts"
  "$repository_root/crates/registry-evidence-client-node/index.js"
  "$repository_root/crates/registry-evidence-client-node/index.d.ts"
  "$repository_root/crates/registry-evidence-client-py/python/registry_evidence_client/__init__.py"
  "$repository_root/crates/registry-evidence-client-py/python/registry_evidence_client/__init__.pyi"
)

# The two package manifests carry no caller-visible API surface that could name
# an acceptance case, and their SPDX license field matches the licence pattern,
# so they take the source-product sweep only.
shipped_package_manifests=(
  "$repository_root/crates/registry-evidence-client-node/package.json"
  "$repository_root/crates/registry-evidence-client-py/pyproject.toml"
)

cargo_manifests=(
  "$repository_root/crates/registry-evidence/Cargo.toml"
  "$repository_root/crates/registry-evidence-client/Cargo.toml"
  "$repository_root/crates/registry-evidence-client-node/Cargo.toml"
  "$repository_root/crates/registry-evidence-client-py/Cargo.toml"
  "$repository_root/crates/registry-evidence-verifier/Cargo.toml"
  "$repository_root/crates/registry-evidencectl/Cargo.toml"
  "$repository_root/Cargo.toml"
)

published_roots=(
  "$repository_root/products/evidence/generated"
  "$repository_root/products/evidence/contracts"
)

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

# A path this gate names explicitly, that a rename or a move has taken away,
# silently narrows what is searched. Say so instead.
for named_file in \
  "${shipped_binding_surface[@]}" \
  "${shipped_package_manifests[@]}" \
  "${cargo_manifests[@]}"; do
  [[ -f "$named_file" ]] ||
    fail "This gate names $named_file, which no longer exists: update the list it appears in."
done

for named_root in "${source_roots[@]}" "${published_roots[@]}"; do
  [[ -d "$named_root" ]] ||
    fail "This gate sweeps $named_root, which no longer exists: update the list it appears in."
done

production_sources=()
while IFS= read -r source_file; do
  case "$source_file" in
  *_tests.rs) continue ;;
  esac
  production_sources+=("$source_file")
done < <(find "${source_roots[@]}" -type f -name '*.rs' | sort)

if [[ "${#production_sources[@]}" -eq 0 ]]; then
  fail 'The neutrality sweep found no Evidence production Rust to search.'
fi

: >"$production_text"
for source_file in "${production_sources[@]}"; do
  python3 - "$source_file" >>"$production_text" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
masked = list(source)
i = 0
block_depth = 0
while i < len(source):
    if block_depth:
        if source.startswith("/*", i):
            masked[i:i + 2] = "  "
            block_depth += 1
            i += 2
        elif source.startswith("*/", i):
            masked[i:i + 2] = "  "
            block_depth -= 1
            i += 2
        else:
            if source[i] != "\n":
                masked[i] = " "
            i += 1
        continue
    if source.startswith("//", i):
        end = source.find("\n", i)
        end = len(source) if end < 0 else end
        masked[i:end] = " " * (end - i)
        i = end
        continue
    if source.startswith("/*", i):
        masked[i:i + 2] = "  "
        block_depth = 1
        i += 2
        continue
    raw = re.match(r'(?:b?r)(?P<hashes>#{0,255})"', source[i:])
    if raw:
        marker = '"' + raw.group("hashes")
        start = i
        i += raw.end()
        end = source.find(marker, i)
        i = len(source) if end < 0 else end + len(marker)
        for position in range(start, i):
            if source[position] != "\n":
                masked[position] = " "
        continue
    prefix = 1 if source.startswith('"', i) else 2 if source.startswith('b"', i) else 0
    if prefix:
        start = i
        i += prefix
        while i < len(source):
            if source[i] == "\\":
                i += 2
            elif source[i] == '"':
                i += 1
                break
            else:
                i += 1
        for position in range(start, min(i, len(source))):
            if source[position] != "\n":
                masked[position] = " "
        continue
    char_prefix = 2 if source.startswith("b'", i) else 1 if source.startswith("'", i) else 0
    if char_prefix:
        start = i
        cursor = i + char_prefix
        if cursor < len(source) and source[cursor] == "\\":
            cursor += 2
        else:
            cursor += 1
        if cursor < len(source) and source[cursor] == "'":
            i = cursor + 1
            for position in range(start, i):
                if source[position] != "\n":
                    masked[position] = " "
            continue
    i += 1

code = "".join(masked)
spans = []
for match in re.finditer(r'#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]', code):
    start = match.start()
    cursor = match.end()
    opener = None
    while cursor < len(code):
        if code[cursor] in "{;":
            opener = code[cursor]
            break
        cursor += 1
    if opener is None or opener == ";":
        end = min(cursor + 1, len(code))
    else:
        depth = 0
        while cursor < len(code):
            if code[cursor] == "{":
                depth += 1
            elif code[cursor] == "}":
                depth -= 1
                if depth == 0:
                    cursor += 1
                    break
            cursor += 1
        end = cursor
    spans.append((start, end))

cursor = 0
for start, end in spans:
    if start < cursor:
        continue
    sys.stdout.write(source[cursor:start])
    cursor = end
sys.stdout.write(source[cursor:])
PY
done

if [[ ! -s "$production_text" ]]; then
  fail 'Masking left no Evidence production Rust text to search.'
fi

published_files=()
while IFS= read -r published_file; do
  published_files+=("$published_file")
done < <(find "${published_roots[@]}" -type f | sort)

if [[ "${#published_files[@]}" -eq 0 ]]; then
  fail 'The neutrality sweep found no Evidence public configuration or generated contracts to search.'
fi

# grep reports 0 for a match, 1 for none, and above 1 for its own failure. The
# third outcome is a broken check rather than a clean tree, so it fails here.
# `/dev/null` keeps the file name on every reported line, whatever the list size.
sweep() {
  local message=$1 pattern=$2
  shift 2
  local status=0 matches
  matches=$(grep -n -i -E -e "$pattern" /dev/null "$@") || status=$?
  case "$status" in
  0)
    printf '%s\n' "$matches" >&2
    fail "$message"
    ;;
  1) ;;
  *)
    fail "A neutrality sweep failed with status $status, searching for: $pattern"
    ;;
  esac
}

sweep \
  'Evidence production code, adopter tooling, the shipped binding surface, or Cargo metadata contains a prohibited source-product name.' \
  'dhis2|opencrvs' \
  "$production_text" \
  "${shipped_binding_surface[@]}" \
  "${shipped_package_manifests[@]}" \
  "${cargo_manifests[@]}"

sweep \
  'Evidence production Rust, adopter tooling, or the shipped binding surface contains acceptance-case or jurisdiction-specific vocabulary.' \
  'adult|age[_ -]?at|residence|licen[cs]e|parentage|legal[_ -]?parent|given_name|family_name|birth_date|national[_ -]?identifier' \
  "$production_text" \
  "${shipped_binding_surface[@]}"

sweep \
  'Evidence public configuration or generated contracts contain a prohibited source-product name.' \
  'dhis2|opencrvs' \
  "${published_files[@]}"

printf 'Evidence source-product and domain neutrality checks passed.\n'
