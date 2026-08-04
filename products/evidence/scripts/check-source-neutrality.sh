#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
temporary_root=$(mktemp -d)
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
production_text="$temporary_root/production-rust.txt"

: >"$production_text"
for source_file in $(
  rg --files \
    "$repository_root/crates/registry-evidence/src" \
    "$repository_root/crates/registry-evidencectl/src" \
    -g '*.rs' | sort
); do
  case "$source_file" in
    *_tests.rs) continue ;;
  esac
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

if rg -n -i 'dhis2|opencrvs' \
  "$production_text" \
  "$repository_root/crates/registry-evidence/Cargo.toml" \
  "$repository_root/crates/registry-evidencectl/Cargo.toml" \
  "$repository_root/Cargo.toml"; then
  echo 'Evidence production code, adopter tooling, or Cargo metadata contains a prohibited source-product name.' >&2
  exit 1
fi

if rg -n -i 'adult|age[_ -]?at|residence|licen[cs]e|parentage|legal[_ -]?parent|given_name|family_name|birth_date|national[_ -]?identifier' \
  "$production_text"; then
  echo 'Evidence production Rust or adopter tooling contains acceptance-case or jurisdiction-specific vocabulary.' >&2
  exit 1
fi

generated_root="$repository_root/products/evidence/generated"
contract_root="$repository_root/products/evidence/contracts"
if rg -n -i 'dhis2|opencrvs' "$generated_root" "$contract_root"; then
  echo 'Evidence public configuration or generated contracts contain a prohibited source-product name.' >&2
  exit 1
fi

echo 'Evidence source-product and domain neutrality checks passed.'
