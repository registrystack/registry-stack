#!/usr/bin/env bash
set -euo pipefail

# CFG-YAML-1: configuration YAML is read only through `registry-platform-yaml`,
# so every reader refuses the same documents with the same diagnostics. Writing
# YAML stays open to every crate.
#
# Every `clippy.toml` holds that with `disallowed-methods` entries for each
# deserialization entry point of `serde_norway` and `serde_yaml_ng`, and the
# workspace clippy run in CI applies them. This gate exists for what that run
# cannot see:
#
#   * clippy reads one configuration per package and a nearer `clippy.toml`
#     replaces the workspace one, so a crate-level file without the entries
#     switches the boundary off for its crate. Every copy must carry them.
#   * an entry that stops resolving is reported as a warning that `-D warnings`
#     does not deny, and an entry naming a crate that is not in the build is not
#     reported at all. A reader crate in the dependency graph is therefore
#     proved here by probes, and one that has left the graph must be banned in
#     `deny.toml`, which is what refuses its return.
#   * a source `#[allow]` beats `-D warnings`. Only test code reading a tool's
#     own output may suppress the lint, with a reason, and production code only
#     for a format `products/platform/config-formats.yaml` registers as an
#     external format, with a reason naming it.
#
# `check-yaml-reader-boundary.py` holds the textual checks and its tests sit
# beside it. The probes below compile each deserialization entry point against
# a copy of every configuration and require the refusal clippy writes for it.

CDPATH=''
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
checker="$repository_root/products/platform/scripts/check-yaml-reader-boundary.py"

workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT

plan="$workspace/plan"
python3 "$checker" --root "$repository_root" --plan "$plan"

configurations=()
while IFS= read -r configuration; do
  configurations+=("$configuration")
done <"$plan/configurations"

readers=()
while IFS= read -r reader; do
  readers+=("$reader")
done <"$plan/readers"

if [[ "${#readers[@]}" -eq 0 ]]; then
  printf 'No YAML reader crate is in the dependency graph, and deny.toml bans each one.\n'
  exit 0
fi

driver=${CLIPPY_DRIVER_BIN:-$(cd -- "$repository_root" && rustup which clippy-driver)}
if [[ ! -x "$driver" ]]; then
  printf 'CLIPPY_DRIVER_BIN is not executable: %s\n' "$driver" >&2
  exit 2
fi

# Clippy emits only metadata for a dependency, so the build below is what puts
# a linkable copy of each reader where the probes can find it.
build_log="$workspace/build.log"
packages=()
for reader in "${readers[@]}"; do
  packages+=(--package "$reader")
done
(
  cd -- "$repository_root"
  cargo build --locked "${packages[@]}"
) >"$build_log" 2>&1 || {
  cat -- "$build_log" >&2
  printf 'The YAML reader crates do not build, so the probes cannot run.\n' >&2
  exit 1
}

# Cargo places that build under CARGO_TARGET_DIR, CARGO_BUILD_TARGET_DIR or the
# workspace `target` directory, so ask it where rather than assuming the last.
target_directory=$(
  cd -- "$repository_root"
  cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
) || {
  printf 'cargo metadata did not report the target directory, so the probes cannot run.\n' >&2
  exit 1
}
dependency_directory="$target_directory/debug/deps"

# `-exec ... +` runs nothing when nothing matches, on GNU and BSD alike, where
# GNU `xargs` would run a bare `ls` in the current directory.
reader_library() {
  find "$dependency_directory" \
    -maxdepth 1 -name "lib$1-*.rlib" -exec ls -t {} + 2>/dev/null |
    head -1 || true
}

# Each probe is one file compiled alone, so a verdict belongs to exactly one
# configuration and one reader.
lint_probe() {
  local directory="$1" reader="$2" name="$3"
  local library log="$directory/$name.log"
  library=$(reader_library "$reader")
  if [[ -z "$library" ]]; then
    printf 'No compiled %s was found under %s, so its probes cannot run.\n' \
      "$reader" "$dependency_directory" >&2
    exit 1
  fi
  CLIPPY_CONF_DIR="$directory" "$driver" \
    --edition 2021 \
    --crate-type lib \
    --emit=metadata \
    --out-dir "$directory" \
    -L "dependency=$dependency_directory" \
    --extern "$reader=$library" \
    "$directory/$name.rs" >"$log" 2>&1 || true
  if grep -qE '^error' -- "$log"; then
    printf 'The %s probe does not compile, so its verdicts prove nothing.\n' \
      "$name" >&2
    cat -- "$log" >&2
    exit 1
  fi
}

# Requires or forbids one exact text in a probe's log.
verdict() {
  local expected="$1" log="$2" shape="$3" reported="$4"
  local found=0
  grep -qF -- "$reported" "$log" || found=$?
  case "$expected:$found" in
  refuses:0 | allows:1) ;;
  refuses:1)
    printf 'The lint no longer refuses %s: its probe reported no "%s". Check the entry against the reader crate and the pinned clippy.\n' \
      "$shape" "$reported" >&2
    cat -- "$log" >&2
    exit 1
    ;;
  allows:0)
    printf 'The lint refuses %s, which writes YAML and stays open to every crate.\n' \
      "$shape" >&2
    cat -- "$log" >&2
    exit 1
    ;;
  *)
    printf 'The search of %s for "%s" failed with status %s.\n' \
      "$log" "$reported" "$found" >&2
    exit 1
    ;;
  esac
}

entry_points=(
  from_str
  from_slice
  from_reader
  from_value
  Deserializer::from_str
  Deserializer::from_slice
  Deserializer::from_reader
)
writers=(to_string to_writer to_value)

index=0
for configuration in "${configurations[@]}"; do
  index=$((index + 1))
  directory="$workspace/configuration-$index"
  mkdir -p -- "$directory"
  cp -- "$repository_root/$configuration" "$directory/clippy.toml"

  for reader in "${readers[@]}"; do
    cat >"$directory/$reader.rs" <<RUST
use ${reader}::Value;

pub fn reads(text: &str, bytes: &[u8], value: Value) {
    let _ = ${reader}::from_str::<Value>(text);
    let _ = ${reader}::from_slice::<Value>(bytes);
    let _ = ${reader}::from_reader::<_, Value>(bytes);
    let _ = ${reader}::from_value::<Value>(value);
    let _ = ${reader}::Deserializer::from_str(text);
    let _ = ${reader}::Deserializer::from_slice(bytes);
    let _ = ${reader}::Deserializer::from_reader(bytes);
}

pub fn writes(value: &Value) {
    let _ = ${reader}::to_string(value);
    let _ = ${reader}::to_writer(Vec::new(), value);
    let _ = ${reader}::to_value(value);
}
RUST
    lint_probe "$directory" "$reader" "$reader"
    log="$directory/$reader.log"

    # An entry clippy cannot resolve refuses nothing, and says so only as a
    # warning that survives `-D warnings`.
    unresolved_status=0
    unresolved=$(grep -E "\`$reader::[^\`]*\` does not refer to" -- "$log") ||
      unresolved_status=$?
    case "$unresolved_status" in
    0)
      printf '%s has %s entries that resolve to nothing, so they refuse nothing:\n%s\n' \
        "$configuration" "$reader" "$unresolved" >&2
      exit 1
      ;;
    1) ;;
    *)
      printf 'The search of %s for unresolved entries failed with status %s.\n' \
        "$log" "$unresolved_status" >&2
      exit 1
      ;;
    esac

    for entry in "${entry_points[@]}"; do
      verdict refuses "$log" "$reader::$entry under $configuration" \
        "disallowed method \`$reader::$entry\`"
    done
    for writer in "${writers[@]}"; do
      verdict allows "$log" "$reader::$writer under $configuration" \
        "disallowed method \`$reader::$writer\`"
    done
  done
  printf 'Probed %s\n' "$configuration"
done

# Clippy matches the path the compiler resolved, so a reader reached under
# another name arrives at the lint as its own. Each shape below uses its own
# entry point, so each verdict belongs to one shape.
shapes="$workspace/configuration-1"
for reader in "${readers[@]}"; do
  cat >"$shapes/${reader}_shapes.rs" <<RUST
use ${reader} as yaml;
use ${reader}::from_str as parse;
use ${reader}::Deserializer as Stream;

pub fn aliased_crate(value: yaml::Value) -> Option<yaml::Value> {
    yaml::from_value(value).ok()
}

pub fn aliased_import(text: &str) -> Option<yaml::Value> {
    parse(text).ok()
}

pub fn function_reference(bytes: &[u8]) -> Option<yaml::Value> {
    let read = ${reader}::from_slice::<yaml::Value>;
    read(bytes).ok()
}

pub fn aliased_type(bytes: &[u8]) {
    let _ = Stream::from_reader(bytes);
}
RUST
  lint_probe "$shapes" "$reader" "${reader}_shapes"
  log="$shapes/${reader}_shapes.log"
  verdict refuses "$log" "$reader through an aliased crate" \
    "disallowed method \`$reader::from_value\`"
  verdict refuses "$log" "$reader through an aliased import" \
    "disallowed method \`$reader::from_str\`"
  verdict refuses "$log" "$reader through a function reference" \
    "disallowed method \`$reader::from_slice\`"
  verdict refuses "$log" "$reader through an aliased type" \
    "disallowed method \`$reader::Deserializer::from_reader\`"
done

printf 'The YAML reader boundary holds for %s, and every entry still refuses its call.\n' \
  "${readers[*]}"
