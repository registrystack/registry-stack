#!/usr/bin/env bash
set -euo pipefail

# `registry-evidence-authoring` is linked into the language server, which is
# linked into `registryctl` and `evidencectl` and speaks JSON-RPC over standard
# input and output. Its licence to run in that process is that it reads no file,
# opens no socket, starts no process and touches neither standard stream.
#
# `crates/registry-evidence-authoring/clippy.toml` is what holds that, by
# disallowing the types, methods and macros that would break it. Clippy matches
# the path the compiler resolved, so an alias, a type alias, a `Default::default()`
# against an annotated binding and a module redirected by `#[path]` all arrive at
# the lint as the one real name, which is what reading source text could never do.
#
# Ordinary clippy runs already apply that file, because clippy finds it from the
# package directory. This gate exists for the two things an ordinary run does not
# do:
#
#   * an entry that stops resolving is reported as a warning that `-D warnings`
#     does not deny, so a renamed or misspelt path would go quiet with every
#     build still green. Here it fails.
#   * the lint is only worth its reputation while it still catches the shapes it
#     was written for. The probe below compiles source holding each of them and
#     requires the verdict, so a change in clippy that stopped resolving one is
#     a failure here rather than a discovery during the next review.

CDPATH=''
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
crate_directory="$repository_root/crates/registry-evidence-authoring"
configuration="$crate_directory/clippy.toml"

if [[ ! -f "$configuration" ]]; then
  printf 'The lint configuration is missing: %s\n' "$configuration" >&2
  exit 1
fi

workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT

printf 'Linting registry-evidence-authoring against %s\n' "${configuration#"$repository_root"/}"

lint_output="$workspace/clippy.log"
lint_status=0
(
  cd -- "$repository_root"
  cargo clippy \
    --locked \
    --package registry-evidence-authoring \
    --all-targets \
    --all-features \
    -- -D warnings
) >"$lint_output" 2>&1 || lint_status=$?

if [[ "$lint_status" -ne 0 ]]; then
  cat -- "$lint_output" >&2
  printf 'registry-evidence-authoring does not satisfy its no-input-output lints.\n' >&2
  exit 1
fi

# An entry clippy cannot resolve refuses nothing. It says so, once, as a warning
# that survives `-D warnings`, which is precisely the shape of a check that has
# quietly stopped checking.
unresolved_status=0
unresolved=$(grep -E 'does not refer to' -- "$lint_output") || unresolved_status=$?
case "$unresolved_status" in
0)
  printf 'These lint entries resolve to nothing, so they refuse nothing:\n%s\n' \
    "$unresolved" >&2
  exit 1
  ;;
1) ;;
*)
  printf 'The search for unresolved lint entries failed with status %s.\n' \
    "$unresolved_status" >&2
  exit 1
  ;;
esac

# The probes. Every shape below is a way of reaching a file, or a stream, that
# reading source text does not catch, and each was written by somebody defeating
# an earlier version of this invariant. `redirected.rs` is the module a `#[path]`
# attribute compiles from a directory no sweep of `src` walks; the aliases are
# the names an engine or a handle arrives under; `Default::default()` never
# mentions a constructor at all. The lines expected to pass are the other half of
# the claim: an error type is not an entry point, and the same method name on a
# value already fetched issues no system call, and a check that refused those
# would be argued down to nothing well before it ever caught anybody.
#
# Each probe is one file put through `clippy-driver` directly against a copy of
# the crate's own configuration, so what is proved here is that configuration and
# not a restatement of it.
probe="$workspace/probe"
mkdir -p -- "$probe"
cp -- "$configuration" "$probe/clippy.toml"

driver=$(rustup which clippy-driver)

# Each probe is compiled alone, so a verdict below belongs to exactly one shape
# rather than to whichever line of a larger file happened to produce it.
lint_probe() {
  local name="$1"
  shift
  local log="$workspace/$name.log"
  CLIPPY_CONF_DIR="$probe" "$driver" \
    --edition 2021 \
    --crate-type lib \
    --emit=metadata \
    --out-dir "$probe" \
    "$@" \
    "$probe/$name.rs" >"$log" 2>&1 || true
  if grep -qE '^error' -- "$log"; then
    printf 'The %s probe does not compile, so its verdicts prove nothing.\n' \
      "$name" >&2
    cat -- "$log" >&2
    exit 1
  fi
}

# The module a `#[path]` attribute compiles from a directory no walk of `src`
# reaches. The attribute is spelt through `cfg_attr`, which is the spelling that
# walked past a sweep looking for `#[path`.
cat >"$probe/elsewhere.rs" <<'RUST'
pub fn read_it() -> String {
    std::fs::read_to_string("/etc/passwd").unwrap_or_default()
}
RUST

cat >"$probe/redirected.rs" <<'RUST'
#[cfg_attr(unix, path = "elsewhere.rs")]
pub mod elsewhere;
RUST

lint_probe redirected

# The names a file handle arrives under, and beside them the two shapes a check
# that read source text could not tell apart from them. `Metadata::is_dir` tests
# a bit in a structure already fetched and `io::Error` is a value, and a check
# that refused those would be argued down to nothing before it caught anybody.
cat >"$probe/handles.rs" <<'RUST'
use std::fs::File as Handle;

type Opener = std::fs::OpenOptions;

pub fn aliased_import(path: &str) -> Option<Handle> {
    Handle::open(path).ok()
}

pub fn aliased_type() -> Opener {
    Opener::new()
}

pub fn asks_the_file_system(path: &std::path::Path) -> bool {
    path.is_dir()
}

pub fn asks_nobody(metadata: &std::fs::Metadata) -> bool {
    metadata.is_dir() || metadata.is_file()
}

pub fn returns_an_error(kind: std::io::ErrorKind) -> std::io::Result<()> {
    Err(std::io::Error::new(kind, "not an entry point"))
}
RUST

lint_probe handles

# The engine probes need the real `rhai`, because no type the configuration
# disallows from the standard library implements `Default`, and an annotated
# binding taking `Default::default()` is the shape that named no constructor at
# all and so walked past three rounds of reading source text. Clippy emits only
# metadata for a dependency, so the build below is what puts a linkable `rhai`
# where the probes can find it; it is already done on any machine that has built
# this crate.
(
  cd -- "$repository_root"
  cargo build --locked --package registry-evidence-authoring --lib
) >>"$lint_output" 2>&1 || {
  cat -- "$lint_output" >&2
  printf 'registry-evidence-authoring does not build, so the engine probes cannot run.\n' >&2
  exit 1
}

engine_library=$(find "$repository_root/target/debug/deps" \
  -maxdepth 1 -name 'librhai-*.rlib' -print0 2>/dev/null |
  xargs -0 ls -t 2>/dev/null | head -1 || true)

if [[ -z "$engine_library" ]]; then
  printf 'No compiled rhai was found under target/debug/deps, so the engine probes cannot run.\n' >&2
  exit 1
fi

lint_engine_probe() {
  lint_probe "$1" \
    -L "dependency=$repository_root/target/debug/deps" \
    --extern "rhai=$engine_library"
}

cat >"$probe/imported_engine.rs" <<'RUST'
use rhai::Engine as Interpreter;

pub fn build() -> Interpreter {
    Interpreter::new()
}
RUST

lint_engine_probe imported_engine

cat >"$probe/aliased_engine.rs" <<'RUST'
type Interpreter = rhai::Engine;

pub fn build() -> Interpreter {
    Interpreter::new()
}
RUST

lint_engine_probe aliased_engine

# No constructor is named anywhere here, so the type annotation is the only place
# a check has to catch this, and `compile` is the one call the crate makes.
cat >"$probe/defaulted_engine.rs" <<'RUST'
use rhai::Engine as Interpreter;

pub fn build() -> bool {
    let engine: Interpreter = Default::default();
    engine.compile("1").is_ok()
}
RUST

lint_engine_probe defaulted_engine

# Each entry is a verdict, the probe it belongs to, the shape it is about, and
# the text clippy writes when it reaches that verdict. The backticks are clippy's
# own, quoting the name it refuses, and every one is single-quoted and literal.
# shellcheck disable=SC2016
verdicts=(
  'refuses|redirected|a module compiled from another directory|disallowed method `std::fs::read_to_string`'
  'refuses|handles|a handle reached through an aliased import|disallowed type `std::fs::File`'
  'refuses|handles|a handle reached through a type alias|disallowed type `std::fs::OpenOptions`'
  'refuses|handles|a path asked what it is|disallowed method `std::path::Path::is_dir`'
  'allows|handles|a predicate on metadata already fetched|disallowed method `std::fs::Metadata::is_dir`'
  'allows|handles|an error value|disallowed type `std::io::Error`'
  'allows|handles|a result alias|disallowed type `std::io::Result`'
  'refuses|imported_engine|an engine built through an aliased import|disallowed method `rhai::Engine::new`'
  'refuses|aliased_engine|an engine built through a type alias|disallowed method `rhai::Engine::new`'
  'refuses|defaulted_engine|an engine reached by `Default::default`|disallowed type `rhai::Engine`'
  'allows|defaulted_engine|compiling a program, which is what the crate does|disallowed method `rhai::Engine::compile`'
)

for verdict in "${verdicts[@]}"; do
  IFS='|' read -r expected name shape reported <<<"$verdict"
  log="$workspace/$name.log"
  found=0
  grep -qF -- "$reported" "$log" || found=$?
  case "$expected:$found" in
  refuses:0 | allows:1) ;;
  refuses:1)
    printf 'The lint no longer refuses %s: the %s probe reported no "%s".\n' \
      "$shape" "$name" "$reported" >&2
    cat -- "$log" >&2
    exit 1
    ;;
  allows:0)
    printf 'The lint refuses %s, which reaches nothing and is written every day in the crates next door.\n' \
      "$shape" >&2
    cat -- "$log" >&2
    exit 1
    ;;
  *)
    printf 'The search of the %s probe for "%s" failed with status %s.\n' \
      "$name" "$reported" "$found" >&2
    exit 1
    ;;
  esac
done

printf 'The no-input-output lints hold, and still refuse every shape probed.\n'
