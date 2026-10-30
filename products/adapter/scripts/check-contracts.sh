#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$repo_root"

# The verification floor from products/adapter/DELIVERY-PLAN.md: format
# over the workspace, then clippy and tests over the adapter crates. Cargo
# runs in the caller's environment: an exported CARGO_TARGET_DIR is
# honored, and cargo's own default (target/ in this repository) is used
# otherwise; PATH keeps cargo reachable when it is not on the caller's
# PATH.
PATH="$HOME/.cargo/bin:$PATH" cargo fmt --check
PATH="$HOME/.cargo/bin:$PATH" cargo clippy -p registry-adapter -p registry-adapter-core -p registry-adapterctl --all-targets -- -D warnings
PATH="$HOME/.cargo/bin:$PATH" cargo test -p registry-adapter -p registry-adapter-core -p registry-adapterctl --locked

# The generated schemas are held to their generator (CFG-SCHEMA-2), and the
# five adapter formats are held to the configuration-format convention
# (CFG-SCHEMA-1) with the platform lint that CI also runs.
PATH="$HOME/.cargo/bin:$PATH" cargo run --locked -p registry-adapterctl -- schemas --check --output-dir products/adapter/schemas
uv run --no-project --with PyYAML==6.0.2 python products/platform/scripts/check-config-conventions.py

# The Camel port table (CONCEPT.md 8.10) is held to the code: every
# delivered row maps to named core tests and every accepted key has a row;
# later-increment rows report pending and never fail.
python3 products/adapter/scripts/check-port-table.py

# The example and corpus checks run the real adapterctl binary. It comes
# from, most explicit first:
#   1. the --bin-dir option,
#   2. the ADAPTERCTL_BIN environment variable, run exactly as named,
#   3. a build under the exported CARGO_TARGET_DIR,
# and the script refuses otherwise. A repo-local target/ directory is
# never used: a stale binary there once checked green against the wrong
# reader, which passed the corpus silently.
bin_dir=''
adapterctl_bin=''
previous=''
for argument in "$@"; do
  case "$argument" in
  --bin-dir=*) bin_dir="${argument#--bin-dir=}" ;;
  *)
    if [[ "$previous" == '--bin-dir' ]]; then
      bin_dir="$argument"
    fi
    ;;
  esac
  previous="$argument"
done

if [[ -n "$bin_dir" ]]; then
  adapterctl_bin="${bin_dir}/adapterctl"
elif [[ -n "${ADAPTERCTL_BIN:-}" ]]; then
  if [[ ! -x "${ADAPTERCTL_BIN}" ]]; then
    printf 'check-contracts: ADAPTERCTL_BIN names no executable: %s\n' "${ADAPTERCTL_BIN}" >&2
    printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR.\n' >&2
    exit 2
  fi
  # Run exactly the named binary: reducing it to its directory would
  # silently run a different adapterctl from the same directory. The
  # directory is kept only for the aws-lc-fips artifact lookup below.
  adapterctl_bin="${ADAPTERCTL_BIN}"
  bin_dir="$(cd "$(dirname "${ADAPTERCTL_BIN}")" && pwd -P)"
elif [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  command -v cargo >/dev/null 2>&1 || {
    printf 'check-contracts: CARGO_TARGET_DIR is set but cargo is not on PATH.\n' >&2
    exit 2
  }
  cargo build --locked -p registry-adapterctl --manifest-path "${repo_root}/Cargo.toml" --target-dir "${CARGO_TARGET_DIR}"
  bin_dir="${CARGO_TARGET_DIR}/debug"
  adapterctl_bin="${bin_dir}/adapterctl"
else
  printf 'check-contracts: no adapterctl binary found.\n' >&2
  printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR; the repository target/ directory is never used.\n' >&2
  exit 2
fi

if [[ ! -x "${adapterctl_bin}" ]]; then
  printf 'check-contracts: no adapterctl binary at %s.\n' "${adapterctl_bin}" >&2
  printf 'Set ADAPTERCTL_BIN to the adapterctl binary, pass --bin-dir, or export CARGO_TARGET_DIR.\n' >&2
  exit 2
fi

# A debug build that links aws-lc-fips-sys dynamically on macOS needs its
# library at each adapterctl launch. Keep the directory in the same
# non-DYLD carrier the conformance wrapper uses, and put it on the DYLD
# search for the direct child executions below.
if [[ -z "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
  for artifacts in "${bin_dir}"/build/aws-lc-fips-sys-*/out/build/artifacts; do
    if [[ -d "$artifacts" ]]; then
      REGISTRY_CARGO_RUNTIME_LIBRARY_PATH="$(cd "$artifacts" && pwd -P)"
      export REGISTRY_CARGO_RUNTIME_LIBRARY_PATH
      break
    fi
  done
fi
if [[ -n "${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH:-}" ]]; then
  DYLD_FALLBACK_LIBRARY_PATH="${REGISTRY_CARGO_RUNTIME_LIBRARY_PATH}${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
  export DYLD_FALLBACK_LIBRARY_PATH
fi

# The example is held to the exact command the configuration-format
# conformance registers for the adapter formats (products/platform/
# config-formats.yaml, `check:`): the project, its pinned profile and
# pack, and the shared fixture set.
fixture_flags=()
for fixture in products/adapter/fixtures/dhis2-tracker/*.yaml; do
  fixture_flags+=(--fixtures "$fixture")
done
"$adapterctl_bin" check products/adapter/examples/dhis2-tracker/project.yaml \
  --profile products/adapter/profiles/breg-records/profile.yaml \
  --pack products/adapter/packs/dhis2-tracker/pack.yaml \
  "${fixture_flags[@]}" >/dev/null
printf 'Example check passed\n'

# The bad-authoring corpus: every discovered bad/ member refuses with its
# own code (plus, transitionally, a co-fired partner code that is another
# member's expectation; see the runner and the corpus README), and the
# base/ control passes with zero findings. The runner self-tests its
# decision logic before it spends an adapterctl run.
python3 products/adapter/scripts/check-corpus.py "$adapterctl_bin"

printf 'Adapter product contracts passed\n'
