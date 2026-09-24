#!/usr/bin/env bash
set -euo pipefail

# `breg-mcp` reaches the Base Registry Engine only as a citizen's delegated
# agent. Every outbound call carries a token exchanged for the verified inbound
# token, and the tools it serves read, draft, and edit that citizen's own change
# request and nothing else.
#
# `crates/registry-breg-mcp/clippy.toml` is what holds that, by disallowing the
# client methods that would present another credential or reach an operation no
# tool offers. Clippy matches the path the compiler resolved, so an aliased
# import, a type alias, and a re-export all arrive at the lint as the one real
# name.
#
# Ordinary clippy runs already apply that file, because clippy finds it from the
# package directory. This gate exists for the two things an ordinary run does not
# do:
#
#   * an entry that stops resolving is reported as a warning that `-D warnings`
#     does not deny, so a renamed or misspelt path would go quiet with every
#     build still green. Here it fails.
#   * the lint is only worth its reputation while it still catches the shapes it
#     was written for. The probes below compile source holding each of them
#     against the real client and require the verdict, and they require that a
#     read the gateway does make is still allowed.

CDPATH=''
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
crate_directory="$repository_root/crates/registry-breg-mcp"
configuration="$crate_directory/clippy.toml"

if [[ ! -f "$configuration" ]]; then
  printf 'The lint configuration is missing: %s\n' "$configuration" >&2
  exit 1
fi

workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT

printf 'Linting registry-breg-mcp against %s\n' "${configuration#"$repository_root"/}"

lint_output="$workspace/clippy.log"
lint_status=0
(
  cd -- "$repository_root"
  cargo clippy \
    --locked \
    --package registry-breg-mcp \
    --all-targets \
    --all-features \
    -- -D warnings
) >"$lint_output" 2>&1 || lint_status=$?

if [[ "$lint_status" -ne 0 ]]; then
  cat -- "$lint_output" >&2
  printf 'registry-breg-mcp does not satisfy its outbound boundary lints.\n' >&2
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

# The probes compile against the real `registry-breg-client`. Clippy emits only
# metadata for a dependency, so this build is what puts a linkable client where
# the probes can find it.
(
  cd -- "$repository_root"
  cargo build --locked --package registry-breg-mcp
) >>"$lint_output" 2>&1 || {
  cat -- "$lint_output" >&2
  printf 'registry-breg-mcp does not build, so the probes cannot run.\n' >&2
  exit 1
}

dependencies="$repository_root/target/debug/deps"
client_library=''
for candidate in "$dependencies"/libregistry_breg_client-*.rlib; do
  [[ -f "$candidate" ]] || continue
  if [[ -z "$client_library" || "$candidate" -nt "$client_library" ]]; then
    client_library="$candidate"
  fi
done

if [[ -z "$client_library" ]]; then
  printf 'No compiled registry-breg-client was found under target/debug/deps, so the probes cannot run.\n' >&2
  exit 1
fi

# Each probe is one file put through `clippy-driver` directly against a copy of
# the crate's own configuration, so what is proved here is that configuration and
# not a restatement of it.
probe="$workspace/probe"
mkdir -p -- "$probe"
cp -- "$configuration" "$probe/clippy.toml"

driver=${CLIPPY_DRIVER_BIN:-$(cd -- "$repository_root" && rustup which clippy-driver)}
if [[ ! -x "$driver" ]]; then
  printf 'CLIPPY_DRIVER_BIN is not executable: %s\n' "$driver" >&2
  exit 2
fi

# Each probe is compiled alone, so a verdict below belongs to exactly one shape
# rather than to whichever line of a larger file happened to produce it.
lint_probe() {
  local name="$1"
  local log="$workspace/$name.log"
  CLIPPY_CONF_DIR="$probe" "$driver" \
    --edition 2021 \
    --crate-type lib \
    --emit=metadata \
    --out-dir "$probe" \
    -L "dependency=$dependencies" \
    --extern "registry_breg_client=$client_library" \
    "$probe/$name.rs" >"$log" 2>&1 || true
  local compiled=0
  grep -E '^error' -- "$log" >/dev/null || compiled=$?
  case "$compiled" in
  0)
    printf 'The %s probe does not compile, so its verdicts prove nothing.\n' \
      "$name" >&2
    cat -- "$log" >&2
    exit 1
    ;;
  1) ;;
  *)
    printf 'The search of the %s probe for compile errors failed with status %s.\n' \
      "$name" "$compiled" >&2
    exit 1
    ;;
  esac
}

# A lifecycle action reached through an aliased import. No tool runs one, so a
# change that did would carry the registry past the citizen's draft.
cat >"$probe/lifecycle.rs" <<'RUST'
use registry_breg_client::BaseRegistryClient as Registry;

pub async fn act(
    registry: &Registry,
    action: &registry_breg_client::BRegLifecycleAction,
    key: &registry_breg_client::BRegIdempotencyKey,
) -> bool {
    registry.execute_lifecycle_action(action, key).await.is_ok()
}
RUST

lint_probe lifecycle

# A credential swapped in through a type alias, and one built from text through
# the client's re-export of the platform token types. Either would let a string
# the gateway did not obtain by exchange reach the registry.
cat >"$probe/credential.rs" <<'RUST'
type Registry = registry_breg_client::BaseRegistryClient;

pub fn swap(registry: &Registry, token: registry_breg_client::BearerToken) -> Registry {
    registry.with_bearer_token(token)
}

pub fn fixed() -> bool {
    registry_breg_client::StaticToken::new("forwarded-inbound-token").is_ok()
}

pub fn built() -> bool {
    registry_breg_client::BearerToken::new("forwarded-inbound-token").is_ok()
}
RUST

lint_probe credential

# The read the gateway makes, through the same alias shapes. A lint that refused
# it would be argued down to nothing well before it ever caught anybody.
cat >"$probe/read.rs" <<'RUST'
use registry_breg_client::BaseRegistryClient as Registry;

pub async fn read(registry: &Registry, route: &str, identifier: &str) -> bool {
    let options = registry_breg_client::BRegRecordOptions::default();
    registry.get_record(route, identifier, &options).await.is_ok()
}
RUST

lint_probe read

# Each entry is a verdict, the probe it belongs to, the shape it is about, and
# the text clippy writes when it reaches that verdict. The backticks are clippy's
# own, quoting the name it refuses, and every one is single-quoted and literal.
# shellcheck disable=SC2016
verdicts=(
  'refuses|lifecycle|a lifecycle action through an aliased import|disallowed method `registry_breg_client::BaseRegistryClient::execute_lifecycle_action`'
  'refuses|credential|a bearer token swapped in through a type alias|disallowed method `registry_breg_client::BaseRegistryClient::with_bearer_token`'
  'refuses|credential|a static token built through a re-export|disallowed method `registry_platform_httputil::client::StaticToken::new`'
  'refuses|credential|a bearer token built through a re-export|disallowed method `registry_platform_httputil::client::BearerToken::new`'
  'allows|read|a record read, which is what the gateway does|disallowed method `registry_breg_client::BaseRegistryClient::get_record`'
)

printf '\n%-8s  %-11s  %s\n' 'verdict' 'probe' 'shape'
for verdict in "${verdicts[@]}"; do
  IFS='|' read -r expected name shape reported <<<"$verdict"
  log="$workspace/$name.log"
  found=0
  grep -F -- "$reported" "$log" >/dev/null || found=$?
  case "$expected:$found" in
  refuses:0 | allows:1)
    printf '%-8s  %-11s  %s\n' "$expected" "$name" "$shape"
    ;;
  refuses:1)
    printf 'The lint no longer refuses %s: the %s probe reported no "%s".\n' \
      "$shape" "$name" "$reported" >&2
    cat -- "$log" >&2
    exit 1
    ;;
  allows:0)
    printf 'The lint refuses %s, which the gateway needs.\n' "$shape" >&2
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

printf '\nThe gateway boundary lints hold, and still refuse every shape probed.\n'
