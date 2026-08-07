#!/usr/bin/env bash
set -euo pipefail

# Client tooling links the portable Evidence verifier to check a stored response
# without the runtime. Portable means free of the service runtime, not target
# independent. Keep its normal dependency tree free of the async runtime, HTTP
# stack, script engine, command line parser, logging framework, and filesystem
# and socket syscall layers that the runtime carries.

CDPATH=''
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)

forbidden_packages=(
  axum
  clap
  fs2
  hyper
  mio
  reqwest
  rhai
  rustix
  socket2
  tokio
  tracing
)

dependency_tree=$(
  cargo tree \
    --locked \
    --manifest-path "$repository_root/Cargo.toml" \
    --package registry-evidence-verifier \
    --edges normal \
    --target all
)

found_forbidden=0
for package in "${forbidden_packages[@]}"; do
  # A search that neither matches nor reports "no match" is a broken check, not
  # a clean tree, so separate the two outcomes from every other status.
  search_status=0
  # `grep -E` rather than ripgrep: the hosted runner that gates this has no
  # ripgrep, and a search command that is absent exits 127, which reads as a
  # clean tree in any construct that only distinguishes match from no match.
  matches=$(
    printf '%s\n' "$dependency_tree" |
      grep -E "(^|[^0-9A-Za-z_-])${package}([-_][0-9A-Za-z_-]+)* v[0-9]"
  ) || search_status=$?
  case "$search_status" in
  0)
    printf 'registry-evidence-verifier reaches %s through its normal dependencies:\n%s\n' \
      "$package" "$matches" >&2
    found_forbidden=1
    ;;
  1) ;;
  *)
    printf 'The dependency search for %s failed with status %s.\n' \
      "$package" "$search_status" >&2
    exit 1
    ;;
  esac
done

if [[ "$found_forbidden" -ne 0 ]]; then
  printf 'The portable Evidence verifier must stay free of runtime-only dependencies.\n' >&2
  exit 1
fi

printf 'Evidence verifier dependencies stay portable.\n'
