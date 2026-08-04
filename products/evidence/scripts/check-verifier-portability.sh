#!/usr/bin/env bash
set -euo pipefail

# Client tooling links the portable Evidence verifier to check a stored
# response, on any platform and without the runtime. Keep its normal dependency
# tree free of the async runtime, HTTP stack, script engine, command line
# parser, and logging framework that the runtime carries.

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
  matches=$(
    printf '%s\n' "$dependency_tree" |
      rg "(^|[^0-9A-Za-z_-])${package}([-_][0-9A-Za-z_-]+)* v[0-9]" || true
  )
  if [[ -n "$matches" ]]; then
    printf 'registry-evidence-verifier reaches %s through its normal dependencies:\n%s\n' \
      "$package" "$matches" >&2
    found_forbidden=1
  fi
done

if [[ "$found_forbidden" -ne 0 ]]; then
  printf 'The portable Evidence verifier must stay free of runtime-only dependencies.\n' >&2
  exit 1
fi

printf 'Evidence verifier dependencies stay portable.\n'
