#!/usr/bin/env bash
set -euo pipefail

# The citizen services beside the Base Registry Engine, the review page and the
# MCP gateway, reach a registry only over its public HTTP contract through
# `registry-breg-client`. Neither may link the registry runtime crate,
# `registry-breg`, into the binary it ships: a service that did could call the
# engine's internals and step around the authorization a registry enforces on
# every request. Native protocol tests use HTTP substitutes and also have no
# engine dependency. The gate checks both normal and test dependency graphs,
# and uses the engine's own graph as a positive resolution probe.

CDPATH=''
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
services=(registry-breg-review registry-breg-mcp)
runtime=registry-breg

workspace=$(mktemp -d)
trap 'rm -rf "$workspace"' EXIT

# Writes one package per line, `name version (source)`, for the named package's
# graph over the given edge kinds.
dependency_graph() {
  local package="$1"
  local edges="$2"
  local output="$3"
  (
    cd -- "$repository_root"
    cargo tree \
      --locked \
      --package "$package" \
      --edges "$edges" \
      --all-features \
      --target all \
      --prefix none \
      --format '{p}'
  ) >"$output" 2>"$output.err" || {
    cat -- "$output.err" >&2
    printf 'cargo tree failed for %s over %s edges.\n' "$package" "$edges" >&2
    exit 1
  }
}

# Succeeds when the graph file lists the runtime crate itself. A line names a
# package and then a space, so `registry-breg-client` does not match.
lists_runtime() {
  local graph="$1"
  local line
  while IFS= read -r line; do
    case "$line" in
    "$runtime "*) return 0 ;;
    esac
  done <"$graph"
  return 1
}

# Succeeds when the graph file lists the named package.
lists_package() {
  local graph="$1"
  local package="$2"
  local line
  while IFS= read -r line; do
    case "$line" in
    "$package "*) return 0 ;;
    esac
  done <"$graph"
  return 1
}

probe="$workspace/runtime.probe"
dependency_graph "$runtime" normal "$probe"
if ! lists_runtime "$probe"; then
  printf 'The check cannot identify the engine in its own dependency graph.\n' >&2
  exit 1
fi

status=0
for service in "${services[@]}"; do
  normal="$workspace/$service.normal"
  with_tests="$workspace/$service.dev"
  dependency_graph "$service" normal "$normal"
  dependency_graph "$service" normal,dev "$with_tests"

  if lists_runtime "$normal"; then
    printf '%s links the registry runtime (%s) outside its dev-dependencies.\n' \
      "$service" "$runtime" >&2
    printf 'Run: cargo tree -p %s -e normal --all-features -i %s\n' \
      "$service" "$runtime" >&2
    status=1
    continue
  fi

  # The client shares the runtime's name prefix; the check must pass it.
  if ! lists_package "$normal" registry-breg-client; then
    printf '%s no longer depends on registry-breg-client, so this gate cannot show it tells the client from the runtime.\n' \
      "$service" >&2
    status=1
    continue
  fi

  if lists_runtime "$with_tests"; then
    printf '%s links the registry runtime through its test dependencies.\n' "$service" >&2
    status=1
    continue
  fi

  printf '%-22s  HTTP client boundary in normal and test dependencies\n' "$service"

done

if [[ "$status" -ne 0 ]]; then
  exit "$status"
fi

printf '\nNeither service links the registry runtime.\n'
