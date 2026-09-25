#!/usr/bin/env bash
set -euo pipefail

# The citizen services beside the Base Registry Engine, the review page and the
# MCP gateway, reach a registry only over its public HTTP contract through
# `registry-breg-client`. Neither may link the registry runtime crate,
# `registry-breg`, into the binary it ships: a service that did could call the
# engine's internals and step around the authorization a registry enforces on
# every request. Their PostgreSQL tests still run against a real engine, so the
# runtime is allowed as a dev-dependency and nowhere else.
#
# This gate reads each service's normal dependency graph, with every feature
# and every target enabled, and fails when the runtime appears in it, directly
# or through any other crate. It then proves the check still works: the same
# graph with dev-dependencies included must show the runtime, so a check that
# stopped seeing it fails here instead of passing quietly, and the client,
# whose name starts with the runtime's, must never be mistaken for it.

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

  # The runtime is reintroduced here by including the dev edges its tests use.
  # A check that cannot see it there would pass a normal edge just as quietly.
  if ! lists_runtime "$with_tests"; then
    printf 'The check does not find %s in the test graph of %s, so it proves nothing about the normal graph.\n' \
      "$runtime" "$service" >&2
    status=1
    continue
  fi

  printf '%-22s  runtime only in dev-dependencies\n' "$service"
done

if [[ "$status" -ne 0 ]]; then
  exit "$status"
fi

printf '\nNeither service links the registry runtime outside its tests.\n'
