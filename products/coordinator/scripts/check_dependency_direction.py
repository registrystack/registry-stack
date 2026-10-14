#!/usr/bin/env python3
"""Check Coordinator dependency direction from Cargo's resolved graph.

The Coordinator composes products only through their public product clients.
Its runtime may reach product clients, product cores, `registry-record` and
shared platform primitives, and nothing else of the workspace: never another
product's runtime, adopter tooling, supporting service or binding. Its client
reaches the runtime over the public HTTP contract only and reuses the runtime-free
shared Review wire contract for policy pins. No crate outside the
Coordinator depends on a Coordinator crate unless it is named below.

Edges are read with every feature enabled and on every target. A package's own
dev-dependencies count, so a test cannot link what the package may not. The
dev-dependencies of a crate it reaches are not followed: Cargo never builds
them into the package being checked.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

COORDINATOR_PREFIX = "registry-coordinator"

COORDINATOR_RUNTIME = "registry-coordinator"

# The Rust client and its Node.js and Python bindings.
COORDINATOR_CLIENTS = (
    "registry-coordinator-client",
    "registry-coordinator-client-node",
    "registry-coordinator-client-py",
)

# Workspace crates the runtime may reach that no naming rule admits, each
# with the product client that carries it.
CLIENT_SUPPORT = {
    "registry-review-protocol": "the review handoff contract registry-casework-client carries",
}

# Exact wire DTO reuse, never the Review client or a provider runtime/core.
COORDINATOR_CLIENT_SUPPORT = frozenset({"registry-review-protocol"})

# The unified Rust facade. It composes the Coordinator client for callers and
# is never a dependency of the runtime.
UNIFIED_CLIENT = "registry-stack-client"

# Every crate outside the Coordinator that may depend on a Coordinator crate,
# with the Coordinator crates it may reach.
ALLOWED_DEPENDENTS = {
    # Builds the published CLI reference from the `coordinator` command tree.
    "registry-cli-docs": frozenset({COORDINATOR_RUNTIME}),
    # The unified Rust client facade.
    UNIFIED_CLIENT: frozenset({"registry-coordinator-client"}),
}

def package_graph(
    metadata: dict,
) -> tuple[dict[str, str], dict[str, set[str]], dict[str, set[str]]]:
    """Package names, every edge, and the edges that exclude dev-dependencies."""
    names = {package["id"]: package["name"] for package in metadata["packages"]}
    resolve = metadata.get("resolve")
    if not resolve:
        raise ValueError("cargo metadata did not include a resolved dependency graph")
    every: dict[str, set[str]] = {}
    linked: dict[str, set[str]] = {}
    for node in resolve["nodes"]:
        every[node["id"]] = set()
        linked[node["id"]] = set()
        for dependency in node["deps"]:
            every[node["id"]].add(dependency["pkg"])
            # Cargo writes a null kind for a normal dependency. A fixture that
            # omits the kinds describes normal dependencies.
            kinds = {kind.get("kind") for kind in dependency.get("dep_kinds", [{}])}
            if kinds - {"dev"}:
                linked[node["id"]].add(dependency["pkg"])
    return names, every, linked


def closure(start: str, every: dict[str, set[str]], linked: dict[str, set[str]]) -> set[str]:
    """Every package the start builds with, its own dev-dependencies included."""
    seen: set[str] = set()
    pending = list(every.get(start, set()))
    while pending:
        package = pending.pop()
        if package in seen:
            continue
        seen.add(package)
        pending.extend(linked.get(package, set()) - seen)
    return seen


def runtime_may_reach(name: str) -> bool:
    if not name.startswith("registry-"):
        return True
    if name.startswith("registry-platform-") or name == "registry-record":
        return True
    if name in CLIENT_SUPPORT:
        return True
    if name.endswith("-core"):
        return True
    return name.endswith("-client") and name != UNIFIED_CLIENT


def client_may_reach(name: str) -> bool:
    if not name.startswith("registry-"):
        return True
    return (
        name == "registry-coordinator-client"
        or name.startswith("registry-platform-")
        or name in COORDINATOR_CLIENT_SUPPORT
    )


def violations(metadata: dict) -> list[str]:
    names, every, linked = package_graph(metadata)
    failures: list[str] = []
    for package_id, name in sorted(names.items(), key=lambda item: item[1]):
        reached = {names[item] for item in closure(package_id, every, linked)}
        if name == COORDINATOR_RUNTIME:
            refused = sorted(item for item in reached if not runtime_may_reach(item))
            if refused:
                failures.append(
                    f"{name} reaches package(s) outside product clients, product cores, "
                    f"registry-record and registry-platform-*: {', '.join(refused)}"
                )
        elif name in COORDINATOR_CLIENTS:
            refused = sorted(item for item in reached if not client_may_reach(item))
            if refused:
                failures.append(
                    f"{name} reaches package(s) other than the Coordinator client and "
                    f"registry-platform-* and registry-review-protocol: {', '.join(refused)}"
                )
        elif name.startswith(COORDINATOR_PREFIX):
            failures.append(
                f"{name} is a Coordinator crate this gate does not know; name its rule here"
            )
        else:
            coordinator = {item for item in reached if item.startswith(COORDINATOR_PREFIX)}
            permitted = ALLOWED_DEPENDENTS.get(name, frozenset())
            refused = sorted(coordinator - permitted)
            if refused:
                failures.append(
                    f"{name} depends on Coordinator package(s) it is not listed for: "
                    f"{', '.join(refused)}"
                )
    return failures


def load_metadata(repository_root: Path, fixture: Path | None) -> dict:
    if fixture:
        return json.loads(fixture.read_text(encoding="utf-8"))
    # All-features resolution, so an optional dependency no supported build
    # enables by default still cannot escape the forward-closure check.
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, help="read a Cargo metadata fixture")
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[3]
    try:
        failures = violations(load_metadata(repository_root, args.metadata))
    except (
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(
            f"dependency-direction check could not inspect Cargo metadata: {error}",
            file=sys.stderr,
        )
        return 2
    if failures:
        for failure in failures:
            print(f"dependency-direction violation: {failure}", file=sys.stderr)
        return 1
    print("Coordinator dependency direction reaches products only through their clients.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
