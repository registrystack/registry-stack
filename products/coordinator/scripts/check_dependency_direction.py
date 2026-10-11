#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check Coordinator dependency direction from Cargo's resolved graph."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

COORDINATOR_PREFIX = "registry-coordinator"
REGISTRY_PREFIX = "registry-"

# The shared primitives every maintained runtime may build on.
PLATFORM_PREFIX = "registry-platform-"

# The product crates a Coordinator crate may name as a dependency: the
# maintained client of each product it calls, and the source-neutral core of
# the two products whose wire types its adapters build. A product runtime or
# adopter tooling crate is never among them.
PRODUCT_CLIENT_CRATES = frozenset(
    {
        "registry-breg-client",
        "registry-casework-client",
        "registry-messaging-client",
        "registry-messaging-core",
        "registry-scheduling-client",
        "registry-scheduling-core",
    }
)

# The crates those clients carry. A Coordinator crate reaches them through a
# product client and never names one itself.
CARRIED_CRATES = frozenset(
    {
        "registry-casework-core",
        "registry-record",
        "registry-review-client",
        "registry-review-protocol",
    }
)

# The only registry crate that may reach a Coordinator crate: the command
# reference generator links every product's command tree to print it.
ALLOWED_DEPENDENTS = frozenset({"registry-cli-docs"})


def package_graph(metadata: dict) -> tuple[dict[str, str], dict[str, set[str]]]:
    names = {package["id"]: package["name"] for package in metadata["packages"]}
    resolve = metadata.get("resolve")
    if not resolve:
        raise ValueError("cargo metadata did not include a resolved dependency graph")
    edges = {
        node["id"]: {
            dependency["pkg"] if isinstance(dependency, dict) else dependency
            for dependency in node.get("deps", node.get("dependencies", []))
        }
        for node in resolve["nodes"]
    }
    return names, edges


def closure(start: str, edges: dict[str, set[str]]) -> set[str]:
    seen: set[str] = set()
    pending = list(edges.get(start, set()))
    while pending:
        package = pending.pop()
        if package in seen:
            continue
        seen.add(package)
        pending.extend(edges.get(package, set()) - seen)
    return seen


def inside_boundary(name: str) -> bool:
    """Whether a Coordinator crate may reach the crate called `name` at all."""
    return (
        not name.startswith(REGISTRY_PREFIX)
        or name.startswith((COORDINATOR_PREFIX, PLATFORM_PREFIX))
        or name in PRODUCT_CLIENT_CRATES
        or name in CARRIED_CRATES
    )


def violations(metadata: dict) -> list[str]:
    names, edges = package_graph(metadata)
    by_name = sorted(names.items(), key=lambda item: (item[1], item[0]))
    coordinator_ids = {
        package_id for package_id, name in names.items() if name.startswith(COORDINATOR_PREFIX)
    }
    if not coordinator_ids:
        # A renamed or removed crate must stop the gate, never empty it.
        raise ValueError("cargo metadata names no Coordinator crate")

    failures: list[str] = []
    for package_id, name in by_name:
        if package_id not in coordinator_ids:
            continue
        outside = sorted(
            {names[item] for item in closure(package_id, edges) if not inside_boundary(names[item])}
        )
        if outside:
            failures.append(
                f"{name} transitively depends on registry crate(s) outside the Coordinator "
                f"boundary: {', '.join(outside)}"
            )
        carried = sorted(
            {names[item] for item in edges.get(package_id, set()) if names[item] in CARRIED_CRATES}
        )
        if carried:
            failures.append(
                f"{name} depends directly on crate(s) it may reach only through a product "
                f"client: {', '.join(carried)}"
            )

    # The boundary runs both ways: a product, platform, or client crate that
    # reached the Coordinator would make it part of that crate's contract.
    for package_id, name in by_name:
        if (
            package_id in coordinator_ids
            or not name.startswith(REGISTRY_PREFIX)
            or name in ALLOWED_DEPENDENTS
        ):
            continue
        reached = sorted(
            {names[item] for item in closure(package_id, edges) if item in coordinator_ids}
        )
        if reached:
            failures.append(
                f"{name} transitively depends on Coordinator package(s): {', '.join(reached)}"
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
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"dependency-direction check could not inspect Cargo metadata: {error}", file=sys.stderr)
        return 2
    if failures:
        for failure in failures:
            print(f"dependency-direction violation: {failure}", file=sys.stderr)
        return 1
    print("Coordinator dependency direction holds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
