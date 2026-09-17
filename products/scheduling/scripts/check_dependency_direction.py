#!/usr/bin/env python3
"""Check Scheduling dependency direction from Cargo's resolved graph."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# The runtime products whose protocol surfaces must never reach a scheduling
# crate, directly or through any shared dependency.
PRODUCT_PREFIXES = ("registry-breg", "registry-casework", "registry-evidence")

# The source-neutral scheduling crates: the model and evaluators, and the
# caller-facing client. Their dependency closures must stay product-free and,
# for the core, free of every other scheduling crate.
NEUTRAL_CRATES = ("registry-scheduling-core", "registry-scheduling-client")


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


def product_violations(name: str, package_id: str, names: dict[str, str], edges: dict[str, set[str]]) -> list[str]:
    forbidden = sorted(
        {
            names[item]
            for item in closure(package_id, edges)
            if names[item].startswith(PRODUCT_PREFIXES)
        }
    )
    if forbidden:
        return [
            f"{name} transitively depends on other-product package(s): {', '.join(forbidden)}"
        ]
    return []


def internal_violations(name: str, package_id: str, names: dict[str, str], edges: dict[str, set[str]]) -> list[str]:
    failures: list[str] = []
    reached = closure(package_id, edges)
    if name == "registry-scheduling-core":
        # The core is the bottom of the product: it may depend on no other
        # scheduling crate, or the runtime and every replay would follow it.
        internal = sorted(
            {names[item] for item in reached if names[item].startswith("registry-scheduling")}
        )
        if internal:
            failures.append(
                f"registry-scheduling-core transitively depends on scheduling crate(s): {', '.join(internal)}"
            )
    if name == "registry-scheduling-client":
        # The client may share the core, never the runtime or adopter tooling.
        reaching_runtime = sorted(
            {
                names[item]
                for item in reached
                if names[item] in ("registry-scheduling", "registry-schedulingctl")
            }
        )
        if reaching_runtime:
            failures.append(
                f"registry-scheduling-client transitively depends on runtime crate(s): {', '.join(reaching_runtime)}"
            )
    return failures


def violations(metadata: dict) -> list[str]:
    names, edges = package_graph(metadata)
    ids_by_name: dict[str, list[str]] = {}
    for package_id, name in names.items():
        ids_by_name.setdefault(name, []).append(package_id)

    failures: list[str] = []
    for scheduling_name, package_ids in sorted(ids_by_name.items()):
        if not scheduling_name.startswith("registry-scheduling"):
            continue
        for package_id in package_ids:
            failures.extend(product_violations(scheduling_name, package_id, names, edges))
            failures.extend(internal_violations(scheduling_name, package_id, names, edges))

    # The boundary runs both ways: no other runtime product may reach into
    # scheduling through a dependency either.
    for package_id, package_name in sorted(names.items(), key=lambda item: item[1]):
        if not package_name.startswith(PRODUCT_PREFIXES):
            continue
        forbidden = sorted(
            {
                names[item]
                for item in closure(package_id, edges)
                if names[item].startswith("registry-scheduling")
            }
        )
        if forbidden:
            failures.append(
                f"{package_name} transitively depends on Scheduling package(s): {', '.join(forbidden)}"
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
    print("Scheduling dependency direction is source-neutral.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
