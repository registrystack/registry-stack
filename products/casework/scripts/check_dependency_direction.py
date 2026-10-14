#!/usr/bin/env python3
"""Check Casework/BReg dependency direction from Cargo's resolved graph."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# The Coordinator composes products through their public clients. It may use
# the Casework client and core, never the runtime, its tooling, or the BReg
# adapter. No Casework, review, or BReg crate may reach a Coordinator crate,
# including through its own test dependencies.
COORDINATOR_PREFIX = "registry-coordinator"
CASEWORK_FOR_COORDINATOR = ("registry-casework-client", "registry-casework-core")


def package_graph(
    metadata: dict,
) -> tuple[dict[str, str], dict[str, set[str]], dict[str, set[str]]]:
    names = {package["id"]: package["name"] for package in metadata["packages"]}
    resolve = metadata.get("resolve")
    if not resolve:
        raise ValueError("cargo metadata did not include a resolved dependency graph")
    every: dict[str, set[str]] = {}
    linked: dict[str, set[str]] = {}
    for node in resolve["nodes"]:
        every[node["id"]] = set()
        linked[node["id"]] = set()
        for dependency in node.get("deps", node.get("dependencies", [])):
            package = dependency["pkg"] if isinstance(dependency, dict) else dependency
            kinds = (
                {kind.get("kind") for kind in dependency.get("dep_kinds", [{}])}
                if isinstance(dependency, dict)
                else {None}
            )
            every[node["id"]].add(package)
            if kinds - {"dev"}:
                linked[node["id"]].add(package)
    return names, every, linked


def closure(
    start: str, every: dict[str, set[str]], linked: dict[str, set[str]]
) -> set[str]:
    """Include the package's tests, but not its dependencies' tests."""
    seen: set[str] = set()
    pending = list(every.get(start, set()))
    while pending:
        package = pending.pop()
        if package in seen:
            continue
        seen.add(package)
        pending.extend(linked.get(package, set()) - seen)
    return seen


def violations(metadata: dict) -> list[str]:
    names, every, linked = package_graph(metadata)
    ids_by_name: dict[str, list[str]] = {}
    for package_id, name in names.items():
        ids_by_name.setdefault(name, []).append(package_id)

    failures: list[str] = []
    for neutral_name in (
        "registry-review-protocol",
        "registry-review-client",
        "registry-casework-core",
        "registry-casework-client",
    ):
        for package_id in ids_by_name.get(neutral_name, []):
            forbidden = sorted(
                {names[item] for item in closure(package_id, every, linked) if names[item].startswith("registry-breg")}
            )
            if forbidden:
                failures.append(
                    f"{neutral_name} transitively depends on BReg package(s): {', '.join(forbidden)}"
                )

    for protocol_name in ("registry-review-protocol", "registry-review-client"):
        for package_id in ids_by_name.get(protocol_name, []):
            forbidden = sorted(
                {
                    names[item]
                    for item in closure(package_id, every, linked)
                    if names[item].startswith("registry-casework")
                }
            )
            if forbidden:
                failures.append(
                    f"{protocol_name} transitively depends on Casework package(s): "
                    f"{', '.join(forbidden)}"
                )

    for breg_id, breg_name in sorted(names.items(), key=lambda item: item[1]):
        if not breg_name.startswith("registry-breg"):
            continue
        forbidden = sorted(
            {names[item] for item in closure(breg_id, every, linked) if names[item].startswith("registry-casework")}
        )
        if forbidden:
            failures.append(
                f"{breg_name} transitively depends on Casework package(s): {', '.join(forbidden)}"
            )

    for package_id, package_name in sorted(names.items(), key=lambda item: item[1]):
        reached = {names[item] for item in closure(package_id, every, linked)}
        if package_name.startswith(("registry-casework", "registry-review-", "registry-breg")):
            forbidden = sorted(
                item for item in reached
                if item.startswith(COORDINATOR_PREFIX)
            )
            if forbidden:
                failures.append(
                    f"{package_name} transitively depends on Coordinator package(s): "
                    f"{', '.join(forbidden)}"
                )
        elif package_name.startswith(COORDINATOR_PREFIX):
            forbidden = sorted(
                item
                for item in reached
                if item.startswith("registry-casework") and item not in CASEWORK_FOR_COORDINATOR
            )
            if forbidden:
                failures.append(
                    f"{package_name} transitively depends on Casework package(s) other than "
                    f"its client and core: {', '.join(forbidden)}"
                )
    return failures


def load_metadata(repository_root: Path, fixture: Path | None) -> dict:
    if fixture:
        return json.loads(fixture.read_text(encoding="utf-8"))
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
    print("Casework dependency direction is source-neutral.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
