#!/usr/bin/env python3
"""Check Casework/BReg dependency direction from Cargo's resolved graph."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


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


def violations(metadata: dict) -> list[str]:
    names, edges = package_graph(metadata)
    ids_by_name: dict[str, list[str]] = {}
    for package_id, name in names.items():
        ids_by_name.setdefault(name, []).append(package_id)

    failures: list[str] = []
    for neutral_name in ("registry-casework-core", "registry-casework-client"):
        for package_id in ids_by_name.get(neutral_name, []):
            forbidden = sorted(
                {names[item] for item in closure(package_id, edges) if names[item].startswith("registry-breg")}
            )
            if forbidden:
                failures.append(
                    f"{neutral_name} transitively depends on BReg package(s): {', '.join(forbidden)}"
                )

    for breg_id, breg_name in sorted(names.items(), key=lambda item: item[1]):
        if not breg_name.startswith("registry-breg"):
            continue
        forbidden = sorted(
            {names[item] for item in closure(breg_id, edges) if names[item].startswith("registry-casework")}
        )
        if forbidden:
            failures.append(
                f"{breg_name} transitively depends on Casework package(s): {', '.join(forbidden)}"
            )
    return failures


def load_metadata(repository_root: Path, fixture: Path | None) -> dict:
    if fixture:
        return json.loads(fixture.read_text(encoding="utf-8"))
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
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
