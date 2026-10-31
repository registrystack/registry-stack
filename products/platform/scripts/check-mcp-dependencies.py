#!/usr/bin/env python3
"""Check the shared and configurable MCP dependency boundaries."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


EDGE = "registry-mcp-edge"
RUNTIME = "registry-mcp"
# The generic service composes reviewed providers and maintained clients.
# Check both the public entry points and their permitted source closure so an
# implementation dependency cannot hide behind a client or provider name.
PROVIDER_BOUNDARIES = frozenset({"registry-breg-mcp"})
CLIENT_BOUNDARIES = frozenset({"registry-casework-client"})
REVIEWED_BOUNDARIES = PROVIDER_BOUNDARIES | CLIENT_BOUNDARIES

BOUNDARY_PRODUCTS = {
    "registry-breg-mcp": frozenset({
        EDGE, "registry-breg-client", "registry-record", "registry-review-protocol",
    }),
    "registry-casework-client": frozenset({
        "registry-casework-core", "registry-review-client", "registry-review-protocol",
    }),
}


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
    start: str,
    roots: dict[str, set[str]],
    linked: dict[str, set[str]],
    leaves: frozenset[str] = frozenset(),
) -> set[str]:
    """Follow selected root edges, then only linked production edges."""

    seen: set[str] = set()
    pending = list(roots.get(start, set()))
    while pending:
        package = pending.pop()
        if package in seen:
            continue
        seen.add(package)
        if package not in leaves:
            pending.extend(linked.get(package, set()) - seen)
    return seen


def violations(metadata: dict) -> list[str]:
    names, every, linked = package_graph(metadata)
    ids_by_name: dict[str, list[str]] = {}
    for package_id, name in names.items():
        ids_by_name.setdefault(name, []).append(package_id)

    failures: list[str] = []
    for required in (EDGE, RUNTIME):
        if len(ids_by_name.get(required, [])) != 1:
            failures.append(f"workspace must contain exactly one {required} package")
    if failures:
        return failures

    edge_id = ids_by_name[EDGE][0]
    # Test fixtures can otherwise make a supposedly neutral shared crate depend
    # on a product, so inspect all direct edge kinds before following only code
    # that dependencies themselves link.
    edge_products = sorted(
        {
            names[package]
            for package in closure(edge_id, every, linked)
            if names[package].startswith("registry-")
            and not names[package].startswith("registry-platform-")
        }
    )
    if edge_products:
        failures.append(
            f"{EDGE} depends on product package(s): {', '.join(edge_products)}"
        )

    runtime_id = ids_by_name[RUNTIME][0]
    boundary_ids = frozenset(
        package_id
        for package_id, name in names.items()
        if name in REVIEWED_BOUNDARIES
    )
    runtime_products = sorted(
        {
            names[package]
            for package in closure(runtime_id, linked, linked, boundary_ids)
            if names[package].startswith("registry-")
            and names[package] != EDGE
            and not names[package].startswith("registry-platform-")
            and package not in boundary_ids
        }
    )
    if runtime_products:
        failures.append(
            f"{RUNTIME} reaches product runtime, core, or tooling package(s) "
            f"outside a maintained client/provider boundary: {', '.join(runtime_products)}"
        )
    for boundary, allowed in BOUNDARY_PRODUCTS.items():
        for boundary_id in ids_by_name.get(boundary, []):
            unexpected = sorted({
                names[package]
                for package in closure(boundary_id, linked, linked)
                if names[package].startswith("registry-")
                and not names[package].startswith("registry-platform-")
                and names[package] not in allowed
            })
            if unexpected:
                failures.append(
                    f"{boundary} reaches packages outside its reviewed source closure: "
                    + ", ".join(unexpected)
                )

    for package_id, name in names.items():
        if (not name.startswith("registry-")
                or name.startswith("registry-platform-")
                or name in {EDGE, RUNTIME, "registry-cli-docs"}
                or name in PROVIDER_BOUNDARIES):
            continue
        upstream = sorted({
            names[dependency]
            for dependency in closure(package_id, linked, linked)
            if names[dependency] in {EDGE, RUNTIME}
        })
        if upstream:
            failures.append(
                f"{name} reaches MCP supporting code: " + ", ".join(upstream)
            )
    return failures


def load_metadata(repository_root: Path, fixture: Path | None) -> dict:
    if fixture:
        return json.loads(fixture.read_text(encoding="utf-8"))
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--all-features",
            "--format-version",
            "1",
        ],
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
            f"MCP dependency-direction check could not inspect Cargo metadata: {error}",
            file=sys.stderr,
        )
        return 2
    if failures:
        for failure in failures:
            print(f"dependency-direction violation: {failure}", file=sys.stderr)
        return 1
    print("MCP dependencies preserve shared-edge and product boundaries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
