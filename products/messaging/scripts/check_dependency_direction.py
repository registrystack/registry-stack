#!/usr/bin/env python3
"""Check Messaging dependency direction from Cargo's resolved graph."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# The runtime products whose crates must never reach the Messaging runtime,
# directly or through any shared dependency. They may use its public client
# to reach Messaging over HTTP, like any external caller.
PRODUCT_PREFIXES = (
    "registry-breg",
    "registry-casework",
    "registry-coordinator",
    "registry-documents",
    "registry-discovery",
    "registry-render",
    "registry-scheduling",
    "registry-evidence",
)

MESSAGING_PREFIX = "registry-messaging"

# The Messaging runtime and its adopter tooling. No other product's crate may
# reach either of them.
MESSAGING_RUNTIME = ("registry-messaging", "registry-messagingctl")

# The Rust client and its Node.js and Python bindings. They reach the runtime
# over its public HTTP contract only, never through a dependency.
MESSAGING_CLIENT_PREFIX = "registry-messaging-client"

# The unified client facade composes every product client. Like a product
# crate, it may use the Messaging client but never the runtime.
UNIFIED_CLIENT_PREFIX = "registry-stack-client"


def package_graph(
    metadata: dict,
) -> tuple[dict[str, str], dict[str, set[str]], dict[str, set[str]]]:
    """All root edges and linked edges, excluding dependencies' test tooling."""
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
            package_id = dependency["pkg"] if isinstance(dependency, dict) else dependency
            every[node["id"]].add(package_id)
            kinds = (
                {kind.get("kind") for kind in dependency.get("dep_kinds", [{}])}
                if isinstance(dependency, dict)
                else {None}
            )
            if kinds - {"dev"}:
                linked[node["id"]].add(package_id)
    return names, every, linked


def closure(
    start: str, every: dict[str, set[str]], linked: dict[str, set[str]]
) -> set[str]:
    """The root's test dependencies count; its dependencies' tests do not link."""
    seen: set[str] = set()
    pending = list(every.get(start, set()))
    while pending:
        package = pending.pop()
        if package in seen:
            continue
        seen.add(package)
        pending.extend(linked.get(package, set()) - seen)
    return seen


def product_violations(
    name: str,
    package_id: str,
    names: dict[str, str],
    every: dict[str, set[str]],
    linked: dict[str, set[str]],
) -> list[str]:
    forbidden = sorted(
        {
            names[item]
            for item in closure(package_id, every, linked)
            if names[item].startswith(PRODUCT_PREFIXES)
        }
    )
    if forbidden:
        return [
            f"{name} transitively depends on other-product package(s): {', '.join(forbidden)}"
        ]
    return []


def internal_violations(
    name: str,
    package_id: str,
    names: dict[str, str],
    every: dict[str, set[str]],
    linked: dict[str, set[str]],
) -> list[str]:
    failures: list[str] = []
    reached = closure(package_id, every, linked)
    if name == "registry-messaging-core":
        # The core is the bottom of the product: it may depend on no other
        # Messaging crate, or the runtime would follow every caller of it.
        internal = sorted(
            {names[item] for item in reached if names[item].startswith(MESSAGING_PREFIX)}
        )
        if internal:
            failures.append(
                "registry-messaging-core transitively depends on Messaging crate(s): "
                f"{', '.join(internal)}"
            )
    if name.startswith(MESSAGING_CLIENT_PREFIX):
        # The client and its bindings may share the core, never the runtime or
        # adopter tooling.
        reaching_runtime = sorted(
            {names[item] for item in reached if names[item] in MESSAGING_RUNTIME}
        )
        if reaching_runtime:
            failures.append(
                f"{name} transitively depends on runtime crate(s): "
                f"{', '.join(reaching_runtime)}"
            )
    return failures


def violations(metadata: dict) -> list[str]:
    names, every, linked = package_graph(metadata)
    failures: list[str] = []
    for package_id, package_name in sorted(names.items(), key=lambda item: item[1]):
        if package_name.startswith(MESSAGING_PREFIX):
            failures.extend(
                product_violations(package_name, package_id, names, every, linked)
            )
            failures.extend(
                internal_violations(package_name, package_id, names, every, linked)
            )

    # The boundary runs both ways: no other runtime product, and no unified
    # client, may reach the Messaging runtime through a dependency either.
    for package_id, package_name in sorted(names.items(), key=lambda item: item[1]):
        if not package_name.startswith((*PRODUCT_PREFIXES, UNIFIED_CLIENT_PREFIX)):
            continue
        forbidden = sorted(
            {
                names[item]
                for item in closure(package_id, every, linked)
                if names[item] in MESSAGING_RUNTIME
            }
        )
        if forbidden:
            failures.append(
                f"{package_name} transitively depends on Messaging runtime package(s): "
                f"{', '.join(forbidden)}"
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
    print("Messaging dependency direction is product-neutral.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
