#!/usr/bin/env python3
"""Check Messaging dependency direction from Cargo's resolved graph."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# The runtime products whose crates must never reach a Messaging crate,
# directly or through any shared dependency. Products reach Messaging over its
# public HTTP contract, like any external caller.
PRODUCT_PREFIXES = (
    "registry-breg",
    "registry-casework",
    "registry-scheduling",
    "registry-evidence",
    "registry-relay",
)

MESSAGING_PREFIX = "registry-messaging"

# The Messaging runtime and its adopter tooling. No other product's crate may
# reach either of them.
MESSAGING_RUNTIME = ("registry-messaging", "registry-messagingctl")


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


def product_violations(
    name: str, package_id: str, names: dict[str, str], edges: dict[str, set[str]]
) -> list[str]:
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


def internal_violations(
    name: str, package_id: str, names: dict[str, str], edges: dict[str, set[str]]
) -> list[str]:
    failures: list[str] = []
    reached = closure(package_id, edges)
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
    if name == "registry-messaging-client":
        # The client may share the core, never the runtime or adopter tooling.
        reaching_runtime = sorted(
            {names[item] for item in reached if names[item] in MESSAGING_RUNTIME}
        )
        if reaching_runtime:
            failures.append(
                "registry-messaging-client transitively depends on runtime crate(s): "
                f"{', '.join(reaching_runtime)}"
            )
    return failures


def violations(metadata: dict) -> list[str]:
    names, edges = package_graph(metadata)
    failures: list[str] = []
    for package_id, package_name in sorted(names.items(), key=lambda item: item[1]):
        if package_name.startswith(MESSAGING_PREFIX):
            failures.extend(product_violations(package_name, package_id, names, edges))
            failures.extend(internal_violations(package_name, package_id, names, edges))

    # The boundary runs both ways: no other runtime product may reach the
    # Messaging runtime through a dependency either.
    for package_id, package_name in sorted(names.items(), key=lambda item: item[1]):
        if not package_name.startswith(PRODUCT_PREFIXES):
            continue
        forbidden = sorted(
            {
                names[item]
                for item in closure(package_id, edges)
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
