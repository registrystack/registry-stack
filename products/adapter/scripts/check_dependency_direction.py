#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check Adapter dependency direction from Cargo's resolved graph.

The Adapter's engine and facade stay source-neutral: `registry-adapter`,
`registry-adapter-core`, `registry-adapter-job`, and
`registry-adapterctl` reach shared platform primitives and nothing else
of the workspace, and no Adapter crate links a Coordinator crate. The
one product-surface exception is the parked connector crate
(`products/adapter/CONCEPT.md` section 17.5):
`registry-adapter-connectors` reaches exactly `registry-breg-client`
behind its off-by-default cargo feature, is reached by no other
workspace crate, is linked by no facade binary and no job path while
parked, and never reaches a product runtime, adopter tooling,
supporting service, binding, or database crate.

Inside `registry-adapter` the engine boundary is a module
(`crates/registry-adapter/src/engine`, `products/adapter/CONCEPT.md`
section 17.2): the listener-free engine the ingestion job runs and the
facade links. Until the boundary becomes its own crate, this gate
holds the same line at import level: no file under `src/engine` names
a facade module, and none names a dependency only the facade half
links. When the split lands, `cargo tree` on the new crate asserts the
same line and this section retires with the move.

Edges are read with every feature enabled and on every target, so an
optional dependency no default build enables still cannot escape the
closure check. A package's own dev-dependencies count, so a test cannot
link what the package may not. The dev-dependencies of a crate it
reaches are not followed: Cargo never builds them into the package being
checked.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ADAPTER_PREFIX = "registry-adapter"

# The engine crates the product contract keeps source-neutral. None may
# reach a product crate of any kind.
ADAPTER_ENGINE = (
    "registry-adapter",
    "registry-adapter-core",
    "registry-adapter-job",
    "registry-adapterctl",
)

# The engine boundary module inside registry-adapter, and the crate it
# becomes when the split lands.
ENGINE_MODULE_DIRECTORY = Path("crates/registry-adapter/src/engine")

# The facade modules of registry-adapter, staying beside the listener
# when the engine module becomes a crate.
FACADE_MODULES = (
    "cli",
    "custody",
    "facade",
    "facade_generated_properties",
    "idempotent",
    "journal",
    "notifier",
    "serve",
    "replay_serve",
)

# Dependencies only the facade half of registry-adapter may link. The
# engine half reaches the platform's shared crates freely.
FACADE_DEPENDENCIES = (
    "axum",
    "deadpool_postgres",
    "tokio_postgres",
    "tokio_postgres_rustls",
    "jsonwebtoken",
    "registry_platform_oidc",
)

# The one product-surface exception: `registry-adapter-connectors` reaches
# exactly one maintained product client, `registry-breg-client`, behind its
# off-by-default cargo feature, is reached by no other workspace crate, is
# parked (no facade binary and no job path links it), and never reaches a
# product runtime, adopter tooling, supporting service, binding, database
# crate, or any Coordinator crate.
CONNECTOR = "registry-adapter-connectors"

# The maintained product client the parked connector may reach.
CONNECTOR_CLIENTS = frozenset(
    {
        "registry-breg-client",
    }
)

# The unified Rust facade is never a dependency of the connector.
UNIFIED_CLIENT = "registry-stack-client"

# Crates every Adapter crate may reach: shared platform primitives and
# neutral support crates without product semantics.
SHARED_SUPPORT = frozenset(
    {
        "registry-record",
        "registry-platform-testing",
    }
)

# Workspace crates the connector's product clients carry into its
# closure, each with the client that carries it (Coordinator's
# CLIENT_SUPPORT precedent).
CLIENT_SUPPORT = {
    "registry-record": "registry-breg-client carries the neutral Record v1 DTOs",
    "registry-review-protocol": "the review handoff contract registry-breg-client carries",
}

# Crates outside the Adapter that may depend on Adapter crates, with the
# Adapter crates they may reach.
ALLOWED_DEPENDENTS = {
    # Builds the published CLI reference from every binary's command
    # tree, adapterctl included.
    "registry-cli-docs": frozenset(
        {
            "registry-adapter",
            "registry-adapter-core",
            "registry-adapterctl",
        }
    ),
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


def engine_may_reach(name: str) -> bool:
    if not name.startswith("registry-"):
        return True
    if name in ADAPTER_ENGINE:
        return True
    return name.startswith("registry-platform-") or name in SHARED_SUPPORT


def connector_may_reach(name: str) -> bool:
    if not name.startswith("registry-"):
        return True
    if name.startswith("registry-platform-") or name == "registry-adapter-core":
        return True
    # The product clients carry their own product's source-neutral core
    # (wire types); the connector reaches a core only through its
    # client, never as its own dependency ambition. Coordinator's gate
    # admits product cores the same way.
    if name.endswith("-core"):
        return True
    return name in CONNECTOR_CLIENTS or name in CLIENT_SUPPORT


def violations(metadata: dict) -> list[str]:
    names, every, linked = package_graph(metadata)
    failures: list[str] = []
    for package_id, name in sorted(names.items(), key=lambda item: item[1]):
        reached = {names[item] for item in closure(package_id, every, linked)}
        if name in ADAPTER_ENGINE:
            refused = sorted(item for item in reached if not engine_may_reach(item))
            if refused:
                failures.append(
                    f"{name} reaches package(s) outside registry-platform-* and "
                    f"neutral support: {', '.join(refused)}"
                )
        elif name == CONNECTOR:
            refused = sorted(item for item in reached if not connector_may_reach(item))
            if refused:
                failures.append(
                    f"{name} reaches package(s) outside the product clients, "
                    f"registry-adapter-core, and registry-platform-*: "
                    f"{', '.join(refused)}"
                )
            unified = sorted(item for item in reached if item == UNIFIED_CLIENT)
            if unified:
                failures.append(
                    f"{name} reaches the unified facade {UNIFIED_CLIENT}; "
                    "a connector carries one product client surface, not the facade"
                )
        elif name.startswith(ADAPTER_PREFIX):
            failures.append(
                f"{name} is an Adapter crate this gate does not know; name its rule here"
            )
        else:
            adapter = {item for item in reached if item.startswith(ADAPTER_PREFIX)}
            permitted = ALLOWED_DEPENDENTS.get(name, frozenset())
            refused = sorted(adapter - permitted)
            if refused:
                failures.append(
                    f"{name} depends on Adapter package(s) it is not listed for: "
                    f"{', '.join(refused)}"
                )
    return failures


def module_violations(repository_root: Path) -> list[str]:
    """Import-level engine boundary inside registry-adapter.

    Reads the files under the engine module and refuses a name of a
    facade module or a facade-only dependency. Comments are stripped
    first, so documentation may say `facade` while code may not.
    """
    engine_root = repository_root / ENGINE_MODULE_DIRECTORY
    if not engine_root.is_dir():
        return [
            "crates/registry-adapter/src/engine is missing; the engine "
            "module boundary is not assembled"
        ]
    failures: list[str] = []
    for path in sorted(engine_root.rglob("*.rs")):
        text = strip_comments(path.read_text(encoding="utf-8"))
        relative = path.relative_to(repository_root)
        for module in FACADE_MODULES:
            for prefix in ("crate", "super::super"):
                if re.search(rf"\b{prefix}::{module}\b", text):
                    failures.append(
                        f"{relative} names the facade module {module}"
                    )
        for dependency in FACADE_DEPENDENCIES:
            if re.search(rf"\b{dependency}::", text):
                failures.append(
                    f"{relative} names the facade-only dependency {dependency}"
                )
    return failures


def strip_comments(text: str) -> str:
    """Remove line and block comments, keeping strings' contents short."""
    without_blocks = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return "\n".join(
        line.split("//", 1)[0] if "//" in line else line
        for line in without_blocks.split("\n")
    )


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
        failures.extend(module_violations(repository_root))
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
    print("Adapter dependency direction holds: the engine is source-neutral;")
    print("the engine module names no facade module or facade-only")
    print("dependency; the parked connector reaches registry-breg-client")
    print("alone, and no Adapter crate links a Coordinator crate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
