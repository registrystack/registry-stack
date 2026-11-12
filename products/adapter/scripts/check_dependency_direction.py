#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check Adapter dependency direction from Cargo's resolved graph.

The Adapter's core and shared engine stay source-neutral, and no Adapter
crate links a Coordinator crate. The direct BReg ingestion connector
exception is
(`products/adapter/CONCEPT.md` section 17.5):
`registry-adapter-connectors` reaches exactly `registry-breg-client`
behind the job host's exact off-by-default `direct-breg` feature, is linked
by no facade or engine crate, and never reaches a product runtime, adopter tooling,
supporting service, binding, or database crate.

The payment host exception (CONCEPT section 19) permits `registry-adapter`
to link its payment protocol, standalone synthetic provider connector, and
the public BReg client for exact restricted Actions. Authoring inherits that
closure only through its host edge. No product runtime enters it, and no
payment or product-client dependency enters the shared engine. The provider
connector itself reaches only the runtime-free payment protocol and platform
transport primitives.

`registry-adapter-engine` is the listener-free engine used by ingestion,
the facade, Evidence and BReg external projections. Its resolved closure may reach only
`registry-adapter-core`, shared platform crates, and non-workspace support.
The source check separately refuses facade-only dependencies, including
Axum and PostgreSQL clients. Evidence and BReg may reach only Adapter core
and engine.

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

# Hosts and engine crates checked here. The facade host has the explicit
# payment exception; authoring may inherit it through that host edge only.
ADAPTER_ENGINE = (
    "registry-adapter-engine",
    "registry-adapter",
    "registry-adapter-core",
    "registry-adapter-job",
    "registry-adapterctl",
)

# The extracted engine crate's source boundary.
ENGINE_MODULE_DIRECTORY = Path("crates/registry-adapter-engine/src")
ENGINE_CRATE = "registry-adapter-engine"
JOB_HOST = "registry-adapter-job"

# The built-in GovStack Consultation wire protocol belongs to the facade host
# under `registry-adapter::govstack::consultation`. The generic engine may keep
# declarative project metadata and source/schema/transform mechanisms, but not
# this fixed protocol module, its wire DTOs, its public URLs, or its mount.
GOVSTACK_PROTOCOL_MODULES = frozenset({"govstack", "consultation"})
GOVSTACK_WIRE_IDENTIFIERS = (
    "ConsultationCapability",
    "CallerCapabilities",
    "CapabilityCollection",
    "CapabilityOperation",
    "CAPABILITIES_PATH",
)
GOVSTACK_WIRE_TEXT = (
    "/govstack/registries",
)

ADAPTER_REACH = {
    "registry-adapter-engine": frozenset({"registry-adapter-core"}),
    "registry-adapter": frozenset(
        {"registry-adapter-core", "registry-adapter-engine"}
    ),
    "registry-adapter-core": frozenset(),
    "registry-adapter-job": frozenset(
        {"registry-adapter-core", "registry-adapter-engine"}
    ),
    "registry-adapterctl": frozenset(
        {"registry-adapter", "registry-adapter-core", "registry-adapter-engine"}
    ),
}

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
    "payments",
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
# off-by-default Cargo feature, is reached only through the job host's exact
# feature path, and never reaches a product runtime, adopter tooling,
# supporting service, binding, database crate, or any Coordinator crate.
CONNECTOR = "registry-adapter-connectors"
PAYMENT_HOST = "registry-adapter"
PAYMENT_PROTOCOL = "registry-payment-protocol"
PAYMENT_PROVIDERS = frozenset({"registry-payment-simulator-connector", "registry-payment-mifos-connector"})

# The maintained product client the connector may reach.
CONNECTOR_CLIENTS = frozenset(
    {
        "registry-breg-client",
    }
)

# Features that stay off by default on the job host and the connector, so a
# plain build never links the BReg client or the Coordinator event path.
DEFAULT_OFF_FEATURES = frozenset(
    {
        "breg",
        "coordinator-event",
        "direct-breg",
        "native-test-support",
        "signed-coordinator-event",
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
            "registry-adapter-engine",
            # Transitive through the job host only, under its exact
            # off-by-default direct-breg feature.
            "registry-adapter-connectors",
            "registry-adapter-job",
            "registry-adapterctl",
        }
    ),
    # BReg owns external-projection grants, storage and disclosure. Its
    # acquisition host embeds only the listener-free Adapter boundary.
    "registry-breg": frozenset(
        {"registry-adapter-core", "registry-adapter-engine"}
    ),
    # The BReg authoring tool reaches the same code through registry-breg.
    "registry-bregctl": frozenset(
        {"registry-adapter-core", "registry-adapter-engine"}
    ),
    # Evidence embeds the listener-free engine and core contract, never the
    # facade host, job host, connector, or Adapter tooling.
    "registry-evidence": frozenset(
        {
            "registry-adapter-core",
            "registry-adapter-engine",
        }
    ),
    # Evidence's public runtime surface carries its listener-free Adapter
    # engine implementation to these maintained consumers. None may reach
    # the facade, job host, connector, or Adapter tooling.
    "registry-casework": frozenset(
        {
            "registry-adapter-core",
            "registry-adapter-engine",
        }
    ),
    # Casework's PostgreSQL proof can link BReg, and caseworkctl can reach
    # that feature-enabled runtime. This adds no new Adapter host edge.
    "registry-caseworkctl": frozenset(
        {"registry-adapter-core", "registry-adapter-engine"}
    ),
    "registry-discovery-client": frozenset(
        {
            "registry-adapter-core",
            "registry-adapter-engine",
        }
    ),
    "registry-evidence-client": frozenset(
        {
            "registry-adapter-core",
            "registry-adapter-engine",
        }
    ),
    "registry-evidencectl": frozenset(
        {
            "registry-adapter-core",
            "registry-adapter-engine",
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


def linked_closure(start: str, linked: dict[str, set[str]]) -> set[str]:
    """Normal/build dependencies below an already-reached package."""
    seen: set[str] = set()
    pending = list(linked.get(start, set()))
    while pending:
        package = pending.pop()
        if package in seen:
            continue
        seen.add(package)
        pending.extend(linked.get(package, set()) - seen)
    return seen


def engine_may_reach(owner: str, name: str) -> bool:
    if owner == ENGINE_CRATE and name.replace("-", "_") in FACADE_DEPENDENCIES:
        return False
    if not name.startswith("registry-"):
        return True
    if name.startswith(ADAPTER_PREFIX):
        return name in ADAPTER_REACH[owner]
    return name.startswith("registry-platform-") or name in SHARED_SUPPORT


def connector_may_reach(name: str) -> bool:
    if not name.startswith("registry-"):
        return True
    if name.startswith("registry-platform-") or name == "registry-adapter-core":
        return True
    return name in CONNECTOR_CLIENTS or name in CLIENT_SUPPORT


def payment_host_may_reach(name: str) -> bool:
    """The host keeps attempts and calls only the public BReg client surface."""
    return (
        engine_may_reach(PAYMENT_HOST, name)
        or name == PAYMENT_PROTOCOL or name in PAYMENT_PROVIDERS
        or name in CONNECTOR_CLIENTS
        or name in CLIENT_SUPPORT
    )


def authoring_refused(start, names, every, linked) -> set[str]:
    """Authoring may inherit the host closure and replay a payment provider, not link product clients itself."""
    refused = set()
    for dependency in every.get(start, set()):
        dependency_name = names[dependency]
        if dependency_name == PAYMENT_HOST:
            permits = payment_host_may_reach
        elif dependency_name in PAYMENT_PROVIDERS:
            permits = lambda name: (
                not name.startswith("registry-")
                or name == dependency_name
                or name == PAYMENT_PROTOCOL
                or name.startswith("registry-platform-")
            )
        else:
            permits = lambda name: engine_may_reach("registry-adapterctl", name)
        for reached in {dependency, *linked_closure(dependency, linked)}:
            # The host is the declared authoring edge itself.
            if names[reached] != PAYMENT_HOST and not permits(names[reached]):
                refused.add(names[reached])
    return refused


def job_refused(
    start: str,
    names: dict[str, str],
    every: dict[str, set[str]],
    linked: dict[str, set[str]],
) -> set[str]:
    """Check each direct job edge under the policy that owns its subtree."""
    refused: set[str] = set()
    for dependency in every.get(start, set()):
        dependency_name = names[dependency]
        permits = (
            lambda name: name == CONNECTOR or connector_may_reach(name)
        ) if dependency_name == CONNECTOR else (
            lambda name: engine_may_reach(JOB_HOST, name)
        )
        for reached in {dependency, *linked_closure(dependency, linked)}:
            if not permits(names[reached]):
                refused.add(names[reached])
    return refused


def job_feature_violations(metadata: dict) -> list[str]:
    """Hold the connector edge to the reviewed off-by-default features."""
    package = next(
        (item for item in metadata["packages"] if item["name"] == JOB_HOST),
        None,
    )
    if package is None:
        return [f"{JOB_HOST} is missing from Cargo metadata"]
    connector = next(
        (
            item
            for item in package.get("dependencies", [])
            if item.get("name") == CONNECTOR
        ),
        None,
    )
    failures: list[str] = []
    if connector is None or not connector.get("optional", False):
        failures.append(
            f"{JOB_HOST} must keep {CONNECTOR} as an optional normal dependency"
        )
    elif connector.get("uses_default_features", True):
        failures.append(
            f"{JOB_HOST} must take {CONNECTOR} with default-features = false"
        )
    features = package.get("features", {})
    enabled_by_default = sorted(set(features.get("default", [])) & DEFAULT_OFF_FEATURES)
    if enabled_by_default:
        failures.append(
            f"{JOB_HOST} enables default-off feature(s) by default: "
            + ", ".join(enabled_by_default)
        )
    direct = set(features.get("direct-breg", []))
    expected_direct = {
        f"dep:{CONNECTOR}",
        "dep:registry-platform-crypto",
        "dep:registry-platform-httputil",
        f"{CONNECTOR}/breg",
    }
    if direct != expected_direct:
        failures.append(
            f"{JOB_HOST} feature direct-breg must contain exactly: "
            + ", ".join(sorted(expected_direct))
        )
    native = set(features.get("native-test-support", []))
    expected_native = {
        "direct-breg",
        f"{CONNECTOR}/native-test-support",
    }
    if native != expected_native:
        failures.append(
            f"{JOB_HOST} feature native-test-support must contain exactly: "
            + ", ".join(sorted(expected_native))
        )
    signed = set(features.get("signed-coordinator-event", []))
    expected_signed = {
        f"dep:{CONNECTOR}",
        "dep:registry-platform-httputil",
        f"{CONNECTOR}/coordinator-event",
    }
    if signed != expected_signed:
        failures.append(
            f"{JOB_HOST} feature signed-coordinator-event must contain exactly: "
            + ", ".join(sorted(expected_signed))
        )

    connector_package = next(
        (item for item in metadata["packages"] if item["name"] == CONNECTOR),
        None,
    )
    if connector_package is None:
        failures.append(f"{CONNECTOR} is missing from Cargo metadata")
        return failures
    connector_default = sorted(
        set(connector_package.get("features", {}).get("default", []))
        & DEFAULT_OFF_FEATURES
    )
    if connector_default:
        failures.append(
            f"{CONNECTOR} enables default-off feature(s) by default: "
            + ", ".join(connector_default)
        )
    coordinator_event = set(
        connector_package.get("features", {}).get("coordinator-event", [])
    )
    expected_coordinator_event = {
        "dep:registry-platform-crypto",
        "dep:registry-platform-hooks",
        "dep:registry-platform-httputil",
        "dep:time",
        "dep:tokio",
        "dep:zeroize",
    }
    if coordinator_event != expected_coordinator_event:
        failures.append(
            f"{CONNECTOR} feature coordinator-event must contain exactly: "
            + ", ".join(sorted(expected_coordinator_event))
        )
    return failures


def violations(metadata: dict) -> list[str]:
    names, every, linked = package_graph(metadata)
    failures: list[str] = []
    for package_id, name in sorted(names.items(), key=lambda item: item[1]):
        reached = {names[item] for item in closure(package_id, every, linked)}
        if name in ADAPTER_ENGINE:
            if name == JOB_HOST:
                refused = sorted(job_refused(package_id, names, every, linked))
            elif name == PAYMENT_HOST:
                refused = sorted(item for item in reached if not payment_host_may_reach(item))
            elif name == "registry-adapterctl":
                refused = sorted(authoring_refused(package_id, names, every, linked))
            else:
                refused = sorted(
                    item for item in reached if not engine_may_reach(name, item)
                )
            if refused:
                failures.append(
                    f"{name} reaches package(s) outside registry-platform-* and "
                    f"neutral support: {', '.join(refused)}"
                )
        elif name == PAYMENT_PROTOCOL or name in PAYMENT_PROVIDERS:
            refused = sorted(
                item for item in reached
                if item.startswith("registry-")
                and not (
                    name in PAYMENT_PROVIDERS
                    and (item == PAYMENT_PROTOCOL or item.startswith("registry-platform-"))
                )
            )
            if refused:
                failures.append(f"{name} reaches package(s) outside its payment boundary: {', '.join(refused)}")
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
            refused_set = adapter - permitted
            direct = {names[item] for item in every.get(package_id, set())}
            if CONNECTOR in direct:
                refused_set.add(CONNECTOR)
            refused = sorted(refused_set)
            if refused:
                failures.append(
                    f"{name} depends on Adapter package(s) it is not listed for: "
                    f"{', '.join(refused)}"
                )
    return failures


def module_violations(repository_root: Path) -> list[str]:
    """Import-level boundary inside registry-adapter-engine.

    Reads the files under the engine module and refuses a name of a
    facade module or a facade-only dependency. Comments are stripped
    first, so documentation may say `facade` while code may not.
    """
    engine_root = repository_root / ENGINE_MODULE_DIRECTORY
    if not engine_root.is_dir():
        return [
            "crates/registry-adapter-engine/src is missing; the engine "
            "crate boundary is not assembled"
        ]
    failures: list[str] = []
    for path in sorted(engine_root.rglob("*.rs")):
        text = strip_comments(path.read_text(encoding="utf-8"))
        relative = path.relative_to(repository_root)
        depth = module_depth(path.relative_to(engine_root))
        for module in sorted(crate_root_modules(text, depth) & set(FACADE_MODULES)):
            failures.append(f"{relative} names the facade module {module}")
        for dependency in FACADE_DEPENDENCIES:
            if re.search(rf"\b{dependency}::", text) or re.search(
                rf"\b(?:use|extern\s+crate)\s+(?:::)?{dependency}\b", text
            ):
                failures.append(
                    f"{relative} names the facade-only dependency {dependency}"
                )
    return failures


def govstack_protocol_violations(repository_root: Path) -> list[str]:
    """Refuse fixed GovStack wire behavior in the listener-free engine.

    The check is deliberately narrower than a search for "consultation". The
    project DTO and generic loading, schema and transformation code may retain
    that domain-neutral metadata name. What may not return is a protocol module,
    a fixed wire DTO/constant, a GovStack problem URL, or the host mount.
    """
    engine_root = repository_root / ENGINE_MODULE_DIRECTORY
    if not engine_root.is_dir():
        return []
    failures: list[str] = []
    for path in sorted(engine_root.rglob("*.rs")):
        source_relative = path.relative_to(engine_root)
        relative = path.relative_to(repository_root)
        if source_relative.stem == "consultation" or "govstack" in source_relative.parts:
            failures.append(f"{relative} is a fixed GovStack protocol module path")

        text = strip_comments(path.read_text(encoding="utf-8"))
        depth = module_depth(source_relative)
        for module in sorted(
            crate_root_modules(text, depth) & GOVSTACK_PROTOCOL_MODULES
        ):
            failures.append(f"{relative} names the fixed GovStack protocol module {module}")

        markers = [
            identifier
            for identifier in GOVSTACK_WIRE_IDENTIFIERS
            if re.search(rf"\b{re.escape(identifier)}\b", text)
        ]
        markers.extend(marker for marker in GOVSTACK_WIRE_TEXT if marker in text)
        if markers:
            failures.append(
                f"{relative} contains fixed GovStack wire marker(s): "
                + ", ".join(markers)
            )
    return failures


def module_depth(relative: Path) -> int:
    """How many `super::` steps from a file under the engine reach the crate root."""
    parts = list(relative.with_suffix("").parts)
    if parts and parts[-1] == "mod":
        parts.pop()
    return 1 + len(parts)


# A path rooted at the crate (`crate::`) or at a run of `super::` steps,
# followed by one identifier or a brace group.
CRATE_PATH = re.compile(r"(?<![\w:])((?:crate|super)(?:::super)*)::(\{|[A-Za-z_]\w*)")


def crate_root_modules(text: str, depth: int) -> set[str]:
    """Names of the crate-root modules the text imports or refers to.

    `crate::x` always names a crate-root module; a run of `super::` steps
    does when it climbs exactly `depth` levels. A brace group names every
    top-level item it lists.
    """
    names: set[str] = set()
    for match in CRATE_PATH.finditer(text):
        prefix, head = match.groups()
        if prefix != "crate" and (prefix.count("super") != depth):
            continue
        if head != "{":
            names.add(head)
            continue
        names.update(brace_heads(text, match.end() - 1))
    return names


def brace_heads(text: str, open_index: int) -> list[str]:
    """The leading identifier of each top-level item in the brace group."""
    heads: list[str] = []
    level = 0
    item = ""
    for char in text[open_index:]:
        if char == "{":
            level += 1
            if level == 1:
                continue
        elif char == "}":
            level -= 1
            if level == 0:
                break
        if level == 1 and char == ",":
            heads.append(item)
            item = ""
        else:
            item += char
    heads.append(item)
    found = []
    for entry in heads:
        head = re.match(r"\s*([A-Za-z_]\w*)", entry)
        if head:
            found.append(head.group(1))
    return found


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
        metadata = load_metadata(repository_root, args.metadata)
        failures = violations(metadata)
        failures.extend(job_feature_violations(metadata))
        failures.extend(module_violations(repository_root))
        failures.extend(govstack_protocol_violations(repository_root))
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
    print("the engine crate names no facade module or facade-only dependency;")
    print("fixed GovStack wire behavior stays in the facade host;")
    print("the job's off-by-default direct-BReg path reaches the connector,")
    print("the signed-event path reaches platform primitives only, the connector")
    print("reaches registry-breg-client alone; the scoped payment host reaches its")
    print("protocol, standalone provider and public BReg client. No Adapter crate links a")
    print("Coordinator crate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
