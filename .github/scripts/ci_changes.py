#!/usr/bin/env python3
"""Classify CI changes and build disk-bounded Rust test shards."""

from __future__ import annotations

import argparse
import fnmatch
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable


SHARDS = {
    "discovery": (
        "registry-discovery",
        "registry-discovery-client",
        "registry-discovery-client-node",
        "registry-discovery-client-py",
        "registry-discovery-profile",
        "registry-discoveryctl",
    ),
    "platform": (
        "registry-platform-audit",
        "registry-platform-authcommon",
        "registry-platform-buildinfo",
        "registry-platform-canonical-json",
        "registry-platform-config",
        "registry-platform-crypto",
        "registry-platform-httpsec",
        "registry-platform-httputil",
        "registry-platform-oidc",
        "registry-platform-sdjwt",
        "registry-platform-sqlite",
        "registry-platform-testing",
    ),
    "manifest": (
        "registry-manifest-cli",
        "registry-manifest-core",
    ),
    "relay-client": (
        "registry-relay-http-contract",
        "registry-relay-client",
        "registry-relay-client-node",
        "registry-relay-client-py",
    ),
    "relay-v2": ("registry-relay-v2", "registry-relayctl"),
    "breg": (
        "registry-breg",
        "registry-breg-client",
        "registry-breg-client-node",
        "registry-breg-client-py",
        "registry-bregctl",
    ),
    "stack-client": ("registry-record", "registry-stack-client"),
    "evidence": (
        "registry-evidence",
        "registry-evidence-authoring",
        "registry-evidence-client",
        "registry-evidence-client-node",
        "registry-evidence-client-py",
        "registry-evidence-oid4vci",
        "registry-evidence-verifier",
        "registry-evidencectl",
    ),
    "mint": ("registry-mint",),
    "developer-tools": (
        "registry-cli-docs",
        "registry-language-server",
    ),
}

EVIDENCE_PACKAGES = frozenset(SHARDS["evidence"])
DISCOVERY_PACKAGES = frozenset(SHARDS["discovery"])
PLATFORM_PACKAGES = frozenset(SHARDS["platform"])
MANIFEST_PACKAGES = frozenset(SHARDS["manifest"])
RELAY_V2_PACKAGES = frozenset(SHARDS["relay-v2"])
RELAY_CLIENT_PACKAGES = frozenset(SHARDS["relay-client"])
BREG_PACKAGES = frozenset(SHARDS["breg"])
STACK_CLIENT_PACKAGES = frozenset(SHARDS["stack-client"])

# These are the cross-product semantic commitments implemented independently by
# Base Registry Engine and Relay V2. A change must replay both real product routers,
# while profile-only tooling and ordinary positive/negative fixtures remain on
# the identifier/profile gate without widening the Rust matrix.
REGISTRY_RECORD_CROSS_PRODUCT_INPUTS = (
    "products/registry-record/schema/**",
    "products/registry-record/context/**",
    "products/registry-record/profile/**",
    "products/registry-record/fixtures/cross-product/**",
)

# Provider publication is part of the Discovery product contract even though
# Evidence and Relay own its generation and serving code. Keep this explicit:
# a publisher-only change must run the cross-product profile and journey gates
# without relying on an incidental reverse dev-dependency.
DISCOVERY_PROVIDER_IMPLEMENTATION_INPUTS = (
    "crates/registry-evidence/src/bundle.rs",
    "crates/registry-evidence/src/cli.rs",
    "crates/registry-evidence/src/config.rs",
    "crates/registry-evidence/src/contracts.rs",
    "crates/registry-evidence/src/discovery.rs",
    "crates/registry-evidence/src/main.rs",
    "crates/registry-evidence/src/runtime_tests.rs",
    "crates/registry-evidence/src/server.rs",
    "crates/registry-evidencectl/src/authoring.rs",
    "crates/registry-evidencectl/src/build.rs",
    "crates/registry-evidencectl/src/fixtures.rs",
    "crates/registry-evidencectl/tests/production_build.rs",
    "crates/registry-relay-http-contract/src/lib.rs",
    "crates/registry-relay-v2/src/api.rs",
    "crates/registry-relay-v2/src/artifacts.rs",
    "crates/registry-relay-v2/src/compiler.rs",
    "crates/registry-relay-v2/src/contract.rs",
    "crates/registry-relay-v2/src/model.rs",
    "crates/registry-relay-v2/src/package.rs",
    "crates/registry-relay-v2/src/server.rs",
    "crates/registry-relay-v2/src/tooling.rs",
    "crates/registry-relay-v2/tests/acceptance_http.rs",
)
DISCOVERY_PROVIDER_INPUTS = DISCOVERY_PROVIDER_IMPLEMENTATION_INPUTS + (
    "products/evidence/contracts/bundle.schema.yaml",
    "products/evidence/fixtures/acceptance/*/catalog.jsonld",
    "products/evidence/fixtures/acceptance/*/evidence.yaml",
    "products/evidence/generated/registry-evidence.openapi.json",
    "products/relay-v2/acceptance/*/expected-http.yaml",
    "products/relay-v2/acceptance/*/registry.yaml",
    "products/relay-v2/contracts/acceptance-scenario-matrix.yaml",
    "products/relay-v2/contracts/artifact-inventory.yaml",
    "products/relay-v2/contracts/generated-baselines.yaml",
)

# The full reader journey is a Discovery product gate, not only a docs lint.
# A tutorial-only edit must replay the same provider, operator, consumer, and
# native-client handoff that the page promises.
DISCOVERY_TUTORIAL_INPUTS = (
    "docs/site/scripts/check-discovery-tutorial.sh",
    "docs/site/scripts/check-discovery-tutorial.test.mjs",
    "docs/site/src/content/docs/tutorials/publish-and-consume-discovery-index.mdx",
)

# Every input the Evidence tutorial gate replays or is built from. The tutorial
# pages and helper scripts here must stay in step with the gate's own registry
# and the helpers it invokes, which test_ci_changes.py enforces: a tutorial or
# helper CI does not watch is one that rots silently.
EVIDENCE_TUTORIAL_INPUTS = frozenset(
    {
        "Cargo.lock",
        "Cargo.toml",
        "docs/site/package-lock.json",
        "docs/site/package.json",
        "docs/site/scripts/check-evidence-tutorials.sh",
        "docs/site/scripts/check-evidence-tutorials.test.mjs",
        "docs/site/scripts/evidence-tutorial-fence.sh",
        "docs/site/scripts/fixtures/fhir-tutorial-mock.py",
        "docs/site/src/content/docs/tutorials/assert-a-role-bound-relationship.mdx",
        "docs/site/src/content/docs/tutorials/connect-a-sqlite-extract.mdx",
        "docs/site/src/content/docs/tutorials/control-who-can-request-evidence.mdx",
        "docs/site/src/content/docs/tutorials/first-evidence-assertion.mdx",
        "docs/site/src/content/docs/tutorials/issue-fhir-evidence-as-vcs.mdx",
        "docs/site/src/content/docs/tutorials/refuse-unsafe-evidence-requests.mdx",
        "docs/site/src/content/docs/tutorials/request-evidence-as-sd-jwt-vc.mdx",
        "docs/site/src/content/docs/tutorials/request-evidence-from-an-application.mdx",
        "docs/site/src/content/docs/tutorials/run-oid4vci-interoperability-checks.mdx",
        "docs/site/src/content/docs/tutorials/return-a-governed-value.mdx",
        "docs/site/src/content/docs/tutorials/verify-an-assertion-as-a-consumer.mdx",
        "products/evidence/fixtures/interoperability/inji-oid4vci/profile.json",
        "products/evidence/fixtures/interoperability/inji-oid4vci/receipt.json",
        "products/evidence/scripts/compat/inji-oid4vci-upstream.sh",
        "products/evidence/scripts/compat/inji-oid4vci.sh",
        # The application tutorial imports the maintained client package, and
        # the job assembles that package from this commit with these scripts
        # and this pinned build tool. A change to any of them changes what the
        # replay imports.
        "release/requirements/maturin-1.9.6.txt",
        "release/scripts/assemble-registry-client-packages.py",
        "release/scripts/assemble-registry-client-wheel.py",
    }
)

# Every input the Base Registry Engine tutorial gate replays or is built from.
# The gate starts the quickstart launcher the page tells a reader to run, so
# the launcher and the Registry Mint key helper it reaches are inputs to the
# replay exactly as the page is: a change to either changes what a reader gets.
BREG_TUTORIAL_INPUTS = (
    "Cargo.lock",
    "Cargo.toml",
    "crates/registry-mint/demo/support/key_material.py",
    "docs/site/package-lock.json",
    "docs/site/package.json",
    "docs/site/scripts/check-breg-tutorial.sh",
    "docs/site/scripts/check-breg-tutorial.test.mjs",
    "docs/site/src/content/docs/tutorials/first-breg.mdx",
    "products/breg/quickstart/**",
)

# This guide explains the authoring form across three intentionally separate
# enforcement layers: the shared form model, the evidencectl compiler, and the
# frozen bundle validator. Keep the routing list at module ownership rather
# than duplicating its fields and rules in another semantic manifest. The
# sample gives the focused CI test one existing path for each route.
EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_INPUTS = (
    (
        "crates/registry-evidence-authoring/src/**",
        "crates/registry-evidence-authoring/src/model.rs",
    ),
    (
        "crates/registry-evidencectl/src/**",
        "crates/registry-evidencectl/src/authoring.rs",
    ),
    (
        "crates/registry-evidence/src/bundle.rs",
        "crates/registry-evidence/src/bundle.rs",
    ),
    (
        "crates/registry-evidence/src/config.rs",
        "crates/registry-evidence/src/config.rs",
    ),
    (
        "crates/registry-platform-crypto/src/lib.rs",
        "crates/registry-platform-crypto/src/lib.rs",
    ),
)
EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_PATTERNS = tuple(
    pattern for pattern, _ in EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_INPUTS
)

# Generated CLI pages consume the supported public Clap trees.
# Keep this list at module ownership so changing an Args
# type beside a top-level parser cannot leave its published page stale.
CLI_REFERENCE_INPUTS = (
    ("Cargo.lock", "Cargo.lock"),
    ("Cargo.toml", "Cargo.toml"),
    ("crates/registry-cli-docs/src/**", "crates/registry-cli-docs/src/lib.rs"),
    ("crates/registry-evidence/src/cli.rs", "crates/registry-evidence/src/cli.rs"),
    (
        "crates/registry-evidence-oid4vci/src/cli.rs",
        "crates/registry-evidence-oid4vci/src/cli.rs",
    ),
    ("crates/registry-evidencectl/src/**", "crates/registry-evidencectl/src/lib.rs"),
    ("crates/registry-mint/src/cli.rs", "crates/registry-mint/src/cli.rs"),
    ("crates/registry-relay-v2/src/cli.rs", "crates/registry-relay-v2/src/cli.rs"),
    ("crates/registry-relayctl/src/**", "crates/registry-relayctl/src/lib.rs"),
    ("crates/registry-breg/src/cli.rs", "crates/registry-breg/src/cli.rs"),
    ("crates/registry-bregctl/src/**", "crates/registry-bregctl/src/lib.rs"),
)
CLI_REFERENCE_PATTERNS = tuple(pattern for pattern, _ in CLI_REFERENCE_INPUTS)

# Each binding stays in its owning product shard. Every binding also selects
# the shared native-client job, whose npm, generated-type, and Python unittest
# suites are the only cover its full language API receives.
EVIDENCE_BINDING_PACKAGES = frozenset(
    {"registry-evidence-client-node", "registry-evidence-client-py"}
)
RELAY_BINDING_PACKAGES = frozenset(
    {"registry-relay-client-node", "registry-relay-client-py"}
)
DISCOVERY_BINDING_PACKAGES = frozenset(
    {"registry-discovery-client-node", "registry-discovery-client-py"}
)
BREG_BINDING_PACKAGES = frozenset(
    {"registry-breg-client-node", "registry-breg-client-py"}
)
NATIVE_BINDING_PACKAGES = (
    DISCOVERY_BINDING_PACKAGES
    | EVIDENCE_BINDING_PACKAGES
    | RELAY_BINDING_PACKAGES
    | BREG_BINDING_PACKAGES
)
LINUX_NODE_BINDING_PACKAGES = frozenset(
    {
        "registry-discovery-client-node",
        "registry-evidence-client-node",
        "registry-relay-client-node",
        "registry-breg-client-node",
    }
)

# Inputs that can change the production Linux Node client recipe without
# changing either binding crate. This proof is deliberately selected from the
# actual changed paths rather than `complete`: push and merge-queue CI use
# `--all` for their Rust matrices, and an unrelated change must not rebuild all
# release addons merely because those matrices are complete.
LINUX_NODE_RELEASE_RECIPE_INPUTS = frozenset(
    {
        ".github/scripts/ci_changes.py",
        ".github/workflows/ci.yml",
        ".github/workflows/release-candidate.yml",
        ".github/workflows/release-rehearsal.yml",
        "Cargo.lock",
        "Cargo.toml",
        "release/requirements/maturin-1.9.6.txt",
        "release/scripts/build-linux-node-client",
        "release/scripts/smoke-discovery-client-package.js",
        "release/scripts/smoke-evidence-client-package.js",
        "release/scripts/smoke-relay-client-package.js",
        "release/scripts/smoke-registry-client-package.js",
        "release/scripts/assemble-registry-client-wheel.py",
        "release/scripts/sync-registry-client-node.py",
        "release/scripts/test_build_linux_node_client.py",
        "release/scripts/test_zig_glibc_compiler.py",
        "release/scripts/zig-glibc-compiler",
        "rust-toolchain",
        "rust-toolchain.toml",
    }
)

# A package is exempt from the tutorial trigger only while no tutorial runs it.
# The Python binding is what `request-evidence-from-an-application` imports, so
# a change to it has to replay that tutorial and is not listed here. Move a
# package out of this set as soon as a registered tutorial exercises it, or its
# regressions reach readers before they reach CI. The registered OID4VCI
# interoperability tutorial builds the adapter and executes its sanitized
# wallet-flow test, so the adapter is deliberately not exempt.
EVIDENCE_TUTORIAL_EXEMPT_PACKAGES = frozenset({"registry-evidence-client-node"})

# The gate also builds and runs `mint`, because one tutorial serves assertions
# to a caller holding a real Mint-issued token.
EVIDENCE_TUTORIAL_PACKAGES = (
    EVIDENCE_PACKAGES - EVIDENCE_TUTORIAL_EXEMPT_PACKAGES
) | frozenset(SHARDS["mint"])

# The application tutorial imports the assembled `registry-stack-client`
# wheel, which the gate builds from every product's Python binding, so a
# change to any of them changes what the replay imports, whichever product it
# belongs to. The pure-Python facade the wheel also carries owns no Cargo
# package, so a change under it already selects the complete matrix.
ASSEMBLED_PYTHON_CLIENT_PACKAGES = frozenset(
    package for package in NATIVE_BINDING_PACKAGES if package.endswith("-client-py")
)

# The gate builds and runs exactly these: the registry, the tool that applies
# its package, and Registry Mint, because the launcher the tutorial starts
# issues the operator token the reader's first authenticated call carries. The
# clients in the Base Registry Engine shard are not on the replayed path.
BREG_TUTORIAL_PACKAGES = frozenset({"registry-breg", "registry-bregctl"}) | frozenset(
    SHARDS["mint"]
)

ROOT_RUST_INPUTS = {
    "Cargo.lock",
    "Cargo.toml",
    "clippy.toml",
    "deny.toml",
    "rust-toolchain",
    "rust-toolchain.toml",
    "rustfmt.toml",
}

# Every workflow whose security properties are inspected by the release gate
# inventory selects the additional local gates that own those properties. All
# root workflows select release_tool below, including workflows not yet in this
# table, so a new privileged workflow cannot silently bypass the policy gate.
SECURITY_WORKFLOW_GATES: dict[str, frozenset[str]] = {
    ".github/workflows/codeql.yml": frozenset({"release_tool"}),
    ".github/workflows/docs-pages.yml": frozenset(
        {"docs", "release_source_proof", "release_tool"}
    ),
    ".github/workflows/evidence-dev.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/nightly-security.yml": frozenset(
        {"platform", "release_tool"}
    ),
    ".github/workflows/nightly-rust-coverage.yml": frozenset(
        {"platform", "release_tool"}
    ),
    ".github/workflows/release.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-candidate.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-canary.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-repeatability.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-candidate-cleanup.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/release-rehearsal.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/scorecard.yml": frozenset({"release_tool"}),
}
REPO_ROOT = Path(__file__).resolve().parents[2]
IDENTIFIER_CATALOG_CONTRACT = (
    REPO_ROOT / "products/identifiers/contracts/catalog-source.json"
)


def identifier_catalog_inputs(
    contract_path: Path = IDENTIFIER_CATALOG_CONTRACT,
) -> tuple[str, ...]:
    """Derive every source path that can change the public identifier catalog."""

    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    problem_sources = contract.get("problemSources")
    schema_groups = contract.get("schemaSources")
    records = contract.get("records")
    if (
        not isinstance(problem_sources, list)
        or not isinstance(schema_groups, list)
        or not isinstance(records, list)
    ):
        raise ValueError(
            f"identifier catalog has an invalid source contract: {contract_path}"
        )

    inputs = [
        "products/identifiers/**",
        "products/registry-record/**",
        "crates/registry-relay-v2/examples/audit-event-schema.rs",
        "crates/registry-relay-v2/src/audit.rs",
    ]
    for index, source in enumerate(problem_sources):
        if not isinstance(source, dict):
            raise ValueError(f"identifier problemSources[{index}] is invalid")
        for field in ("sourcePath", "exporterPath"):
            path = source.get(field)
            if not isinstance(path, str) or not path:
                raise ValueError(
                    f"identifier problemSources[{index}] has no {field}"
                )
            inputs.append(path)
    for index, group in enumerate(schema_groups):
        pattern = group.get("glob") if isinstance(group, dict) else None
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"identifier schemaSources[{index}] has no glob")
        inputs.append(pattern)
        source = group.get("sourcePath")
        if source is not None:
            if not isinstance(source, str) or not source:
                raise ValueError(
                    f"identifier schemaSources[{index}] has an invalid sourcePath"
                )
            inputs.append(source)
    for index, record in enumerate(records):
        source = record.get("sourcePath") if isinstance(record, dict) else None
        if not isinstance(source, str) or not source:
            raise ValueError(f"identifier records[{index}] has no sourcePath")
        inputs.append(source)

    if any(source.startswith(("/", "../")) for source in inputs):
        raise ValueError("identifier catalog inputs must be repository-relative")
    return tuple(dict.fromkeys(inputs))


IDENTIFIER_CATALOG_INPUTS = identifier_catalog_inputs()


class Workspace:
    def __init__(self, metadata: dict[str, Any]) -> None:
        workspace_ids = set(metadata["workspace_members"])
        packages = {
            package["name"]: package
            for package in metadata["packages"]
            if package["id"] in workspace_ids
        }
        shard_packages = [package for members in SHARDS.values() for package in members]
        duplicates = sorted(
            package
            for package in set(shard_packages)
            if shard_packages.count(package) > 1
        )
        if duplicates:
            raise ValueError(f"packages assigned to multiple Rust shards: {duplicates}")

        missing = sorted(set(packages) - set(shard_packages))
        stale = sorted(set(shard_packages) - set(packages))
        if missing or stale:
            raise ValueError(
                "Rust shard inventory does not match the Cargo workspace: "
                f"missing={missing}, stale={stale}"
            )

        self.packages = packages
        self.package_names = frozenset(packages)
        self.roots: dict[str, str] = {}
        workspace_root = Path(metadata["workspace_root"]).resolve()
        for name, package in packages.items():
            manifest_path = Path(package["manifest_path"]).resolve()
            self.roots[name] = manifest_path.parent.relative_to(
                workspace_root
            ).as_posix()

        reverse_dependencies: dict[str, set[str]] = defaultdict(set)
        dev_reverse_dependencies: dict[str, set[str]] = defaultdict(set)
        for package_name, package in packages.items():
            for dependency in package["dependencies"]:
                dependency_name = dependency["name"]
                dependency_path = dependency.get("path")
                if (
                    dependency_name in packages
                    and dependency_path is not None
                    and Path(dependency_path).resolve()
                    == Path(packages[dependency_name]["manifest_path"]).resolve().parent
                ):
                    if dependency.get("kind") == "dev":
                        dev_reverse_dependencies[dependency_name].add(package_name)
                    else:
                        reverse_dependencies[dependency_name].add(package_name)
        self.reverse_dependencies = reverse_dependencies
        self.dev_reverse_dependencies = dev_reverse_dependencies

    def package_for_path(self, path: str) -> str | None:
        matches = [
            (root, package)
            for package, root in self.roots.items()
            if path == f"{root}/Cargo.toml" or path.startswith(f"{root}/")
        ]
        if not matches:
            return None
        return max(matches, key=lambda item: len(item[0]))[1]

    def affected_packages(self, seeds: Iterable[str]) -> set[str]:
        affected = set(seeds)
        propagating = set(seeds)
        queue = deque(propagating)
        while queue:
            dependency = queue.popleft()
            for dependent in self.reverse_dependencies.get(dependency, ()):
                if dependent not in propagating:
                    affected.add(dependent)
                    propagating.add(dependent)
                    queue.append(dependent)
            # A dev-dependency must schedule the immediate consumer's tests,
            # but it is not linked into that consumer's library. Do not let
            # this test-only edge fan out through the consumer's dependents.
            affected.update(self.dev_reverse_dependencies.get(dependency, ()))
        return affected


def matches(path: str, *patterns: str) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def is_root_workflow(path: str) -> bool:
    """Return whether path is an executable GitHub workflow at the root."""

    parts = path.split("/")
    return (
        len(parts) == 3
        and parts[:2] == [".github", "workflows"]
        and parts[2].endswith((".yml", ".yaml"))
    )


def classify(
    workspace: Workspace, changed_paths: Iterable[str], *, run_all: bool = False
) -> dict[str, Any]:
    paths = tuple(
        path.strip().removeprefix("./") for path in changed_paths if path.strip()
    )
    security_workflow_gates = frozenset(
        gate
        for path in paths
        for gate in SECURITY_WORKFLOW_GATES.get(path, ())
    )
    registry_record_cross_product = any(
        matches(path, *REGISTRY_RECORD_CROSS_PRODUCT_INPUTS) for path in paths
    )
    force_all = run_all or any(
        path
        in {
            ".github/workflows/ci.yml",
            ".github/scripts/ci_changes.py",
            ".github/scripts/run_cargo_packages.py",
        }
        or (is_root_workflow(path) and path not in SECURITY_WORKFLOW_GATES)
        or path.startswith(".cargo/")
        or path in ROOT_RUST_INPUTS
        for path in paths
    )

    seeds: set[str] = set()
    if not force_all:
        for path in paths:
            package = workspace.package_for_path(path)
            if package is not None:
                seeds.add(package)
                continue
            if path.startswith("products/evidence/"):
                seeds.update(EVIDENCE_PACKAGES)
            elif path.startswith("products/discovery/"):
                seeds.update(DISCOVERY_PACKAGES)
            elif path.startswith("products/manifest/"):
                seeds.update(MANIFEST_PACKAGES)
            elif path.startswith("products/platform/"):
                seeds.update(PLATFORM_PACKAGES)
            elif path.startswith("products/relay-v2/"):
                seeds.update(RELAY_V2_PACKAGES)
            elif path.startswith("products/breg/"):
                seeds.update(BREG_PACKAGES)
            elif path.startswith("products/identifiers/"):
                # The catalog gate compiles its focused Relay V2 exporter.
                # Catalog-only tooling does not require the full Rust matrix.
                pass
            elif path.startswith("products/registry-record/"):
                # Shared-profile material remains outside the broad Rust shard.
                # Cross-product commitments select the two owning product gates
                # explicitly below; each gate compiles and exercises its router.
                pass
            elif path.startswith(("crates/", "products/")):
                # A new or moved Rust package must not silently escape the test matrix.
                force_all = True

    affected = (
        set(workspace.package_names)
        if force_all
        else workspace.affected_packages(seeds)
    )
    complete = run_all or force_all

    # Compute this closure independently of the broad Rust selection above.
    # In particular, `run_all=True` must not manufacture a release recipe
    # trigger when no relevant path changed.
    linux_node_seeds = {
        package
        for path in paths
        if (package := workspace.package_for_path(path)) is not None
    }
    release_linux_node_clients = any(
        path in LINUX_NODE_RELEASE_RECIPE_INPUTS
        or path.startswith(".cargo/")
        or path.startswith("crates/registry-stack-client-node/")
        for path in paths
    ) or bool(
        workspace.affected_packages(linux_node_seeds)
        & LINUX_NODE_BINDING_PACKAGES
    )

    identifiers = complete or any(
        matches(path, *IDENTIFIER_CATALOG_INPUTS) for path in paths
    )

    platform = complete or "platform" in security_workflow_gates or any(
        matches(
            path,
            "crates/registry-platform-*",
            "products/platform/*",
        )
        or path in ROOT_RUST_INPUTS
        for path in paths
    )
    platform_hygiene = complete or any(
        matches(
            path,
            "products/platform/clippy.toml",
            "products/platform/deny.toml",
            "products/platform/rustfmt.toml",
            "products/platform/scripts/*",
            "products/platform/templates/*",
        )
        or path in {"clippy.toml", "deny.toml", "rustfmt.toml"}
        for path in paths
    )
    release_tool = (
        complete
        or "release_tool" in security_workflow_gates
        or any(is_root_workflow(path) for path in paths)
        or any(
            path.startswith("release/")
            or path
            in {
                "docs/site/src/content/docs/reference/errors.mdx",
            }
            for path in paths
        )
    )
    release_source_proof = (
        complete
        or "release_source_proof" in security_workflow_gates
        or any(
            path
            in {
                "Cargo.lock",
                "Cargo.toml",
                "release/scripts/check-release-source-model.sh",
                "release/scripts/test_check_release_source_model.py",
            }
            or path.startswith("release/manifests/")
            for path in paths
        )
    )
    docs = complete or "docs" in security_workflow_gates or any(
        matches(
            path,
            "docs/site/*",
            "products/manifest/docs/*",
            # The Evidence configuration reference page is generated from the
            # frozen contracts and from the authoring-form schemas beside
            # them, so either going stale needs a docs rebuild.
            "products/evidence/contracts/*",
            "crates/registry-evidencectl/schemas/authoring/*",
            "products/breg/generated/authoring/*",
            "products/breg/generated/runtime/*",
            # The same page names the product reference that explains each
            # schema, and the docs tests read those references to prove the
            # published key paths and the documented ones agree.
            "products/evidence/reference/*/CONFIG.md",
            # The published authoring guide states behavior enforced in these
            # modules, not only the generated question and marker schemas.
            *EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_PATTERNS,
            *CLI_REFERENCE_PATTERNS,
        )
        or path
        in {
            # The two Relay V2 product documents the site publishes through
            # repo-docs.yaml. Relay V2 generates no docs-site page from crate
            # source: relayctl compiles a project instead of exposing a schema
            # catalog, and each deployment generates its own OpenAPI
            # description.
            "products/relay-v2/CONCEPT.md",
            "products/relay-v2/STANDARDS-ALIGNMENT.md",
            # No page is generated from these files, but scripts/
            # ops-posture-spec.test.mjs reads them to prove the published
            # operational claims still match the runtime. A probe route, a
            # runtime bound, or a healthcheck default can change here and
            # leave RS-OP-POSTURE stale, and that test is the only thing that
            # catches it.
            "crates/registry-relay-v2/src/server.rs",
            "crates/registry-relay-v2/src/main.rs",
            "crates/registry-relay-v2/src/contract.rs",
            "crates/registry-relay-v2/src/startup.rs",
            "crates/registry-relay-http-contract/src/lib.rs",
        }
        for path in paths
    )
    # Rebuild immutable history only when archive inputs or assembly semantics
    # change. Publication workflows and this classifier do not alter archived
    # bytes; their focused tests cover those contracts without replaying every
    # historical docset.
    docs_archives = any(
        path
        in {
            ".github/workflows/ci.yml",
            "docs/site/astro.config.mjs",
            "docs/site/package-lock.json",
            "docs/site/package.json",
            "docs/site/scripts/apply-archive-seo.mjs",
            "docs/site/scripts/archive-bundle.mjs",
            "docs/site/scripts/archive-lock.mjs",
            "docs/site/scripts/assemble-archives.mjs",
            "docs/site/scripts/build-archive.mjs",
            "docs/site/scripts/build-archives.mjs",
            "docs/site/scripts/check-built-links.mjs",
            "docs/site/scripts/check-seo.mjs",
            "docs/site/scripts/docsets.mjs",
            "docs/site/src/data/archive-lock.yaml",
            "docs/site/src/data/docsets.yaml",
            "docs/site/src/data/repo-docs.yaml",
        }
        for path in paths
    )
    editors = (
        complete
        or any(path.startswith("editors/") for path in paths)
        or "registry-language-server" in affected
    )
    # Reverse dependents, not changed paths: bindings are Cargo path dependents
    # of each SDK, so an SDK or shared HTTP-contract change can move a native
    # surface without touching a binding crate.
    unified_client_changed = any(
        path.startswith("crates/registry-stack-client-node/")
        or path.startswith("crates/registry-stack-client-py/")
        for path in changed_paths
    )
    client_bindings = (
        complete
        or bool(affected & NATIVE_BINDING_PACKAGES)
        or unified_client_changed
    )

    evidence_tutorial = (
        complete
        or any(path in EVIDENCE_TUTORIAL_INPUTS for path in paths)
        or bool(
            affected & (EVIDENCE_TUTORIAL_PACKAGES | ASSEMBLED_PYTHON_CLIENT_PACKAGES)
        )
    )

    breg_tutorial = (
        complete
        or any(matches(path, *BREG_TUTORIAL_INPUTS) for path in paths)
        or bool(affected & BREG_TUTORIAL_PACKAGES)
    )

    matrix = []
    for shard_name, shard_packages in SHARDS.items():
        selected = sorted(affected.intersection(shard_packages))
        if selected:
            matrix.append(
                {
                    "name": shard_name,
                    "packages": selected,
                    "all_features": shard_name == "relay-v2",
                }
            )

    return {
        "rust": bool(affected),
        "rust_matrix": {"include": matrix},
        "rust_packages": sorted(affected),
        "platform": platform,
        "platform_hygiene": platform_hygiene,
        "discovery_contracts": complete
        or bool(affected & DISCOVERY_PACKAGES)
        or any(matches(path, *DISCOVERY_PROVIDER_INPUTS) for path in paths)
        or any(path in DISCOVERY_TUTORIAL_INPUTS for path in paths),
        "relay_v2_contracts": registry_record_cross_product
        or bool(affected & RELAY_V2_PACKAGES),
        "relay_client_contracts": bool(affected & RELAY_CLIENT_PACKAGES),
        "breg_contracts": registry_record_cross_product
        or bool(affected & BREG_PACKAGES),
        "evidence_contracts": bool(affected & EVIDENCE_PACKAGES),
        "release_tool": release_tool,
        "release_source_proof": release_source_proof,
        "docs": docs,
        "docs_archives": docs_archives,
        "editors": editors,
        "client_bindings": client_bindings,
        "release_linux_node_clients": release_linux_node_clients,
        "evidence_tutorial": evidence_tutorial,
        "breg_tutorial": breg_tutorial,
        "identifiers": identifiers,
    }


def write_github_outputs(path: Path, outputs: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in outputs.items():
            if isinstance(value, bool):
                rendered = str(value).lower()
            elif isinstance(value, (dict, list)):
                rendered = json.dumps(value, separators=(",", ":"), sort_keys=True)
            else:
                rendered = str(value)
            output.write(f"{key}={rendered}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--all", action="store_true", dest="run_all")
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()

    if not args.run_all and args.changed_files is None:
        parser.error("--changed-files is required unless --all is set")

    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    changed_paths = (
        args.changed_files.read_text(encoding="utf-8").splitlines()
        if args.changed_files is not None
        else ()
    )
    outputs = classify(Workspace(metadata), changed_paths, run_all=args.run_all)
    write_github_outputs(args.github_output, outputs)
    print(json.dumps(outputs, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
