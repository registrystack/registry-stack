#!/usr/bin/env python3
"""Classify CI changes and build disk-bounded Rust test shards."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass
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
        "registry-platform-activation",
        "registry-platform-audit",
        "registry-platform-authcommon",
        "registry-platform-buildinfo",
        "registry-platform-calendar",
        "registry-platform-canonical-json",
        "registry-platform-config",
        "registry-platform-crypto",
        "registry-platform-dispatch",
        "registry-platform-hooks",
        "registry-platform-httpsec",
        "registry-platform-httputil",
        "registry-platform-oidc",
        "registry-platform-ratelimit",
        "registry-platform-script",
        "registry-platform-sdjwt",
        "registry-platform-sqlite",
        "registry-platform-testing",
        "registry-platform-yaml",
    ),
    "manifest": (
        "registry-manifest-cli",
        "registry-manifest-core",
    ),
    "breg": (
        "registry-breg",
        "registry-breg-client",
        "registry-breg-client-node",
        "registry-breg-client-py",
        "registry-breg-mcp",
        "registry-breg-review",
        "registry-bregctl",
        "registry-linkml",
    ),
    "casework": (
        "registry-review-protocol",
        "registry-review-client",
        "registry-casework-core",
        "registry-casework-breg",
        "registry-casework",
        "registry-caseworkctl",
        "registry-casework-client",
        "registry-casework-client-node",
        "registry-casework-client-py",
    ),
    "scheduling": (
        "registry-scheduling-core",
        "registry-scheduling",
        "registry-schedulingctl",
        "registry-scheduling-client",
        "registry-scheduling-client-node",
        "registry-scheduling-client-py",
    ),
    "messaging": (
        "registry-messaging-core",
        "registry-messaging",
        "registry-messagingctl",
        "registry-messaging-client",
        "registry-messaging-client-node",
        "registry-messaging-client-py",
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
    "developer-tools": (
        "registry-thunderid-tooling",
        "registry-cli-docs",
        "registry-cli-reference",
        "registry-language-server",
    ),
    "render": ("registry-render",),
}

EVIDENCE_PACKAGES = frozenset(SHARDS["evidence"])
DISCOVERY_PACKAGES = frozenset(SHARDS["discovery"])
PLATFORM_PACKAGES = frozenset(SHARDS["platform"])
MANIFEST_PACKAGES = frozenset(SHARDS["manifest"])
BREG_PACKAGES = frozenset(SHARDS["breg"])
CASEWORK_PACKAGES = frozenset(SHARDS["casework"])
SCHEDULING_PACKAGES = frozenset(SHARDS["scheduling"])
MESSAGING_PACKAGES = frozenset(SHARDS["messaging"])
STACK_CLIENT_PACKAGES = frozenset(SHARDS["stack-client"])

# The runtime configuration conformance gate reads the sources of the runtimes
# it holds rows for, their generated runtime schemas, and the canonical shared
# configuration blocks schema. A product that joins the gate joins this set.
CONFIG_CONFORMANCE_PACKAGES = frozenset(
    {
        "registry-platform-config",
        "registry-breg",
        "registry-breg-mcp",
        "registry-breg-review",
        "registry-casework",
        "registry-discovery",
        "registry-evidence",
        "registry-render",
        "registry-scheduling",
        "registry-messaging",
    }
)
# The configuration conformance corpus runs the registered `check` command of
# each format it reaches from the built binaries of these packages, which the
# job builds; a change to one, or to anything it links, runs the corpus.
CONFIG_CHECK_PACKAGES = frozenset(
    {
        "registry-bregctl",
        "registry-caseworkctl",
        "registry-discoveryctl",
        "registry-evidence",
        "registry-evidencectl",
        "registry-manifest-cli",
        "registry-messagingctl",
        "registry-render",
        "registry-schedulingctl",
    }
)
CONFIG_CONFORMANCE_INPUTS = (
    "products/platform/generated/*",
    "products/platform/scripts/*config-conformance*",
    "products/platform/scripts/*config_conformance*",
    "products/platform/conformance/*",
    "products/breg/generated/runtime/*",
    "products/casework/generated/runtime/*",
    "products/scheduling/generated/runtime/*",
    "products/messaging/generated/runtime/*",
)

# The configuration conventions lint runs in the same job. Beyond the files
# below it reads every file and reader crate config-formats.yaml names (see
# config_format_inputs), and it refuses a schema under these globs that
# nobody registered, so a new one has to reach it.
CONFIG_CONVENTIONS_INPUTS = (
    "products/platform/config-formats.yaml",
    "products/platform/config-conventions-exceptions.yaml",
    "products/platform/CONFIG-CONVENTIONS.md",
    "products/platform/scripts/*config-conventions*",
    "editors/configure.py",
    "products/*/generated/*.schema.json",
    "products/*/contracts/*.schema.json",
    "products/*/contracts/*.schema.yaml",
    "products/*/schemas/*.schema.json",
    "products/*/profile/schema/*.schema.json",
    "crates/*/schemas/*.schema.json",
)

# These are Registry Record commitments implemented by Base Registry Engine.
REGISTRY_RECORD_CROSS_PRODUCT_INPUTS = (
    "products/registry-record/schema/**",
    "products/registry-record/context/**",
    "products/registry-record/profile/**",
    "products/registry-record/fixtures/cross-product/**",
)

# Provider publication is part of the Discovery product contract even though
# Evidence owns its generation and serving code. Keep this explicit:
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
)
DISCOVERY_PROVIDER_INPUTS = DISCOVERY_PROVIDER_IMPLEMENTATION_INPUTS + (
    "products/evidence/contracts/bundle.schema.yaml",
    "products/evidence/fixtures/acceptance/*/catalog.jsonld",
    "products/evidence/fixtures/acceptance/*/evidence.yaml",
    "products/evidence/generated/registry-evidence.openapi.json",
)

# The full reader journey is a Discovery product gate, not only a docs lint.
# Every input the Discovery tutorial gate replays: the page runner and the page
# whose frontmatter it replays. The fixtures and helpers the page reads live
# under products/discovery/, whose paths already seed the Discovery packages.
DISCOVERY_TUTORIAL_INPUTS = (
    "docs/site/package-lock.json",
    "docs/site/package.json",
    "docs/site/scripts/run-tutorial.mjs",
    "docs/site/scripts/tutorial-runner/**",
    "docs/site/src/content/docs/tutorials/publish-and-consume-discovery-index.mdx",
)

# Every input the Evidence tutorial gate replays or is built from: the page
# runner, the pages whose frontmatter it replays, the source mock the toolset
# starts, and the build inputs of what the pages run. The replayed pages here
# must stay in step with their tutorial_test frontmatter, which
# test_ci_changes.py enforces: a tutorial CI does not watch is one that rots
# silently.
EVIDENCE_TUTORIAL_INPUTS = (
    "Cargo.lock",
    "Cargo.toml",
    "docs/site/package-lock.json",
    "docs/site/package.json",
    "docs/site/scripts/run-tutorial.mjs",
    "docs/site/scripts/tutorial-runner/**",
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
    "release/scripts/build-linux-python-client",
    "release/scripts/zig-glibc-compiler",
    "release/scripts/smoke-registry-client-package.py",
)

# Every input the Base Registry Engine tutorial gate replays or is built from:
# the page runner, the pages whose frontmatter it replays, and the build inputs
# of the binaries it runs. The same job runs the request-attachments acceptance
# check.
BREG_TUTORIAL_INPUTS = (
    "Cargo.lock",
    "Cargo.toml",
    "docs/site/package-lock.json",
    "docs/site/package.json",
    "docs/site/scripts/run-tutorial.mjs",
    "docs/site/scripts/tutorial-runner/**",
    "docs/site/src/content/docs/tutorials/derive-a-registry-from-publicschema.mdx",
    "docs/site/src/content/docs/tutorials/extend-a-registry-with-a-module.mdx",
    "docs/site/src/content/docs/tutorials/first-breg.mdx",
    "docs/site/src/content/docs/tutorials/review-registry-changes.mdx",
    "products/breg/acceptance/request-attachments/**",
    "products/breg/scripts/test-request-attachments.py",
)

# Every input the Registry Casework tutorial gate replays or is built from: the
# page runner, the pages whose frontmatter it replays, and the build inputs of
# the binaries it runs. The gate starts the all-in-one local runtime the page
# tells a reader to run, and that runtime starts stock ThunderID from the
# project's own client declarations, so the page and the runner are inputs to
# the replay exactly as the toolset is.
# The project template the page initializes is written by registry-caseworkctl,
# so package routing already carries it.
CASEWORK_TUTORIAL_INPUTS = (
    "Cargo.lock",
    "Cargo.toml",
    "docs/site/package-lock.json",
    "docs/site/package.json",
    "docs/site/scripts/run-tutorial.mjs",
    "docs/site/scripts/tutorial-runner/**",
    "docs/site/src/content/docs/tutorials/first-casework.mdx",
)

# Every input the Registry Messaging tutorial gate replays or is built from.
# The gate starts the local session the page tells a reader to run; that
# session and the starter project the page initializes are both written by
# registry-messagingctl, so package routing already carries them.
MESSAGING_TUTORIAL_INPUTS = (
    "Cargo.lock",
    "Cargo.toml",
    "docs/site/package-lock.json",
    "docs/site/package.json",
    "docs/site/scripts/check-messaging-tutorial.sh",
    "docs/site/scripts/check-messaging-tutorial.test.mjs",
    "docs/site/src/content/docs/tutorials/first-messaging.mdx",
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
    ("crates/registry-cli-docs/**", "crates/registry-cli-docs/src/lib.rs"),
    # Feature/dependency changes can alter the collector without editing Clap.
    ("crates/*/Cargo.toml", "crates/registry-cli-docs/Cargo.toml"),
    ("crates/registry-evidence/src/cli.rs", "crates/registry-evidence/src/cli.rs"),
    (
        "crates/registry-evidence-oid4vci/src/cli.rs",
        "crates/registry-evidence-oid4vci/src/cli.rs",
    ),
    ("crates/registry-evidencectl/src/**", "crates/registry-evidencectl/src/lib.rs"),
    ("crates/registry-breg/src/cli.rs", "crates/registry-breg/src/cli.rs"),
    ("crates/registry-breg-mcp/src/cli.rs", "crates/registry-breg-mcp/src/cli.rs"),
    (
        "crates/registry-breg-review/src/lib.rs",
        "crates/registry-breg-review/src/lib.rs",
    ),
    ("crates/registry-bregctl/src/**", "crates/registry-bregctl/src/lib.rs"),
    (
        "crates/registry-casework/src/runtime.rs",
        "crates/registry-casework/src/runtime.rs",
    ),
    ("crates/registry-caseworkctl/src/**", "crates/registry-caseworkctl/src/lib.rs"),
    (
        "crates/registry-messaging/src/runtime.rs",
        "crates/registry-messaging/src/runtime.rs",
    ),
    ("crates/registry-messagingctl/src/**", "crates/registry-messagingctl/src/lib.rs"),
)
CLI_REFERENCE_PATTERNS = tuple(pattern for pattern, _ in CLI_REFERENCE_INPUTS)

# Each binding stays in its owning product shard. Every binding also selects
# the shared native-client job, whose npm, generated-type, and Python unittest
# suites are the only cover its full language API receives.
EVIDENCE_BINDING_PACKAGES = frozenset(
    {"registry-evidence-client-node", "registry-evidence-client-py"}
)
DISCOVERY_BINDING_PACKAGES = frozenset(
    {"registry-discovery-client-node", "registry-discovery-client-py"}
)
BREG_BINDING_PACKAGES = frozenset(
    {"registry-breg-client-node", "registry-breg-client-py"}
)
CASEWORK_BINDING_PACKAGES = frozenset(
    {"registry-casework-client-node", "registry-casework-client-py"}
)
MESSAGING_BINDING_PACKAGES = frozenset(
    {"registry-messaging-client-node", "registry-messaging-client-py"}
)
SCHEDULING_BINDING_PACKAGES = frozenset(
    {"registry-scheduling-client-node", "registry-scheduling-client-py"}
)
NATIVE_BINDING_PACKAGES = (
    DISCOVERY_BINDING_PACKAGES
    | EVIDENCE_BINDING_PACKAGES
    | BREG_BINDING_PACKAGES
    | CASEWORK_BINDING_PACKAGES
    | MESSAGING_BINDING_PACKAGES
    | SCHEDULING_BINDING_PACKAGES
)

# The breg-contracts matrix lanes. Review runs the first; the merge queue, the
# nightly sweep and a `ci:full` pull request run every lane.
BREG_CONTRACTS_LANES = ("contracts", "postgres", "immediate-actions")

# A package is exempt from the tutorial trigger only while no tutorial runs it.
# The Python binding is what `request-evidence-from-an-application` imports, so
# a change to it has to replay that tutorial and is not listed here. Move a
# package out of this set as soon as a registered tutorial exercises it, or its
# regressions reach readers before they reach CI. The registered OID4VCI
# interoperability tutorial builds the adapter and executes its sanitized
# wallet-flow test, so the adapter is deliberately not exempt.
EVIDENCE_TUTORIAL_EXEMPT_PACKAGES = frozenset({"registry-evidence-client-node"})

# The tutorial uses the maintained stock issuer lifecycle for bearer tokens.
EVIDENCE_TUTORIAL_PACKAGES = (
    EVIDENCE_PACKAGES - EVIDENCE_TUTORIAL_EXEMPT_PACKAGES
) | frozenset({"registry-thunderid-tooling"})

# The application tutorial imports the assembled `registry-stack-client`
# wheel, which the gate builds from every product's Python binding, so a
# change to any of them changes what the replay imports, whichever product it
# belongs to. The pure-Python facade the wheel also carries owns no Cargo
# package, so a change under it already selects the complete matrix.
ASSEMBLED_PYTHON_CLIENT_PACKAGES = frozenset(
    package for package in NATIVE_BINDING_PACKAGES if package.endswith("-client-py")
)

# The gate builds and runs exactly these: the registry, the tool that applies
# its package, and issuer tooling, because the `bregctl dev` session the
# tutorial starts issues the operator token the reader's first authenticated call carries. The
# clients in the Base Registry Engine shard are not on the replayed path.
BREG_TUTORIAL_PACKAGES = frozenset(
    {"registry-breg", "registry-bregctl", "registry-thunderid-tooling"}
)

# The gate builds and runs exactly these: the Casework runtime, the tool that
# starts and seeds the local session, and issuer tooling, because every call the
# reader makes carries a token that session issued. The clients in the Casework
# shard are not on the replayed path.
CASEWORK_TUTORIAL_PACKAGES = frozenset(
    {"registry-casework", "registry-caseworkctl", "registry-breg", "registry-bregctl", "registry-thunderid-tooling"}
)

# The gate builds and runs exactly messagingctl, which links the Messaging
# runtime in process for its local session and issues every token the reader's
# calls carry. The client crates in the Messaging shard are not on the
# replayed path.
MESSAGING_TUTORIAL_PACKAGES = frozenset({"registry-messaging", "registry-messagingctl"})

# The offline proof of the native BReg to Evidence composition drives bregctl,
# evidencectl and the Evidence runtime over the reviewed teaching inputs. It
# starts no container, so it is selected on its own rather than through the
# Docker-backed tutorial replay. Reverse-dependency routing carries the shared
# authoring and runtime crates those three binaries link.
BREG_EVIDENCE_COMPOSITION_PACKAGES = frozenset(
    {
        "registry-breg",
        "registry-bregctl",
        "registry-evidence",
        "registry-evidencectl",
    }
)

# The reviewed registry, starter project and test driver the proof reads.
BREG_EVIDENCE_COMPOSITION_INPUTS = ("products/breg/evidence/**",)

ROOT_RUST_INPUTS = {
    "Cargo.lock",
    "Cargo.toml",
    "clippy.toml",
    "deny.toml",
    "rust-toolchain",
    "rust-toolchain.toml",
    "rustfmt.toml",
    "scripts/cargo-runtime-library-path.sh",
    "scripts/cargo_runtime_library_path.py",
}

# A Cargo.lock-only change is routed through the workspace members that reach
# a changed locked package, except when that package can change native code.
# Cargo.lock does not record `links`, so every `-sys` package counts by name,
# every locked package that depends on a C build helper counts by that edge,
# and this list names the rest: each locked package declaring `links` without
# a `-sys` suffix, and the helpers themselves. Refresh it from
# `cargo metadata --format-version 1 --locked | jq -r '.packages[] | select(.links) | .name'`
# when the lock gains a native package: an unlisted one is routed like pure
# Rust.
LOCK_NATIVE_BUILD_HELPERS = frozenset(
    {
        "bindgen",
        "cc",
        "cmake",
        "napi-build",
        "pkg-config",
        "pyo3-build-config",
        "vcpkg",
    }
)
LOCK_NATIVE_PACKAGES = LOCK_NATIVE_BUILD_HELPERS | frozenset(
    {
        "aws-lc-rs",
        "dunce",
        "fs_extra",
        "prettyplease",
        "pyo3",
        "pyo3-ffi",
        "rayon-core",
        "ring",
        "tree-sitter",
        "tree-sitter-language",
        "wasm-bindgen-shared",
    }
)

# Everything the archive-specific commands of `check:archives` and
# `check:archive-lock` read after the current-site build the docs job proves:
# the site build configuration, the archive scripts and their import closure,
# the locked archive inventory, and the page-markdown source check-llms reads.
DOCS_ARCHIVE_INPUTS = frozenset(
    {
        "docs/site/astro.config.mjs",
        "docs/site/package-lock.json",
        "docs/site/package.json",
        "docs/site/scripts/apply-archive-seo.mjs",
        "docs/site/scripts/archive-bundle.mjs",
        "docs/site/scripts/archive-lock.mjs",
        "docs/site/scripts/assemble-archives.mjs",
        "docs/site/scripts/build-archive.mjs",
        "docs/site/scripts/build-archives.mjs",
        "docs/site/scripts/check-built-analytics.mjs",
        "docs/site/scripts/check-built-links.mjs",
        "docs/site/scripts/check-evidence-links.mjs",
        "docs/site/scripts/check-llms-contract.mjs",
        "docs/site/scripts/check-llms.mjs",
        "docs/site/scripts/check-seo.mjs",
        "docs/site/scripts/configuration-reference.mjs",
        "docs/site/scripts/docsets.mjs",
        "docs/site/scripts/generate-breg-configuration.mjs",
        "docs/site/scripts/generate-configuration-formats.mjs",
        "docs/site/scripts/generate-evidence-configuration.mjs",
        "docs/site/scripts/retry.mjs",
        "docs/site/src/data/archive-lock.yaml",
        "docs/site/src/data/docsets.yaml",
        "docs/site/src/data/repo-docs.yaml",
        "docs/site/src/lib/analytics.mjs",
        "docs/site/src/lib/archived-evidence-paths.mjs",
        "docs/site/src/lib/docset-path.mjs",
        "docs/site/src/lib/docset-retention.mjs",
        "docs/site/src/lib/generated-api-bases.mjs",
        "docs/site/src/lib/page-markdown.ts",
    }
)

# Every workflow whose security properties are inspected by the release gate
# inventory selects the additional local gates that own those properties. All
# root workflows select release_tool below, including workflows not yet in this
# table, so a new privileged workflow cannot silently bypass the policy gate.
SECURITY_WORKFLOW_GATES: dict[str, frozenset[str]] = {
    ".github/workflows/codeql.yml": frozenset({"release_tool"}),
    ".github/workflows/mirror-buildkit.yml": frozenset({"release_tool"}),
    ".github/workflows/docs-pages.yml": frozenset(
        {"docs", "release_source_proof", "release_tool"}
    ),
    ".github/workflows/evidence-dev.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/nightly-release.yml": frozenset(
        {"release_source_proof", "release_tool"}
    ),
    ".github/workflows/nightly-security.yml": frozenset(
        {"evidence_assurance", "platform", "release_tool"}
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
    ".github/workflows/release-native-benchmark.yml": frozenset(
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
    ".github/workflows/release-upgrade-rehearsal.yml": frozenset(
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


def identifier_catalog_packages(workspace: Workspace) -> frozenset[str]:
    """Workspace packages owning a file the identifier catalog is built from."""

    return frozenset(
        package
        for path in IDENTIFIER_CATALOG_INPUTS
        if not any(character in path for character in "*?[")
        and (package := workspace.package_for_path(path)) is not None
    )


@dataclass(frozen=True)
class LockChange:
    """How a Cargo.lock difference routes CI.

    ``members`` names the workspace members whose locked dependency closure
    changed, or is None when the change must select the complete matrix.
    ``native`` is true when the change can alter compiled or linked native
    code, or when that cannot be ruled out.
    """

    members: frozenset[str] | None
    native: bool
    reason: str


LockKey = tuple[str, str, str]


class LockGraph:
    """The package graph Cargo.lock records, keyed by name, version and source.

    Lock edges carry no dependency kind, so normal, build and dev edges are all
    followed. Parsing needs no registry download.
    """

    def __init__(self, text: str) -> None:
        document = tomllib.loads(text)
        packages = document.get("package")
        if not isinstance(packages, list) or not packages:
            raise ValueError("it has no package list")
        self.header = {key: value for key, value in document.items() if key != "package"}
        self.entries: dict[LockKey, tuple[Any, tuple[str, ...]]] = {}
        for package in packages:
            name, version = package.get("name"), package.get("version")
            source = package.get("source", "")
            dependencies = package.get("dependencies", [])
            if not all(isinstance(value, str) for value in (name, version, source)):
                raise ValueError(f"it has an invalid package entry: {package!r}")
            if not isinstance(dependencies, list) or not all(
                isinstance(dependency, str) for dependency in dependencies
            ):
                raise ValueError(f"{name} {version} has invalid dependencies")
            key = (name, version, source)
            if key in self.entries:
                raise ValueError(f"it repeats {name} {version}")
            self.entries[key] = (package.get("checksum"), tuple(dependencies))

        by_name: dict[str, list[LockKey]] = defaultdict(list)
        for key in self.entries:
            by_name[key[0]].append(key)
        self.dependents: dict[LockKey, set[LockKey]] = defaultdict(set)
        for key, (_, dependencies) in self.entries.items():
            for dependency in dependencies:
                parts = dependency.split(" ")
                candidates = [
                    candidate
                    for candidate in by_name.get(parts[0], ())
                    if len(parts) < 2 or candidate[1] == parts[1]
                ]
                if len(parts) == 3:
                    candidates = [
                        candidate
                        for candidate in candidates
                        if f"({candidate[2]})" == parts[2]
                    ]
                if len(parts) > 3 or len(candidates) != 1:
                    raise ValueError(f"{key[0]} {key[1]} names unresolved {dependency!r}")
                self.dependents[candidates[0]].add(key)

    def members_reaching(
        self, changed: Iterable[LockKey], members: frozenset[str]
    ) -> set[str]:
        """Workspace members whose locked closure contains a changed package.

        The walk stops at a member: Workspace.affected_packages owns the
        member-to-member closure, including its dev-dependency rule.
        """

        reached: set[str] = set()
        seen = set(changed)
        queue = deque(seen)
        while queue:
            key = queue.popleft()
            if not key[2] and key[0] in members:
                reached.add(key[0])
                continue
            for dependent in self.dependents.get(key, ()):
                if dependent not in seen:
                    seen.add(dependent)
                    queue.append(dependent)
        return reached


def lock_change(
    base_text: str | None, head_text: str | None, workspace: Workspace
) -> LockChange:
    """Route a Cargo.lock difference, failing closed to the complete matrix."""

    if base_text is None or head_text is None:
        return LockChange(None, True, "Cargo.lock is absent or unreadable at one comparison endpoint")
    try:
        base, head = LockGraph(base_text), LockGraph(head_text)
    except (tomllib.TOMLDecodeError, ValueError) as error:
        return LockChange(None, True, f"Cargo.lock cannot be compared: {error}")
    if base.header != head.header:
        return LockChange(None, True, "Cargo.lock format or patch section changed")

    changed = {
        key
        for key in base.entries.keys() | head.entries.keys()
        if base.entries.get(key) != head.entries.get(key)
    }
    if not changed:
        return LockChange(None, True, "Cargo.lock changed without a package difference")

    native = sorted(
        {
            key[0]
            for key in changed
            if key[0].endswith("-sys")
            or key[0] in LOCK_NATIVE_PACKAGES
            or any(
                dependency.split(" ")[0] in LOCK_NATIVE_BUILD_HELPERS
                for graph in (base, head)
                for dependency in graph.entries.get(key, (None, ()))[1]
            )
        }
    )
    if native:
        return LockChange(None, True, f"native locked package changed: {', '.join(native)}")
    git = sorted({key[0] for key in changed if key[2].startswith("git+")})
    if git:
        return LockChange(None, True, f"git-sourced locked package changed: {', '.join(git)}")

    members = workspace.package_names
    reached = base.members_reaching(changed & base.entries.keys(), members)
    reached |= head.members_reaching(changed & head.entries.keys(), members)
    if not reached:
        return LockChange(None, False, "Cargo.lock change reaches no workspace member")
    affected = workspace.affected_packages(reached)
    # Widely used proc-macros (serde_derive, thiserror-impl, tokio-macros) and
    # their syntax toolchain reach most of the workspace, and so does any other
    # widely shared crate. Past half the workspace, the remaining gates cost
    # little more than the affected ones, so the complete matrix runs instead.
    if 2 * len(affected) >= len(members):
        return LockChange(
            None,
            False,
            f"Cargo.lock change reaches {len(affected)} of {len(members)} workspace members",
        )
    return LockChange(
        frozenset(reached),
        False,
        f"{len(changed)} locked package entries changed; "
        f"{len(affected)} workspace members affected",
    )


def matches(path: str, *patterns: str) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_DOCS_MANIFEST = "docs/site/src/data/repo-docs.yaml"
REPO_DOCS_SOURCE = re.compile(r"^\s*(?:-\s+)?src:\s*(\S+)\s*$", re.MULTILINE)


def repo_docs_sources(root: Path = REPO_ROOT) -> frozenset[str]:
    """Return the owning source of every page the site generates from repo-docs.yaml.

    The classifier runs without PyYAML, so this reads each docs entry's
    ``src:`` key by line; test_ci_changes.py holds the result equal to a full
    YAML parse of the manifest.
    """

    text = (root / REPO_DOCS_MANIFEST).read_text(encoding="utf-8")
    return frozenset(
        match.group(1).strip("'\"") for match in REPO_DOCS_SOURCE.finditer(text)
    )


CONFIG_FORMATS = "products/platform/config-formats.yaml"
CONFIG_FORMAT_PATH = re.compile(
    r"^\s*(?:-\s+)?(?:path|file|example|driftCheck|differentialTest):\s*(\S+)\s*$",
    re.MULTILINE,
)
CONFIG_FORMAT_CRATE = re.compile(r"^\s*(?:-\s+)?crate:\s*(\S+)\s*$", re.MULTILINE)


def config_format_inputs(
    root: Path = REPO_ROOT,
) -> tuple[frozenset[str], frozenset[str]]:
    """Return the repository files and reader crates config-formats.yaml names.

    The classifier runs without PyYAML, so this reads the path-valued and
    ``crate:`` keys by line; test_ci_changes.py holds the result equal to a
    full YAML parse of the registry.
    """

    text = (root / CONFIG_FORMATS).read_text(encoding="utf-8")
    paths = {
        match.group(1).strip("'\"") for match in CONFIG_FORMAT_PATH.finditer(text)
    }
    crates = {
        match.group(1).strip("'\"") for match in CONFIG_FORMAT_CRATE.finditer(text)
    }
    return frozenset(paths - {"none"}), frozenset(crates)


def is_root_workflow(path: str) -> bool:
    """Return whether path is an executable GitHub workflow at the root."""

    parts = path.split("/")
    return (
        len(parts) == 3
        and parts[:2] == [".github", "workflows"]
        and parts[2].endswith((".yml", ".yaml"))
    )


def classify(
    workspace: Workspace,
    changed_paths: Iterable[str],
    *,
    run_all: bool = False,
    full_sweep: bool = False,
    pull_request: bool = False,
    ci_full: bool = False,
    main_push: bool = False,
    lock_change: LockChange | None = None,
) -> dict[str, Any]:
    """Select CI gates for changed paths.

    ``pull_request`` defers broad assurance and the heavy integration tier to
    the merge queue and the nightly sweep; ``ci_full`` opts a pull request back
    into the heavy tier. ``main_push`` marks a push to main, where platform
    line coverage runs.
    ``lock_change`` routes a Cargo.lock difference through the packages it
    reaches; without one, Cargo.lock selects the complete matrix.
    """

    changed = tuple(
        path.strip().removeprefix("./") for path in changed_paths if path.strip()
    )
    lock_members = (
        lock_change.members
        if lock_change is not None and "Cargo.lock" in changed
        else None
    )
    # A routed lock change selects work through its affected packages, so the
    # literal Cargo.lock path only reaches the gates that read the lock bytes.
    paths = tuple(
        path for path in changed if not (path == "Cargo.lock" and lock_members is not None)
    )
    security_workflow_gates = frozenset(
        gate
        for path in paths
        for gate in SECURITY_WORKFLOW_GATES.get(path, ())
    )
    registry_record_cross_product = any(
        matches(path, *REGISTRY_RECORD_CROSS_PRODUCT_INPUTS) for path in paths
    )
    force_all = run_all or full_sweep or any(
        path
        in {
            ".github/workflows/ci.yml",
            ".github/scripts/ci_changes.py",
            ".github/scripts/ci_event_routing.py",
            ".github/scripts/run_cargo_packages.py",
        }
        or (is_root_workflow(path) and path not in SECURITY_WORKFLOW_GATES)
        or path.startswith(".cargo/")
        or path in ROOT_RUST_INPUTS
        for path in paths
    )

    seeds: set[str] = set(lock_members or ())
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
            elif path.startswith("products/breg/"):
                seeds.update(BREG_PACKAGES)
            elif path.startswith("products/casework/"):
                seeds.update(CASEWORK_PACKAGES)
            elif path.startswith("products/scheduling/"):
                seeds.update(SCHEDULING_PACKAGES)
            elif path.startswith("products/messaging/"):
                seeds.update(MESSAGING_PACKAGES)
            elif path.startswith("products/identifiers/"):
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

    # The heavy integration tier: PostgreSQL suites, the WebAssembly build and
    # the tutorial and composition journeys. Each keeps its path gate below.
    # A pull request runs it only when labeled `ci:full`. Every other event
    # runs it: the merge queue, the nightly sweep, manual runs and main
    # pushes, whose full run the release protected-ci checks read.
    integration = full_sweep or ci_full or not pull_request
    # The production cross-compiled Linux client recipe runs only in the
    # nightly and manual full sweeps; review and the merge queue prove each
    # binding with the native binding job.
    release_linux_node_clients = full_sweep

    identifiers = complete or any(
        matches(path, *IDENTIFIER_CATALOG_INPUTS) for path in paths
    ) or (
        # The catalog compiles its exporters, so a routed lock change that
        # reaches one regenerates the catalog as the complete matrix did.
        lock_members is not None
        and bool(affected & identifier_catalog_packages(workspace))
    )

    platform = complete or "platform" in security_workflow_gates or any(
        matches(
            path,
            "crates/registry-platform-*",
            "products/platform/*",
        )
        or path in ROOT_RUST_INPUTS
        for path in paths
    ) or (lock_members is not None and bool(affected & PLATFORM_PACKAGES))
    # Fuzz smoke is broad assurance for the merge queue and the nightly sweep,
    # while review keeps platform-quality. Line coverage runs on main and in
    # the nightly sweep only, outside the merge verdict.
    platform_assurance = platform and (full_sweep or not pull_request)
    platform_coverage = platform and (full_sweep or main_push)
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
    # Evidence fuzz smoke follows the platform fuzz policy: broad assurance
    # for the merge queue and the nightly sweep, deferred out of review.
    evidence_assurance = (
        bool(affected & EVIDENCE_PACKAGES)
        or "evidence_assurance" in security_workflow_gates
    ) and (full_sweep or not pull_request)
    format_paths, format_crates = config_format_inputs()
    config_conformance = (
        complete
        or any(
            path in format_paths
            or matches(path, *CONFIG_CONFORMANCE_INPUTS, *CONFIG_CONVENTIONS_INPUTS)
            for path in paths
        )
        or bool(
            affected
            & (CONFIG_CONFORMANCE_PACKAGES | CONFIG_CHECK_PACKAGES | format_crates)
        )
    )
    release_tool = (
        complete
        or "release_tool" in security_workflow_gates
        or any(is_root_workflow(path) for path in paths)
        or any(
            path.startswith("release/")
            or path
            in {
                # The release helper validates the workspace versions it locks.
                "Cargo.lock",
                "THIRD_PARTY_NOTICES",
                "docs/site/src/content/docs/reference/errors.mdx",
            }
            for path in changed
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
            for path in changed
        )
    )
    # The docs suite scans every current page generated from repo-docs.yaml,
    # so a change to one of their owning sources needs a docs run.
    repo_docs = repo_docs_sources()
    docs = complete or "docs" in security_workflow_gates or any(
        matches(
            path,
            "docs/site/*",
            "products/manifest/docs/*",
            # The Evidence configuration reference page is generated from the
            # frozen contracts and from the authoring-form schemas beside
            # them, so either going stale needs a docs rebuild.
            "products/evidence/contracts/*",
            "products/evidence/generated/registry-evidence.openapi.json",
            "crates/registry-evidencectl/schemas/authoring/*",
            "products/breg/generated/authoring/*",
            "products/breg/generated/runtime/*",
            "products/breg/evidence/**",
            "products/evidence/reference/authoring-projects/SOURCE-EXPORT.md",
            "products/evidence/reference/request-adapter/deployment-projects/SOURCE-CREDENTIAL-ROTATION.md",
            # The same page names the product reference that explains each
            # schema, and the docs tests read those references to prove the
            # published key paths and the documented ones agree.
            "products/evidence/reference/*/CONFIG.md",
            # The published authoring guide states behavior enforced in these
            # modules, not only the generated question and marker schemas.
            *EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_PATTERNS,
            *CLI_REFERENCE_PATTERNS,
        )
        or path in repo_docs
        or path
        in {
            # An operator document outside the site that the docs release-pin
            # suite (scripts/current-docs-release-pins.test.mjs) scans as a
            # current page.
            "docker/README.md",
        }
        for path in paths
    ) or (
        # Generated CLI pages compile every public Clap tree.
        lock_members is not None and "registry-cli-docs" in affected
    )
    # Rebuild immutable history only when archive inputs or assembly semantics
    # change. Publication workflows, this workflow and this classifier do not
    # alter archived bytes; their focused tests cover those contracts, and the
    # nightly full sweep replays the archive job's own recipe. Review defers
    # the rebuild to the merge queue.
    docs_archives = full_sweep or (
        not pull_request and any(path in DOCS_ARCHIVE_INPUTS for path in changed)
    )
    editors = (
        complete
        or any(path.startswith("editors/") for path in paths)
        # The shared editor configurator copies these product-owned schemas.
        # Exercise its real settings generation when a copied contract changes.
        or any(
            path.startswith(prefix)
            for path in paths
            for prefix in (
                "products/breg/generated/authoring/",
                "products/breg/generated/runtime/",
                "products/casework/generated/runtime/",
                "products/scheduling/generated/runtime/",
                "products/messaging/generated/runtime/",
                "products/discovery/schemas/",
            )
        )
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

    evidence_tutorial = integration and (
        complete
        or any(matches(path, *EVIDENCE_TUTORIAL_INPUTS) for path in paths)
        or bool(
            affected & (EVIDENCE_TUTORIAL_PACKAGES | ASSEMBLED_PYTHON_CLIENT_PACKAGES)
        )
    )

    breg_tutorial = integration and (
        complete
        or any(matches(path, *BREG_TUTORIAL_INPUTS) for path in paths)
        or bool(affected & BREG_TUTORIAL_PACKAGES)
    )

    casework_tutorial = integration and (
        complete
        or any(matches(path, *CASEWORK_TUTORIAL_INPUTS) for path in paths)
        or bool(affected & CASEWORK_TUTORIAL_PACKAGES)
    )

    messaging_tutorial = (
        complete
        or any(matches(path, *MESSAGING_TUTORIAL_INPUTS) for path in paths)
        or bool(affected & MESSAGING_TUTORIAL_PACKAGES)
    )

    breg_evidence_composition = integration and (
        complete
        or any(matches(path, *BREG_EVIDENCE_COMPOSITION_INPUTS) for path in paths)
        or bool(affected & BREG_EVIDENCE_COMPOSITION_PACKAGES)
    )

    matrix = []
    for shard_name, shard_packages in SHARDS.items():
        selected = sorted(affected.intersection(shard_packages))
        if selected:
            matrix.append(
                {
                    "name": shard_name,
                    "packages": selected,
                    "all_features": False,
                }
            )

    # The PostgreSQL lane starts the real Evidence service. This is an
    # integration test edge, not a production runtime Cargo dependency.
    breg_contracts = (
        registry_record_cross_product
        or bool(affected & BREG_PACKAGES)
        or "registry-evidence" in affected
        or any(
            matches(
                path,
                "crates/registry-casework/src/**",
                "crates/registry-casework-core/src/task_grant.rs",
                "crates/registry-thunderid-tooling/**",
            )
            for path in paths
        )
    )

    outputs = {
        "full_sweep": full_sweep,
        "rust": bool(affected),
        "rust_matrix": {"include": matrix},
        "rust_packages": sorted(affected),
        "platform": platform,
        "platform_assurance": platform_assurance,
        "platform_coverage": platform_coverage,
        "platform_hygiene": platform_hygiene,
        "config_conformance": config_conformance,
        "discovery_contracts": complete
        or bool(affected & DISCOVERY_PACKAGES)
        or any(matches(path, *DISCOVERY_PROVIDER_INPUTS) for path in paths)
        or any(matches(path, *DISCOVERY_TUTORIAL_INPUTS) for path in paths),
        "breg_contracts": breg_contracts,
        "evidence_contracts": bool(affected & EVIDENCE_PACKAGES),
        "evidence_assurance": evidence_assurance,
        "scheduling_contracts": bool(affected & SCHEDULING_PACKAGES),
        # The Casework task approval journey drives the stock issuer through
        # Evidence, BReg, and the Scheduling authorization probe, so it runs on
        # every input of the BReg product gate and of the Scheduling runtime.
        "breg_integration": integration and breg_contracts,
        "breg_contracts_lanes": list(
            BREG_CONTRACTS_LANES if integration else BREG_CONTRACTS_LANES[:1]
        ),
        "casework_postgres": (integration or "registry-platform-activation" in affected)
        and (
            bool(affected & CASEWORK_PACKAGES)
            or breg_contracts
            or "registry-scheduling" in affected
        ),
        "scheduling_postgres": (
            integration or "registry-platform-activation" in affected
        ) and bool(affected & (SCHEDULING_PACKAGES | {"registry-platform-dispatch"})),
        "messaging_contracts": bool(affected & MESSAGING_PACKAGES),
        "messaging_postgres": bool(affected & MESSAGING_PACKAGES),
        "release_tool": release_tool,
        "release_source_proof": release_source_proof,
        "docs": docs,
        "docs_archives": docs_archives,
        "editors": editors,
        "client_bindings": client_bindings,
        "release_linux_node_clients": release_linux_node_clients,
        "evidence_tutorial": evidence_tutorial,
        "breg_tutorial": breg_tutorial,
        "casework_tutorial": casework_tutorial,
        "messaging_tutorial": messaging_tutorial,
        "breg_evidence_composition": breg_evidence_composition,
        "identifiers": identifiers,
    }
    return outputs


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
    parser.add_argument("--full-sweep", action="store_true")
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()

    if not (args.run_all or args.full_sweep) and args.changed_files is None:
        parser.error("--changed-files is required unless --all or --full-sweep is set")

    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    changed_paths = (
        args.changed_files.read_text(encoding="utf-8").splitlines()
        if args.changed_files is not None
        else ()
    )
    outputs = classify(
        Workspace(metadata), changed_paths, run_all=args.run_all, full_sweep=args.full_sweep
    )
    write_github_outputs(args.github_output, outputs)
    print(json.dumps(outputs, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
