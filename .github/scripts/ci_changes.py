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
        "registry-platform-ops",
        "registry-platform-pdp",
        "registry-platform-sdjwt",
        "registry-platform-sqlite",
        "registry-platform-testing",
    ),
    "manifest": (
        "registry-manifest-cli",
        "registry-manifest-core",
    ),
    "relay": ("registry-relay",),
    "relay-v2": ("registry-relay-v2", "registry-relayctl"),
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
        "registry-config-report",
        "registry-language-server",
    ),
    "registryctl": ("registryctl",),
}

EVIDENCE_PACKAGES = frozenset(SHARDS["evidence"])
PLATFORM_PACKAGES = frozenset(SHARDS["platform"])
MANIFEST_PACKAGES = frozenset(SHARDS["manifest"])
RELAY_V2_PACKAGES = frozenset(SHARDS["relay-v2"])
TUTORIAL_PACKAGES = frozenset(
    package
    for shard in ("platform", "manifest", "relay", "registryctl")
    for package in SHARDS[shard]
) | {"registry-config-report"}

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
        "docs/site/scripts/registryctl-tutorial.mjs",
        "docs/site/src/content/docs/tutorials/assert-a-role-bound-relationship.mdx",
        "docs/site/src/content/docs/tutorials/control-who-can-request-evidence.mdx",
        "docs/site/src/content/docs/tutorials/first-evidence-assertion.mdx",
        "docs/site/src/content/docs/tutorials/refuse-unsafe-evidence-requests.mdx",
        "docs/site/src/content/docs/tutorials/request-evidence-as-sd-jwt-vc.mdx",
        "docs/site/src/content/docs/tutorials/request-evidence-from-an-application.mdx",
        "docs/site/src/content/docs/tutorials/return-a-governed-value.mdx",
        "docs/site/src/content/docs/tutorials/verify-an-assertion-as-a-consumer.mdx",
    }
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

# Binding crates stay in EVIDENCE_PACKAGES and the `evidence` shard, because
# their own source is covered by check-source-neutrality.sh, and that is what
# makes `evidence_contracts` run the neutrality check against them. Every
# binding also selects its own job, whose npm, type-drift and unittest suites
# are the only cover its full API gets.
EVIDENCE_BINDING_PACKAGES = frozenset(
    {"registry-evidence-client-node", "registry-evidence-client-py"}
)

# A package is exempt from the tutorial trigger only while no tutorial runs it.
# The Python binding is what `request-evidence-from-an-application` imports, so
# a change to it has to replay that tutorial and is not listed here. Move a
# package out of this set as soon as a registered tutorial exercises it, or its
# regressions reach readers before they reach CI. Evidence OID4VCI has its own
# Rust and frozen-profile contract coverage; the current tutorial gate neither
# builds the adapter nor executes a wallet flow. Exemption is from the tutorial
# trigger alone, never from Evidence contracts or package tests.
EVIDENCE_TUTORIAL_EXEMPT_PACKAGES = frozenset(
    {"registry-evidence-client-node", "registry-evidence-oid4vci"}
)

# The gate also builds and runs `mint`, because one tutorial serves assertions
# to a caller holding a real Mint-issued token.
EVIDENCE_TUTORIAL_PACKAGES = (
    EVIDENCE_PACKAGES - EVIDENCE_TUTORIAL_EXEMPT_PACKAGES
) | frozenset(SHARDS["mint"])

ROOT_RUST_INPUTS = {
    "Cargo.lock",
    "Cargo.toml",
    "clippy.toml",
    "deny.toml",
    "rust-toolchain",
    "rust-toolchain.toml",
    "rustfmt.toml",
}

RELEASE_SECURITY_WORKFLOWS = frozenset(
    {
        ".github/workflows/evidence-dev.yml",
        ".github/workflows/release.yml",
        ".github/workflows/release-candidate.yml",
        ".github/workflows/release-repeatability.yml",
        ".github/workflows/release-candidate-cleanup.yml",
    }
)
REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORING_REFERENCE_MANIFEST = (
    REPO_ROOT / "docs/site/scripts/authoring-reference-sources.json"
)


def authoring_reference_contract_sources(
    manifest_path: Path = AUTHORING_REFERENCE_MANIFEST,
) -> tuple[str, ...]:
    """Derive repository inputs from the published reference source contract."""

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    schema_sources = manifest.get("schema_sources")
    field_knowledge = manifest.get("field_knowledge")
    human_intent = manifest.get("human_intent")
    runtime_intent = manifest.get("runtime_intent")
    if (
        not isinstance(schema_sources, list)
        or not schema_sources
        or not all(isinstance(source, str) and source for source in schema_sources)
        or not isinstance(field_knowledge, str)
        or not field_knowledge
        or not isinstance(human_intent, str)
        or not human_intent
        or not isinstance(runtime_intent, list)
        or not runtime_intent
        or not all(isinstance(source, str) and source for source in runtime_intent)
    ):
        raise ValueError(
            f"authoring-reference manifest has an invalid source contract: {manifest_path}"
        )

    sources = [
        (
            f"schemas/{source}"
            if source.startswith("registry-")
            else f"crates/registryctl/schemas/project-authoring/{source}"
        )
        for source in schema_sources
    ]
    for source in (field_knowledge.split("#", 1)[0], human_intent):
        sources.append(
            source if source.startswith("crates/") else f"crates/registryctl/{source}"
        )
    sources.extend(runtime_intent)
    if any(source.startswith(("/", "../")) for source in sources):
        raise ValueError(
            "authoring-reference source contract must use repository-relative paths"
        )
    if len(sources) != len(set(sources)):
        raise ValueError("authoring-reference source contract paths must be unique")
    return tuple(sources)


def validate_authoring_reference_routing(
    contract_sources: tuple[str, ...],
    inputs: tuple[tuple[str, str], ...],
) -> None:
    """Fail when a source-contract input can change without rebuilding docs."""

    missing = [
        source
        for source in contract_sources
        if not any(fnmatch.fnmatchcase(source, pattern) for pattern, _ in inputs)
    ]
    if missing:
        raise ValueError(
            "authoring-reference CI inputs do not route source-contract paths: "
            f"{missing}"
        )


def authoring_reference_inputs(
    manifest_path: Path = AUTHORING_REFERENCE_MANIFEST,
) -> tuple[tuple[str, str], ...]:
    """Load the authoring-reference CI routing inventory from its owner."""

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    inputs = manifest.get("ci_inputs")
    if not isinstance(inputs, list) or not inputs:
        raise ValueError(
            f"authoring-reference manifest has no ci_inputs: {manifest_path}"
        )

    parsed: list[tuple[str, str]] = []
    for index, entry in enumerate(inputs):
        if not isinstance(entry, dict):
            raise ValueError(
                f"authoring-reference ci_inputs[{index}] must be an object"
            )
        pattern = entry.get("pattern")
        sample = entry.get("sample")
        if (
            not isinstance(pattern, str)
            or not pattern
            or not isinstance(sample, str)
            or not sample
            or pattern.startswith(("/", "../"))
            or sample.startswith(("/", "../"))
            or not fnmatch.fnmatchcase(sample, pattern)
        ):
            raise ValueError(
                "authoring-reference CI inputs must have matching "
                f"repository-relative pattern/sample pairs: {entry!r}"
            )
        if not (REPO_ROOT / sample).is_file():
            raise ValueError(
                "authoring-reference CI input samples must name existing "
                f"repository files: {sample!r}"
            )
        parsed.append((pattern, sample))

    patterns = [pattern for pattern, _ in parsed]
    samples = [sample for _, sample in parsed]
    if len(patterns) != len(set(patterns)) or len(samples) != len(set(samples)):
        raise ValueError("authoring-reference CI patterns and samples must be unique")
    result = tuple(parsed)
    validate_authoring_reference_routing(
        authoring_reference_contract_sources(manifest_path),
        result,
    )
    return result


AUTHORING_REFERENCE_CONTRACT_SOURCES = authoring_reference_contract_sources()
AUTHORING_REFERENCE_INPUTS = authoring_reference_inputs()
AUTHORING_REFERENCE_PATTERNS = tuple(
    pattern for pattern, _ in AUTHORING_REFERENCE_INPUTS
)


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
                    reverse_dependencies[dependency_name].add(package_name)
        self.reverse_dependencies = reverse_dependencies

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
        queue = deque(affected)
        while queue:
            dependency = queue.popleft()
            for dependent in self.reverse_dependencies.get(dependency, ()):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)
        return affected


def matches(path: str, *patterns: str) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def classify(
    workspace: Workspace, changed_paths: Iterable[str], *, run_all: bool = False
) -> dict[str, Any]:
    paths = tuple(
        path.strip().removeprefix("./") for path in changed_paths if path.strip()
    )
    force_all = run_all or any(
        path
        in {
            ".github/workflows/ci.yml",
            ".github/scripts/ci_changes.py",
            ".github/scripts/run_cargo_packages.py",
        }
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
            elif path.startswith("products/manifest/"):
                seeds.update(MANIFEST_PACKAGES)
            elif path.startswith("products/platform/"):
                seeds.update(PLATFORM_PACKAGES)
            elif path.startswith("products/relay-v2/"):
                seeds.update(RELAY_V2_PACKAGES)
            elif path in {
                "docs/site/src/data/generated/relay-support.json",
                "docs/site/src/data/relay-support.yaml",
            }:
                seeds.add("registry-relay")
            elif path.startswith(("crates/", "products/")):
                # A new or moved Rust package must not silently escape the test matrix.
                force_all = True

    affected = (
        set(workspace.package_names)
        if force_all
        else workspace.affected_packages(seeds)
    )
    complete = run_all or force_all

    platform = complete or any(
        matches(
            path,
            "crates/registry-config-report/*",
            "crates/registry-platform-*",
            "products/platform/*",
        )
        or path in ROOT_RUST_INPUTS
        for path in paths
    )
    platform_hygiene = complete or any(
        matches(
            path,
            "crates/registry-relay/clippy.toml",
            "crates/registry-relay/config/*",
            "crates/registry-relay/demo/config/*",
            "crates/registry-relay/deny.toml",
            "crates/registry-relay/perf/config/*",
            "crates/registry-relay/profiles/*",
            "crates/registry-relay/rustfmt.toml",
            "crates/registry-relay/tests/fixtures/config/*",
            "products/platform/clippy.toml",
            "products/platform/deny.toml",
            "products/platform/rustfmt.toml",
            "products/platform/scripts/*",
            "products/platform/templates/*",
        )
        or path in {"clippy.toml", "deny.toml", "rustfmt.toml"}
        for path in paths
    )
    release_tool = complete or any(
        path.startswith("release/")
        or path
        in RELEASE_SECURITY_WORKFLOWS
        | {
            "docs/site/src/content/docs/reference/errors.mdx",
        }
        for path in paths
    )
    release_source_proof = complete or any(
        path in RELEASE_SECURITY_WORKFLOWS
        or path
        in {
            "Cargo.lock",
            "Cargo.toml",
            "release/scripts/check-release-source-model.sh",
            "release/scripts/test_check_release_source_model.py",
        }
        or path.startswith("release/manifests/")
        for path in paths
    )
    docs = complete or any(
        matches(
            path,
            "crates/registry-relay/docs/*",
            "crates/registry-relay/openapi/*",
            "crates/registry-relay/src/api/openapi.rs",
            "crates/registryctl/assets/project-starters/*",
            "crates/registry-platform-ops/src/lib.rs",
            "crates/registry-relay/src/consultation/*",
            "crates/registryctl/schemas/project-reports/*",
            "crates/registryctl/src/templates/*",
            "crates/registryctl/tests/fixtures/project-authoring/*",
            "crates/registryctl/tests/fixtures/project-reports/*",
            "docs/site/*",
            "products/manifest/docs/*",
            # The Evidence configuration reference page is generated from the
            # frozen contracts and from the authoring-form schemas beside
            # them, so either going stale needs a docs rebuild.
            "products/evidence/contracts/*",
            "crates/registry-evidencectl/schemas/authoring/*",
            # The same page names the product reference that explains each
            # schema, and the docs tests read those references to prove the
            # published key paths and the documented ones agree.
            "products/evidence/reference/*/CONFIG.md",
            # The published authoring guide states behavior enforced in these
            # modules, not only the generated question and marker schemas.
            *EVIDENCE_AUTHORING_GUIDE_IMPLEMENTATION_PATTERNS,
            *AUTHORING_REFERENCE_PATTERNS,
        )
        or path
        in {
            ".github/workflows/docs-pages.yml",
            "crates/registry-relay/src/main.rs",
            "crates/registry-relay/src/process_startup.rs",
            "crates/registry-relay/src/server.rs",
            "crates/registryctl/src/main.rs",
            "crates/registryctl/src/project_authoring/capability_inventory.rs",
            "crates/registryctl/src/project_authoring/diagnostic_reference.rs",
            "crates/registryctl/src/project_authoring/diagnostics.rs",
            "crates/registryctl/src/project_authoring/fixture_diagnostics.rs",
            "crates/registryctl/src/project_authoring/fixture_coverage.rs",
            "crates/registryctl/src/project_authoring/output.rs",
            "crates/registryctl/src/project_authoring/preflight.rs",
            "crates/registryctl/src/project_authoring/promotion_projection.rs",
            "crates/registryctl/src/project_authoring/report_contract.rs",
            "crates/registryctl/src/project_authoring/required_product_action.rs",
            "crates/registryctl/tests/fixtures/project-authoring-journeys.yaml",
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
    # Reverse dependents, not changed paths: both bindings are Cargo path
    # dependents of the SDK and the verifier, so a change to either can move
    # the native surface or the error envelope the packages wrap without
    # touching a file inside a binding crate.
    client_bindings = complete or bool(affected & EVIDENCE_BINDING_PACKAGES)

    tutorial_infrastructure = any(
        path
        in {
            "Cargo.lock",
            "Cargo.toml",
            "LICENSE",
            "docs/site/package-lock.json",
            "docs/site/package.json",
            "docs/site/public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh",
            "docs/site/public/examples/registryctl/jsonplaceholder-todo-live-overlay-v1.sh.sha256",
            "docs/site/public/examples/registryctl/opencrvs-events-api-overlay-v1.sh",
            "docs/site/public/examples/registryctl/opencrvs-events-api-overlay-v1.sh.sha256",
            "docs/site/scripts/check-registryctl-tutorials.sh",
            "docs/site/scripts/registryctl-tutorial.mjs",
            "docs/site/scripts/registryctl-tutorial.test.mjs",
            "docs/site/src/content/docs/configure/oauth-client-credentials.mdx",
            "docs/site/src/content/docs/operate/approve-initial-baseline.mdx",
            "docs/site/src/content/docs/tutorials/author-registry-project.mdx",
            "docs/site/src/content/docs/tutorials/configure-project-script-adapter.mdx",
            "docs/site/src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx",
            "docs/site/src/content/docs/tutorials/use-your-spreadsheet.mdx",
            "docs/site/src/content/docs/tutorials/verify-claim-registry-api.mdx",
            "docs/site/src/content/docs/tutorials/verify-opencrvs-claims.mdx",
            "release/docker/Dockerfile.registry-relay",
        }
        for path in paths
    )
    tutorial_source_under_test = any(
        matches(
            path,
            "crates/registryctl/src/templates/*",
        )
        or path
        in {
            "crates/registry-relay/src/api/openapi.rs",
            "crates/registry-relay/src/main.rs",
            "crates/registry-relay/src/server.rs",
            "crates/registryctl/src/main.rs",
            "crates/registryctl/src/project_authoring/output.rs",
        }
        for path in paths
    )
    registryctl_tutorial = (
        complete
        or tutorial_infrastructure
        or tutorial_source_under_test
        or bool(affected & TUTORIAL_PACKAGES)
    )

    evidence_tutorial = (
        complete
        or any(path in EVIDENCE_TUTORIAL_INPUTS for path in paths)
        or bool(affected & EVIDENCE_TUTORIAL_PACKAGES)
    )

    matrix = []
    for shard_name, shard_packages in SHARDS.items():
        selected = sorted(affected.intersection(shard_packages))
        if selected:
            matrix.append(
                {
                    "name": shard_name,
                    "packages": selected,
                    "all_features": shard_name in {"relay", "relay-v2"},
                }
            )

    return {
        "rust": bool(affected),
        "rust_matrix": {"include": matrix},
        "rust_packages": sorted(affected),
        "platform": platform,
        "platform_hygiene": platform_hygiene,
        "relay_contracts": "registry-relay" in affected,
        "relay_v2_contracts": bool(affected & RELAY_V2_PACKAGES),
        "evidence_contracts": bool(affected & EVIDENCE_PACKAGES),
        "project_authoring": "registryctl" in affected,
        "release_tool": release_tool,
        "release_source_proof": release_source_proof,
        "docs": docs,
        "docs_archives": docs_archives,
        "editors": editors,
        "client_bindings": client_bindings,
        "registryctl_tutorial": registryctl_tutorial,
        "evidence_tutorial": evidence_tutorial,
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
