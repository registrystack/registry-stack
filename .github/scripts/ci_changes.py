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
        "registry-platform-cache",
        "registry-platform-canonical-json",
        "registry-platform-config",
        "registry-platform-crypto",
        "registry-platform-httpsec",
        "registry-platform-httputil",
        "registry-platform-oid4vci",
        "registry-platform-oidc",
        "registry-platform-ops",
        "registry-platform-pdp",
        "registry-platform-replay",
        "registry-platform-sdjwt",
        "registry-platform-testing",
    ),
    "manifest": (
        "registry-manifest-cli",
        "registry-manifest-core",
    ),
    "notary": (
        "registry-notary",
        "registry-notary-client",
        "registry-notary-core",
        "registry-notary-server",
        "registry-notary-worker-harness",
        "xtask",
    ),
    "relay": ("registry-relay",),
    "developer-tools": (
        "registry-config-report",
        "registry-language-server",
    ),
    "registryctl": ("registryctl",),
}

NOTARY_PACKAGES = frozenset(SHARDS["notary"])
PLATFORM_PACKAGES = frozenset(SHARDS["platform"])
MANIFEST_PACKAGES = frozenset(SHARDS["manifest"])
TUTORIAL_PACKAGES = frozenset(
    package
    for shard in ("platform", "manifest", "notary", "relay", "registryctl")
    for package in SHARDS[shard]
) | {"registry-config-report"}

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
        ".github/workflows/release.yml",
        ".github/workflows/release-candidate.yml",
        ".github/workflows/release-repeatability.yml",
        ".github/workflows/release-candidate-cleanup.yml",
    }
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
            if path.startswith("products/notary/"):
                seeds.update(NOTARY_PACKAGES)
            elif path.startswith("products/manifest/"):
                seeds.update(MANIFEST_PACKAGES)
            elif path.startswith("products/platform/"):
                seeds.update(PLATFORM_PACKAGES)
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
            "docs/site/*",
            "products/manifest/docs/*",
            "products/notary/docs/*",
            "products/notary/openapi/*",
        )
        or path == ".github/workflows/docs-pages.yml"
        for path in paths
    )
    docs_archives = any(
        path
        in {
            ".github/workflows/ci.yml",
            ".github/workflows/docs-pages.yml",
            ".github/workflows/release.yml",
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
    editors = complete or any(path.startswith("editors/") for path in paths)

    tutorial_infrastructure = any(
        path
        in {
            "Cargo.lock",
            "Cargo.toml",
            "LICENSE",
            "docs/site/package-lock.json",
            "docs/site/package.json",
            "docs/site/scripts/check-registryctl-tutorials.sh",
            "docs/site/scripts/registryctl-tutorial.mjs",
            "docs/site/scripts/registryctl-tutorial.test.mjs",
            "docs/site/src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx",
            "docs/site/src/content/docs/tutorials/verify-claim-registry-api.mdx",
            "release/docker/Dockerfile.registry-notary",
            "release/docker/Dockerfile.registry-relay",
        }
        or path.startswith("products/notary/")
        for path in paths
    )
    registryctl_tutorial = (
        complete or tutorial_infrastructure or bool(affected & TUTORIAL_PACKAGES)
    )

    matrix = []
    for shard_name, shard_packages in SHARDS.items():
        selected = sorted(affected.intersection(shard_packages))
        if selected:
            matrix.append(
                {
                    "name": shard_name,
                    "packages": selected,
                    "all_features": shard_name == "relay",
                }
            )

    return {
        "rust": bool(affected),
        "rust_matrix": {"include": matrix},
        "rust_packages": sorted(affected),
        "platform": platform,
        "platform_hygiene": platform_hygiene,
        "notary_contracts": bool(affected & NOTARY_PACKAGES),
        "relay_contracts": "registry-relay" in affected,
        "project_authoring": "registryctl" in affected,
        "release_tool": release_tool,
        "release_source_proof": release_source_proof,
        "docs": docs,
        "docs_archives": docs_archives,
        "editors": editors,
        "registryctl_tutorial": registryctl_tutorial,
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
