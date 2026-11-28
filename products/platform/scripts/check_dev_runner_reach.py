#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check normal dependency declarations and references to the development runner."""

import argparse
import json
import re
import subprocess
import sys
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEV_RUNNER = "registry-rstack-dev"
ALLOWLIST = {
    DEV_RUNNER: {
        "registry-adapterctl": "Hosts Adapter development runs.",
        "registry-bregctl": "Hosts BReg development runs.",
        "registry-caseworkctl": "Hosts Casework development runs.",
        "registry-cli-docs": "Reads CLI command trees from development command hosts.",
        "registry-coordinator": "Hosts Coordinator development runs in coordinatorctl.",
        "registry-discoveryctl": "Hosts Discovery development runs.",
        "registry-documentsctl": "Hosts Document Store development runs.",
        "registry-evidencectl": "Hosts Evidence development runs.",
        "registry-messagingctl": "Hosts Messaging development runs.",
        "registry-render": "Hosts Render development runs in the CLI.",
        "registry-schedulingctl": "Hosts Scheduling development runs.",
    },
    "registry-platform-testing": {
        "registry-adapter-job": "Enables connector test support only through native-test-support.",
        "registry-cli-docs": "Reads the Adapter job command tree, which exposes connector test support only with native-test-support.",
        "registry-adapter-connectors": "Provides the authorization server behind the connector test-support feature.",
    },
    "registry-thunderid-tooling": {
        "registry-adapterctl": "Authors Adapter identity configuration.",
        "registry-bregctl": "Authors BReg identity configuration and local sessions.",
        "registry-caseworkctl": "Authors Casework identity configuration.",
        "registry-cli-docs": "Reads CLI command trees from identity authoring hosts.",
        "registry-coordinator": "Authors Coordinator identity configuration in coordinatorctl.",
        "registry-documentsctl": "Authors Document Store identity configuration.",
        "registry-evidencectl": "Authors Evidence identity configuration.",
        "registry-messagingctl": "Authors Messaging identity configuration and local sessions.",
        "registry-render": "Authors Render identity configuration in the CLI.",
        "registry-rstack": "Provides shared identity authoring commands.",
        "registry-schedulingctl": "Authors Scheduling identity configuration.",
    },
}

# These crates link the runner to read command trees and start no development
# runs, so CI change routing does not treat them as development run hosts.
COMMAND_TREE_READERS = frozenset({"registry-cli-docs"})
DEV_RUNNER_HOSTS = frozenset(ALLOWLIST[DEV_RUNNER]) - COMMAND_TREE_READERS

RUNNER_REFERENCE = re.compile(
    r"\bregistry_rstack_dev\s*::|\b(?:use\s+(?:::)?\s*|extern\s+crate\s+)registry_rstack_dev\b"
)

RUNTIME_REFERENCES = {
    "registry-coordinator": {"cli.rs", "project_check.rs"},
    "registry-render": {"main.rs", "cli.rs", "bundle.rs", "check.rs"},
}


def dependency_violations(metadata: dict) -> list[str]:
    failures = []
    packages = {package["id"]: package for package in metadata["packages"]}
    normal_dependencies = {
        node["id"]: [
            dependency["pkg"] for dependency in node["deps"]
            if any(kind["kind"] is None for kind in dependency["dep_kinds"])
        ]
        for node in (metadata.get("resolve") or {}).get("nodes", [])
    }
    for member in metadata["workspace_members"]:
        package = packages[member]
        name = package["name"]
        pending = deque([(member, [name])])
        seen = {member}
        reported = set()
        while pending:
            current, chain = pending.popleft()
            for dependency_id in normal_dependencies.get(current, []):
                if dependency_id in seen:
                    continue
                seen.add(dependency_id)
                target = packages[dependency_id]["name"]
                next_chain = [*chain, target]
                if target in ALLOWLIST and name not in ALLOWLIST[target] and target not in reported:
                    failures.append(f"Unapproved normal dependency: {' -> '.join(next_chain)}")
                    reported.add(target)
                pending.append((dependency_id, next_chain))

        # Keep checking direct declarations even if a supplied graph omits optional features.
        for dependency in package["dependencies"]:
            target = dependency["name"]
            if (
                dependency["kind"] is None and target in ALLOWLIST
                and name not in ALLOWLIST[target] and target not in reported
            ):
                failures.append(f"Unapproved normal dependency: {name} -> {target}")
    return sorted(failures)


def source_violations(root: Path) -> list[str]:
    failures = []
    for package, permitted in RUNTIME_REFERENCES.items():
        source = root / "crates" / package / "src"
        for path in sorted(source.rglob("*.rs")):
            if path.relative_to(source).as_posix() in permitted:
                continue
            contents = path.read_text(encoding="utf-8")
            for match in RUNNER_REFERENCE.finditer(contents):
                line_number = contents.count("\n", 0, match.start()) + 1
                failures.append(f"{path.relative_to(root)}:{line_number}: development runner reference")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, help="Read a saved Cargo metadata JSON response")
    args = parser.parse_args()
    if args.metadata:
        metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    else:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1",
             "--manifest-path", str(ROOT / "Cargo.toml")],
            cwd=ROOT,
        ))
    failures = dependency_violations(metadata) + source_violations(ROOT)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Development runner and tooling reach passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
