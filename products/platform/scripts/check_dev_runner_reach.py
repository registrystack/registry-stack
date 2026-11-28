#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check normal dependency declarations and references to the development runner."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEV_RUNNER = "registry-rstack-dev"
ALLOWLIST = {
    DEV_RUNNER: {
        "registry-adapterctl": "Hosts Adapter development runs.",
        "registry-bregctl": "Hosts BReg development runs.",
        "registry-caseworkctl": "Hosts Casework development runs.",
        "registry-coordinator": "Hosts Coordinator development runs in coordinatorctl.",
        "registry-discoveryctl": "Hosts Discovery development runs.",
        "registry-documentsctl": "Hosts Document Store development runs.",
        "registry-evidencectl": "Hosts Evidence development runs.",
        "registry-messagingctl": "Hosts Messaging development runs.",
        "registry-render": "Hosts Render development runs in the CLI.",
        "registry-schedulingctl": "Hosts Scheduling development runs.",
    },
    "registry-platform-testing": {
        "registry-adapter-connectors": "Provides the authorization server behind the connector test-support feature.",
    },
    "registry-thunderid-tooling": {
        "registry-adapterctl": "Authors Adapter identity configuration.",
        "registry-bregctl": "Authors BReg identity configuration and local sessions.",
        "registry-caseworkctl": "Authors Casework identity configuration.",
        "registry-coordinator": "Authors Coordinator identity configuration in coordinatorctl.",
        "registry-documentsctl": "Authors Document Store identity configuration.",
        "registry-evidencectl": "Authors Evidence identity configuration.",
        "registry-messagingctl": "Authors Messaging identity configuration and local sessions.",
        "registry-render": "Authors Render identity configuration in the CLI.",
        "registry-rstack": "Provides shared identity authoring commands.",
        "registry-schedulingctl": "Authors Scheduling identity configuration.",
    },
}

RUNTIME_REFERENCES = {
    "registry-coordinator": {"cli.rs", "project_check.rs"},
    "registry-render": {"main.rs", "cli.rs", "bundle.rs", "check.rs"},
}


def dependency_violations(metadata: dict) -> list[str]:
    failures = []
    members = set(metadata["workspace_members"])
    for package in metadata["packages"]:
        if package["id"] not in members:
            continue
        name = package["name"]
        for dependency in package["dependencies"]:
            target = dependency["name"]
            if dependency["kind"] is None and target in ALLOWLIST and name not in ALLOWLIST[target]:
                failures.append(f"{name} declares an unapproved normal dependency on {target}")
    return sorted(failures)


def source_violations(root: Path) -> list[str]:
    failures = []
    for package, permitted in RUNTIME_REFERENCES.items():
        source = root / "crates" / package / "src"
        for path in sorted(source.rglob("*.rs")):
            if path.relative_to(source).as_posix() in permitted:
                continue
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "registry_rstack_dev::" in line:
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
            ["cargo", "metadata", "--locked", "--format-version", "1",
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
