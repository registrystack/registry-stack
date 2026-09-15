#!/usr/bin/env python3
"""Check that no Scheduling crate selects a sibling's database-only tests."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

# The product this gate speaks for. A dependency on another product's crate is
# that product's business, and its own gates are where it belongs.
SCHEDULING_PREFIX = "registry-scheduling"


def gated_test_targets(metadata: dict) -> dict[str, dict[str, list[str]]]:
    """Map each package to the feature that gates each of its test targets."""
    gated: dict[str, dict[str, list[str]]] = {}
    for package in metadata["packages"]:
        for target in package.get("targets", []):
            if "test" not in target.get("kind", []):
                continue
            for feature in target.get("required-features") or []:
                gated.setdefault(package["name"], {}).setdefault(feature, []).append(
                    target["name"]
                )
    return gated


def violations(metadata: dict) -> list[str]:
    """Report every dependency entry that turns a sibling's gate on.

    Cargo unifies features across one invocation, so a dependency entry naming
    a feature is the same as passing it on the command line for every build
    that selects both crates. A feature gating a test target that needs a
    disposable PostgreSQL server therefore stops being opt-in: the database-free
    shard compiles and runs the suite, and it fails for want of a server the
    caller never offered. The feature the package declares for itself is the
    opt-in the suites are meant to have; this is about what a sibling asks for.
    """
    gated = gated_test_targets(metadata)
    failures: list[str] = []
    for package in metadata["packages"]:
        if not package["name"].startswith(SCHEDULING_PREFIX):
            continue
        for dependency in package.get("dependencies", []):
            if not dependency["name"].startswith(SCHEDULING_PREFIX):
                continue
            requested = gated.get(dependency["name"], {})
            for feature in dependency.get("features") or []:
                targets = requested.get(feature)
                if not targets:
                    continue
                kind = dependency.get("kind")
                table = f"{kind}-dependencies" if kind else "dependencies"
                failures.append(
                    f"{package['name']} enables {dependency['name']}/{feature} in its "
                    f"[{table}] entry, which selects that crate's database-only test "
                    f"target(s) {', '.join(sorted(targets))} in every build holding "
                    f"both crates, including the ones with no database"
                )
    return failures


def load_metadata(repository_root: Path, fixture: Path | None) -> dict:
    if fixture:
        return json.loads(fixture.read_text(encoding="utf-8"))
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
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
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"database-test isolation check could not inspect Cargo metadata: {error}", file=sys.stderr)
        return 2
    if failures:
        for failure in failures:
            print(f"database-test isolation violation: {failure}", file=sys.stderr)
        return 1
    print("Scheduling database suites stay opt-in.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
