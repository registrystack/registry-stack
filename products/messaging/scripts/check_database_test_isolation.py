#!/usr/bin/env python3
"""Keep Messaging's maintained PostgreSQL suites out of default test runs."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

DATABASE_SUITES = {
    "registry-messaging": {
        "postgres_dispatch",
        "postgres_messages",
        "postgres_migrate",
        "postgres_package",
    },
    "registry-messagingctl": {"postgres_messages_cli"},
}


def violations(metadata: dict) -> list[str]:
    """Use Cargo's default feature resolution, including aliases and forwarding.

    Only maintained database targets need a gate. Ordinary integration tests
    remain database-free and may run without required-features. A declared
    suite that no longer exists is reported, so renaming a suite cannot drop
    it from this check unnoticed.
    """
    resolved = {
        node["id"]: set(node["features"])
        for node in metadata["resolve"]["nodes"]
    }
    failures: list[str] = []
    seen: set[tuple[str, str]] = set()
    for package in metadata["packages"]:
        expected = DATABASE_SUITES.get(package["name"], set())
        for target in package.get("targets", []):
            if "test" not in target.get("kind", []) or target["name"] not in expected:
                continue
            seen.add((package["name"], target["name"]))
            label = f"{package['name']}/{target['name']}"
            required = set(target.get("required-features") or [])
            if "postgres-test" not in required:
                failures.append(f"{label} must require the postgres-test feature")
            elif package["id"] not in resolved:
                failures.append(f"{label} has no resolved feature inventory")
            elif required <= resolved[package["id"]]:
                failures.append(f"{label} is enabled by default resolved features")
    for package_name, targets in sorted(DATABASE_SUITES.items()):
        for target_name in sorted(targets):
            if (package_name, target_name) not in seen:
                failures.append(
                    f"{package_name}/{target_name} is a declared database suite with no test target"
                )
    return failures


def load_metadata(repository_root: Path, fixture: Path | None) -> dict:
    if fixture:
        return json.loads(fixture.read_text(encoding="utf-8"))
    completed = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
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
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(
            f"database-test isolation check could not inspect Cargo metadata: {error}",
            file=sys.stderr,
        )
        return 2
    if failures:
        for failure in failures:
            print(f"database-test isolation violation: {failure}", file=sys.stderr)
        return 1
    print("Messaging database suites remain opt-in under default Cargo resolution.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
