#!/usr/bin/env python3
"""Keep Scheduling's maintained PostgreSQL suites out of default test runs."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

DATABASE_SUITES = {
    "registry-scheduling": {"postgres_commitments"},
    "registry-schedulingctl": {"records_apply_postgres", "intents_postgres"},
}


def violations(metadata: dict) -> list[str]:
    """Use Cargo's default feature resolution, including aliases and forwarding.

    Only maintained database targets need a gate. Ordinary integration tests
    remain database-free and may run without required-features.
    """
    resolved = {
        node["id"]: set(node["features"])
        for node in metadata["resolve"]["nodes"]
    }
    failures: list[str] = []
    for package in metadata["packages"]:
        expected = DATABASE_SUITES.get(package["name"], set())
        for target in package.get("targets", []):
            if "test" not in target.get("kind", []) or target["name"] not in expected:
                continue
            label = f"{package['name']}/{target['name']}"
            required = set(target.get("required-features") or [])
            if "postgres-test" not in required:
                failures.append(f"{label} must require the postgres-test feature")
            elif package["id"] not in resolved:
                failures.append(f"{label} has no resolved feature inventory")
            elif required <= resolved[package["id"]]:
                failures.append(f"{label} is enabled by default resolved features")
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
        print(f"database-test isolation check could not inspect Cargo metadata: {error}", file=sys.stderr)
        return 2
    if failures:
        for failure in failures:
            print(f"database-test isolation violation: {failure}", file=sys.stderr)
        return 1
    print("Scheduling database suites remain opt-in under default Cargo resolution.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
