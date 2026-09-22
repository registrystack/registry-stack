#!/usr/bin/env python3
"""Keep Casework's BReg PostgreSQL support out of default workspace tests."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def package(metadata: dict, name: str) -> dict:
    matches = [candidate for candidate in metadata["packages"] if candidate["name"] == name]
    if len(matches) != 1:
        raise ValueError(f"expected one {name} package, found {len(matches)}")
    return matches[0]


def resolved_features(metadata: dict, package_id: str) -> set[str]:
    matches = [node for node in metadata["resolve"]["nodes"] if node["id"] == package_id]
    if len(matches) != 1:
        raise ValueError(f"expected one resolved node for {package_id}, found {len(matches)}")
    return set(matches[0]["features"])


def violations(default_metadata: dict, postgres_metadata: dict) -> list[str]:
    failures: list[str] = []
    casework = package(default_metadata, "registry-casework")
    breg = package(default_metadata, "registry-breg")
    forwarded = set(casework.get("features", {}).get("postgres-test", []))
    expected = {"dep:registry-breg", "registry-breg/postgres-test"}
    if not expected <= forwarded:
        failures.append(
            "registry-casework/postgres-test must activate its optional BReg dependency "
            "and forward registry-breg/postgres-test"
        )
    if "postgres-test" in resolved_features(default_metadata, breg["id"]):
        failures.append("default workspace resolution activates registry-breg/postgres-test")

    postgres_breg = package(postgres_metadata, "registry-breg")
    if "postgres-test" not in resolved_features(postgres_metadata, postgres_breg["id"]):
        failures.append(
            "registry-casework/postgres-test does not activate registry-breg/postgres-test"
        )
    return failures


def load_metadata(repository_root: Path, features: str | None, fixture: Path | None) -> dict:
    if fixture:
        return json.loads(fixture.read_text(encoding="utf-8"))
    command = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if features:
        command.extend(["--features", features])
    completed = subprocess.run(
        command,
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--default-metadata", type=Path)
    parser.add_argument("--postgres-metadata", type=Path)
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[3]
    try:
        failures = violations(
            load_metadata(repository_root, None, args.default_metadata),
            load_metadata(
                repository_root,
                "registry-casework/postgres-test",
                args.postgres_metadata,
            ),
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"database-test isolation check could not inspect Cargo metadata: {error}", file=sys.stderr)
        return 2
    if failures:
        for failure in failures:
            print(f"database-test isolation violation: {failure}", file=sys.stderr)
        return 1
    print("Casework's BReg PostgreSQL support remains an explicit feature opt-in.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
