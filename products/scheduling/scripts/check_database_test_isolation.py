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


# The database suites the product maintains. Each must keep its
# required-features gate: a suite that loses it runs in every workspace test
# invocation and fails for want of a database the caller never offered.
DATABASE_SUITES = {
    "registry-scheduling": {"postgres_commitments"},
    "registry-schedulingctl": {"records_apply_postgres", "intents_postgres"},
}


def ungated_database_targets(metadata: dict) -> dict[str, list[str]]:
    """Map each package to its declared database suites missing the gate.

    A suite the metadata does not declare at all is absent, not ungated: a
    fixture that does not model it, or a suite a later change removed, is
    not running anywhere uninvited. Only a declared target with an empty or
    absent `required-features` list runs in every test invocation.
    """
    ungated: dict[str, list[str]] = {}
    for package in metadata["packages"]:
        expected = DATABASE_SUITES.get(package["name"])
        if expected is None:
            continue
        missing_gate = sorted(
            target["name"]
            for target in package.get("targets", [])
            if "test" in target.get("kind", [])
            and target["name"] in expected
            and not target.get("required-features")
        )
        if missing_gate:
            ungated[package["name"]] = missing_gate
    return ungated


def features_enabling(metadata: dict, sibling: str, wanted: str) -> list[str]:
    """The sibling's features whose expansion names `wanted`.

    One level of expansion is enough here: a feature whose own expansion
    names a gating feature selects the gated targets exactly as naming the
    gate itself would, and the gate's subject stays the dependency entry
    that asks for it.
    """
    for package in metadata["packages"]:
        if package["name"] == sibling:
            return [
                name
                for name, enables in (package.get("features") or {}).items()
                if wanted in enables
            ]
    return []


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
    ungated = ungated_database_targets(metadata)
    failures: list[str] = []
    for package in metadata["packages"]:
        if not package["name"].startswith(SCHEDULING_PREFIX):
            continue
        # A database-only suite must stay opt-in. A test target the package
        # does not gate runs in every workspace test invocation, including
        # the shards with no database to offer.
        for target in ungated.get(package["name"], []):
            failures.append(
                f"{package['name']}/{target} has no required-features gate; "
                f"the database suites must stay opt-in"
            )
        for dependency in package.get("dependencies", []):
            if not dependency["name"].startswith(SCHEDULING_PREFIX):
                continue
            sibling = dependency["name"]
            requested = gated.get(sibling, {})
            # Both spellings of the same accident: asking for the gating
            # feature itself, or for a feature whose expansion enables it.
            # The alias map is keyed by the gate; a forwarded feature lands
            # there under the gate it selects.
            aliases = {
                forwarder: gate
                for gate in requested
                for forwarder in features_enabling(metadata, sibling, gate)
            }
            direct = list(dependency.get("features") or [])
            asked: list[tuple[str, str]] = [(feature, feature) for feature in direct]
            asked.extend(
                (feature, aliases[feature]) for feature in direct if feature in aliases
            )
            for feature, gate in sorted(set(asked)):
                targets = requested.get(gate)
                if not targets:
                    continue
                kind = dependency.get("kind")
                table = f"{kind}-dependencies" if kind else "dependencies"
                failures.append(
                    f"{package['name']} enables {sibling}/{feature} in its "
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
    print("No Scheduling crate enables a sibling's database-only test feature.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
