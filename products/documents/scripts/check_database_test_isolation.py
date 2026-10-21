#!/usr/bin/env python3
"""Keep the Document Store's PostgreSQL suites out of default test runs, and
make each one fail, rather than skip, without its database."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DATABASE_SUITES = {
    "registry-documents": {
        "postgres_documents",
        "postgres_journey",
        "postgres_operator",
        "postgres_s3",
        "postgres_startup",
    },
    "registry-documentsctl": {"postgres_cli"},
}

DATABASE_VARIABLE = "DOCUMENTS_TEST_DATABASE_URL"

# One read of the database variable and the call that follows it.
DATABASE_READ = re.compile(
    r"env::var(?:_os)?\(\s*\"" + DATABASE_VARIABLE + r"\"\s*\)\s*(\.\s*\w+)?"
)


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


def source_violations(repository_root: Path) -> list[str]:
    """A suite without its database must fail on the spot, never pass.

    Each declared suite reads the database variable itself or through the
    shared `support` module, every read is followed by `.expect(`, so an
    absent variable panics, and no test in a suite is `#[ignore]`d, since
    an ignored database test is one nobody runs.
    """
    failures: list[str] = []

    def reads(path: Path, label: str) -> bool:
        text = path.read_text(encoding="utf-8")
        found = False
        for match in DATABASE_READ.finditer(text):
            found = True
            call = re.sub(r"\s", "", match.group(1) or "")
            if call != ".expect":
                line = text.count("\n", 0, match.start()) + 1
                failures.append(
                    f"{label}:{line} reads {DATABASE_VARIABLE} without .expect, so it can skip"
                )
        return found

    for package_name, targets in sorted(DATABASE_SUITES.items()):
        tests = repository_root / "crates" / package_name / "tests"
        support = tests / "support" / "mod.rs"
        support_reads = support.is_file() and reads(
            support, f"{package_name}/tests/support/mod.rs"
        )
        for target_name in sorted(targets):
            path = tests / f"{target_name}.rs"
            label = f"{package_name}/{target_name}"
            if not path.is_file():
                failures.append(f"{label} has no source at {path.relative_to(repository_root)}")
                continue
            text = path.read_text(encoding="utf-8")
            direct = reads(path, label)
            through_support = support_reads and re.search(r"^mod support;", text, re.M)
            if not direct and not through_support:
                failures.append(f"{label} never reads {DATABASE_VARIABLE}")
            if re.search(r"#\[\s*ignore\b", text):
                failures.append(f"{label} ignores a database test, so it never runs")
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
    parser.add_argument("--sources", type=Path, help="read suite sources under this root")
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[3]
    try:
        failures = violations(load_metadata(repository_root, args.metadata))
        failures += source_violations(args.sources or repository_root)
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
    print(
        "Document Store database suites remain opt-in under default Cargo resolution"
        " and fail without DOCUMENTS_TEST_DATABASE_URL."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
