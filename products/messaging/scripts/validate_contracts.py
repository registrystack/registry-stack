#!/usr/bin/env python3
"""Validate the Messaging product contract files against the code they cite.

The three documents under products/messaging/contracts/ are the review
baseline for every later Messaging change. This validator holds them to the
shape the product committed to:

- the matrix lists exactly the ten invariants of the product specification,
  MESSAGING-SEC-01 to MESSAGING-SEC-10;
- every invariant names a threat, an enforcement point, and a refusal;
- an enforced or partial invariant names a negative test, and every cited
  test exists in the cited file and is selectable by its runner. Rust
  inventories compile the selected target with its required features;
  citations may add features for gated library modules. Python inventories
  use unittest discovery. Neither inventory executes test bodies;
- a pending invariant names the slice that owes it and what that slice will
  prove, and cites no test until the slice lands;
- the traceability document covers exactly the invariants that are not
  pending;
- every recorded decision cites evidence that exists;
- every deferral names the tracked file that records it, and that file
  exists.

The check is source-mapped, not executed: rows whose tests live in a
PostgreSQL suite are proven when that suite runs, and the matrix says so in
its own evidence note.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Callable

import yaml

CONTRACT_API_VERSION = "registry.registrystack.org/product-contract/v1"
TRACEABILITY_CONTRACT = "registry.messaging.security-test-traceability/v1"
SECURITY_ID = re.compile(r"^MESSAGING-SEC-\d{2}$")
DEFERRED_ID = re.compile(r"^MESSAGING-DEF-\d{2}$")
DECISION_ID = re.compile(r"^MESSAGING-DEC-\d{2}$")
PLANNED_SLICE = re.compile(r"^S[2-6]$")
EXPECTED_INVARIANTS = tuple(f"MESSAGING-SEC-{number:02d}" for number in range(1, 11))
STATES = ("enforced", "partial", "pending")

TextResolver = Callable[[str], str | None]


def _non_empty(value: object) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _cited_test_violations(
    label: str, path: str | None, name: str | None, resolve: TextResolver
) -> list[str]:
    """One cited test: the file must exist and must define the name."""
    if not _non_empty(path) or not _non_empty(name):
        return [f"{label}: a cited test needs both a path and a name"]
    if path.startswith("/") or ".." in Path(path).parts:
        return [f"{label}: cited path {path!r} must be a repository-relative path"]
    text = resolve(path)
    if text is None:
        return [f"{label}: cited file {path} does not exist"]
    if path.endswith(".rs"):
        if f"fn {name}(" not in text:
            return [f"{label}: {path} defines no test function {name}"]
    elif path.endswith(".py"):
        if f"def {name}(" not in text:
            return [f"{label}: {path} defines no test method {name}"]
    else:
        return [f"{label}: cited file {path} is neither Rust nor Python"]
    return []


def _row_violations(row: dict, label: str, resolve: TextResolver) -> list[str]:
    violations: list[str] = []
    for field in ("threat", "enforcementPoint", "refusal"):
        if not _non_empty(row.get(field)):
            violations.append(f"{label}: {field} is required and empty")
    state = row.get("state")
    if state not in STATES:
        return violations + [
            f"{label}: state must be enforced, partial, or pending, not {state!r}"
        ]
    if state == "pending":
        if not isinstance(row.get("plannedSlice"), str) or not PLANNED_SLICE.match(
            row["plannedSlice"]
        ):
            violations.append(f"{label}: a pending invariant must name its slice, S2 to S6")
        if not _non_empty(row.get("pendingNote")):
            violations.append(f"{label}: a pending invariant must say what its slice will prove")
        if "negativeTest" in row:
            violations.append(
                f"{label}: a pending invariant cites no test; move it to partial or enforced"
            )
        return violations
    if "plannedSlice" in row or "pendingNote" in row:
        violations.append(f"{label}: only a pending invariant names a planned slice")
    if state == "partial" and not _non_empty(row.get("partialNote")):
        violations.append(f"{label}: a partial invariant must say what is missing")
    test = row.get("negativeTest")
    if not isinstance(test, dict):
        violations.append(f"{label}: negativeTest with path and name is required")
    else:
        violations.extend(
            _cited_test_violations(label, test.get("path"), test.get("name"), resolve)
        )
    return violations


def matrix_violations(matrix: dict, resolve: TextResolver) -> list[str]:
    violations: list[str] = []
    if matrix.get("apiVersion") != CONTRACT_API_VERSION:
        violations.append(f"matrix: apiVersion must be {CONTRACT_API_VERSION}")
    if matrix.get("product") != "messaging":
        violations.append("matrix: product must be messaging")

    invariants = matrix.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        return violations + ["matrix: no invariants listed"]

    ids: list[str] = []
    for row in invariants:
        if not isinstance(row, dict):
            violations.append("matrix: every invariant is a mapping")
            continue
        row_id = row.get("id")
        label = f"matrix {row_id}"
        if not isinstance(row_id, str) or not SECURITY_ID.match(row_id):
            violations.append(f"matrix: invariant id {row_id!r} is not MESSAGING-SEC-NN")
            continue
        if row_id in ids:
            violations.append(f"{label}: listed more than once")
        ids.append(row_id)
        violations.extend(_row_violations(row, label, resolve))
    if tuple(ids) != EXPECTED_INVARIANTS:
        violations.append(
            "matrix: the invariants must be exactly MESSAGING-SEC-01 to MESSAGING-SEC-10, in order"
        )

    deferred = matrix.get("deferred", [])
    deferred_ids: set[str] = set()
    if not isinstance(deferred, list):
        violations.append("matrix: deferred must be a list")
        deferred = []
    for row in deferred:
        row_id = row.get("id") if isinstance(row, dict) else None
        label = f"matrix {row_id}"
        if not isinstance(row_id, str) or not DEFERRED_ID.match(row_id):
            violations.append(f"matrix: deferred id {row_id!r} is not MESSAGING-DEF-NN")
            continue
        if row_id in deferred_ids:
            violations.append(f"{label}: listed more than once")
        deferred_ids.add(row_id)
        for field in ("subject", "reason", "compensatingControl", "recordedIn"):
            if not _non_empty(row.get(field)):
                violations.append(f"{label}: {field} is required and empty")
        recorded_in = row.get("recordedIn")
        if _non_empty(recorded_in) and resolve(recorded_in) is None:
            violations.append(f"{label}: recordedIn file {recorded_in} does not exist")
    return violations


def traceability_violations(
    traceability: dict, matrix: dict, resolve: TextResolver
) -> list[str]:
    violations: list[str] = []
    if traceability.get("contract") != TRACEABILITY_CONTRACT:
        violations.append(f"traceability: contract must be {TRACEABILITY_CONTRACT}")
    entries = traceability.get("entries")
    if not isinstance(entries, list) or not entries:
        return violations + ["traceability: no entries listed"]

    cited: set[str] = set()
    for entry in entries:
        entry_id = entry.get("id") if isinstance(entry, dict) else None
        label = f"traceability {entry_id}"
        if not isinstance(entry_id, str) or not SECURITY_ID.match(entry_id):
            violations.append(f"traceability: entry id {entry_id!r} is not MESSAGING-SEC-NN")
            continue
        if entry_id in cited:
            violations.append(f"{label}: listed more than once")
        cited.add(entry_id)
        tests = entry.get("tests")
        if not isinstance(tests, list) or not tests:
            violations.append(f"{label}: at least one test must be cited")
            continue
        for test in tests:
            if not isinstance(test, dict):
                violations.append(f"{label}: every cited test is a path and name pair")
                continue
            violations.extend(
                _cited_test_violations(label, test.get("path"), test.get("name"), resolve)
            )

    rows = [row for row in matrix.get("invariants", []) if isinstance(row, dict)]
    earned = {row.get("id") for row in rows if row.get("state") in ("enforced", "partial")}
    pending = {row.get("id") for row in rows if row.get("state") == "pending"}
    for missing in sorted(earned - cited):
        violations.append(f"traceability: invariant {missing} has no entry")
    for early in sorted(cited & pending):
        violations.append(f"traceability: entry {early} cites tests for a pending invariant")
    for extra in sorted(cited - earned - pending):
        violations.append(f"traceability: entry {extra} matches no matrix invariant")
    return violations


def decisions_violations(decisions: dict, resolve: TextResolver) -> list[str]:
    violations: list[str] = []
    if decisions.get("apiVersion") != CONTRACT_API_VERSION:
        violations.append(f"decisions: apiVersion must be {CONTRACT_API_VERSION}")
    if decisions.get("product") != "messaging":
        violations.append("decisions: product must be messaging")
    if not _non_empty(decisions.get("purpose")):
        violations.append("decisions: purpose is required and empty")
    entries = decisions.get("decisions")
    if not isinstance(entries, list) or not entries:
        return violations + ["decisions: no decisions listed"]

    seen: set[str] = set()
    for row in entries:
        row_id = row.get("id") if isinstance(row, dict) else None
        label = f"decision {row_id}"
        if not isinstance(row_id, str) or not DECISION_ID.match(row_id):
            violations.append(f"decisions: id {row_id!r} is not MESSAGING-DEC-NN")
            continue
        if row_id in seen:
            violations.append(f"{label}: listed more than once")
        seen.add(row_id)
        for field in ("subject", "decision", "reasoning"):
            if not _non_empty(row.get(field)):
                violations.append(f"{label}: {field} is required and empty")
        evidence = row.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            violations.append(f"{label}: at least one evidence test must be cited")
            continue
        for test in evidence:
            if not isinstance(test, dict):
                violations.append(f"{label}: every evidence test is a path and name pair")
                continue
            violations.extend(
                _cited_test_violations(label, test.get("path"), test.get("name"), resolve)
            )
    return violations


def validate(
    matrix: dict, traceability: dict, decisions: dict, resolve: TextResolver
) -> list[str]:
    return [
        *matrix_violations(matrix, resolve),
        *traceability_violations(traceability, matrix, resolve),
        *decisions_violations(decisions, resolve),
    ]


def runner_violations(root: Path, citations: list[dict]) -> list[str]:
    """List tests, never execute them, caching each runner within this check."""
    inventories: dict[tuple[str, ...], set[str]] = {}
    failures: list[str] = []
    for path, name, features in sorted({
        (test["path"], test["name"], tuple(test.get("features", []))) for test in citations
    }):
        source = (root / path).resolve()
        if not source.is_relative_to(root.resolve()) or not source.is_file():
            failures.append(f"{path}: cited test source is missing or outside the repository")
            continue
        try:
            if source.suffix == ".rs":
                manifest = next(
                    (parent / "Cargo.toml" for parent in source.parents
                     if parent.is_relative_to(root.resolve())
                     and (parent / "Cargo.toml").is_file()),
                    None,
                )
                if manifest is None:
                    raise ValueError("no Cargo manifest for cited test")
                package = tomllib.loads(manifest.read_text(encoding="utf-8"))
                command = ["cargo", "test", "--locked", "--manifest-path", str(manifest)]
                relative = source.relative_to(manifest.parent)
                targets = package.get("test", [])
                target = next((target for target in targets if
                    target.get("path", f"tests/{target['name']}.rs") == relative.as_posix()), None)
                if target is not None or relative.parts[0] == "tests":
                    if target is None and len(relative.parts) != 2:
                        raise ValueError("cite the integration test target source")
                    target = target or {"name": source.stem}
                    command.extend(["--test", target["name"]])
                    if target.get("required-features"):
                        command.extend(["--features", ",".join(target["required-features"])])
                else:
                    command.append("--lib")
                if features:
                    command.extend(["--features", ",".join(features)])
                command.extend(["--", "--list", "--format", "terse"])
                key = tuple(command)
                if key not in inventories:
                    result = subprocess.run(command, cwd=root, check=True,
                                            capture_output=True, text=True)
                    inventories[key] = {
                        line.removesuffix(": test") for line in result.stdout.splitlines()
                        if line.endswith(": test")
                    }
                matches = [test for test in inventories[key]
                           if test == name or test.endswith(f"::{name}")]
            elif source.suffix == ".py":
                # A separate interpreter keeps discovery imports and load_tests
                # hooks out of the validator's own module namespace.
                command = [sys.executable, "-c", PYTHON_TEST_INVENTORY, str(source)]
                key = tuple(command)
                if key not in inventories:
                    result = subprocess.run(command, cwd=root, check=True,
                                            capture_output=True, text=True)
                    inventories[key] = set(json.loads(result.stdout))
                matches = [test for test in inventories[key]
                           if test == name or test.endswith(f".{name}")]
            else:
                raise ValueError("cited file is neither Rust nor Python")
            if len(matches) != 1:
                failures.append(f"{path}: {name} is not selectable as one test by its runner")
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            # Do not turn a failed build or import into an empty passing inventory.
            failures.append(f"{path}: test inventory failed ({type(error).__name__})")
    return failures


PYTHON_TEST_INVENTORY = """\
import inspect
import json
from pathlib import Path
import sys
import unittest

source = Path(sys.argv[1]).resolve()
loader = unittest.TestLoader()
suite = loader.discover(str(source.parent), pattern=source.name)
if loader.errors:
    raise RuntimeError("unittest discovery failed")

def names(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from names(test)
        else:
            method = getattr(test, test._testMethodName)
            if Path(inspect.getfile(method)).resolve() == source:
                yield test.id()

print(json.dumps(list(names(suite))))
"""


def cited_tests(value: object) -> list[dict]:
    if isinstance(value, dict):
        if "path" in value and "name" in value:
            return [value]
        return [test for child in value.values() for test in cited_tests(child)]
    if isinstance(value, list):
        return [test for child in value for test in cited_tests(child)]
    return []


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    contracts = root / "products" / "messaging" / "contracts"

    def resolve(path: str) -> str | None:
        candidate = root / path
        if not candidate.is_file():
            return None
        return candidate.read_text(encoding="utf-8")

    failures: list[str] = []
    loaded: dict[str, dict] = {}
    for name in (
        "security-invariant-matrix.yaml",
        "security-test-traceability.yaml",
        "recorded-decisions.yaml",
    ):
        try:
            with (contracts / name).open(encoding="utf-8") as handle:
                loaded[name] = yaml.safe_load(handle)
        except FileNotFoundError:
            failures.append(f"{name}: missing from {contracts}")
        except yaml.YAMLError as error:
            failures.append(f"{name}: not valid YAML: {error}")

    if not failures:
        failures = validate(
            loaded["security-invariant-matrix.yaml"],
            loaded["security-test-traceability.yaml"],
            loaded["recorded-decisions.yaml"],
            resolve,
        )

    if not failures:
        failures = runner_violations(root, cited_tests(loaded))

    if failures:
        for failure in failures:
            print(f"contracts: {failure}", file=sys.stderr)
        return 1
    print("Messaging product contracts are internally consistent and source-mapped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
