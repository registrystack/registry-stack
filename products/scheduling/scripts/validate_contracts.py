#!/usr/bin/env python3
"""Validate the Scheduling product contract files against the code they cite.

The three documents under products/scheduling/contracts/ are the review
baseline for every later Scheduling change. This validator holds them to
the shape the product committed to:

- every security invariant names a threat, an enforcement point, a
  refusal, and a negative test;
- every cited test exists in the cited file, as a Rust test function or a
  Python test method, which is what makes it selectable by its own runner
  (cargo test <name>, unittest <name>);
- the traceability document covers exactly the matrix's invariants;
- every recorded decision cites evidence that exists;
- every deferral names the tracked file that records it, and that file
  exists.

The check is source-mapped, not executed: rows whose tests live in a
PostgreSQL suite are proven when that suite runs, and the matrix says so
in its own evidence note.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Callable

import yaml

CONTRACT_API_VERSION = "registry.registrystack.org/product-contract/v1"
TRACEABILITY_CONTRACT = "registry.scheduling.security-test-traceability/v1"
SECURITY_ID = re.compile(r"^SCHEDULING-SEC-\d{2}$")
DEFERRED_ID = re.compile(r"^SCHEDULING-DEF-\d{2}$")
DECISION_ID = re.compile(r"^SCHEDULING-DEC-\d{2}$")

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


def matrix_violations(matrix: dict, resolve: TextResolver) -> list[str]:
    violations: list[str] = []
    if matrix.get("apiVersion") != CONTRACT_API_VERSION:
        violations.append(f"matrix: apiVersion must be {CONTRACT_API_VERSION}")
    if matrix.get("product") != "scheduling":
        violations.append("matrix: product must be scheduling")

    invariants = matrix.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        return violations + ["matrix: no invariants listed"]

    ids: set[str] = set()
    for row in invariants:
        row_id = row.get("id")
        label = f"matrix {row_id}"
        if not isinstance(row_id, str) or not SECURITY_ID.match(row_id):
            violations.append(f"matrix: invariant id {row_id!r} is not SCHEDULING-SEC-NN")
            continue
        if row_id in ids:
            violations.append(f"{label}: listed more than once")
        ids.add(row_id)
        for field in ("threat", "enforcementPoint", "refusal"):
            if not _non_empty(row.get(field)):
                violations.append(f"{label}: {field} is required and empty")
        state = row.get("state")
        if state not in ("enforced", "partial"):
            violations.append(f"{label}: state must be enforced or partial, not {state!r}")
        if state == "partial" and not _non_empty(row.get("partialNote")):
            violations.append(f"{label}: a partial invariant must say what is missing")
        test = row.get("negativeTest")
        if not isinstance(test, dict):
            violations.append(f"{label}: negativeTest with path and name is required")
        else:
            violations.extend(
                _cited_test_violations(label, test.get("path"), test.get("name"), resolve)
            )

    deferred = matrix.get("deferred", [])
    deferred_ids: set[str] = set()
    if not isinstance(deferred, list):
        violations.append("matrix: deferred must be a list")
        deferred = []
    for row in deferred:
        row_id = row.get("id")
        label = f"matrix {row_id}"
        if not isinstance(row_id, str) or not DEFERRED_ID.match(row_id):
            violations.append(f"matrix: deferred id {row_id!r} is not SCHEDULING-DEF-NN")
            continue
        if row_id in deferred_ids:
            violations.append(f"{label}: listed more than once")
        deferred_ids.add(row_id)
        for field in ("subject", "reason", "compensatingControl", "recordedIn"):
            if not _non_empty(row.get(field)):
                violations.append(f"{label}: {field} is required and empty")
        recorded_in = row.get("recordedIn")
        if _non_empty(recorded_in):
            if resolve(recorded_in) is None:
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

    cited: dict[str, list[str]] = {}
    for entry in entries:
        entry_id = entry.get("id")
        label = f"traceability {entry_id}"
        if not isinstance(entry_id, str) or not SECURITY_ID.match(entry_id):
            violations.append(f"traceability: entry id {entry_id!r} is not SCHEDULING-SEC-NN")
            continue
        tests = entry.get("tests")
        if not isinstance(tests, list) or not tests:
            violations.append(f"{label}: at least one test must be cited")
            continue
        cited[entry_id] = []
        for test in tests:
            if not isinstance(test, dict):
                violations.append(f"{label}: every cited test is a path and name pair")
                continue
            cited[entry_id].append(str(test.get("name")))
            violations.extend(
                _cited_test_violations(label, test.get("path"), test.get("name"), resolve)
            )

    matrix_ids = {
        row.get("id") for row in matrix.get("invariants", []) if isinstance(row, dict)
    }
    for missing in sorted(matrix_ids - set(cited)):
        violations.append(f"traceability: invariant {missing} has no entry")
    for extra in sorted(set(cited) - matrix_ids):
        violations.append(f"traceability: entry {extra} matches no matrix invariant")
    return violations


def decisions_violations(decisions: dict, resolve: TextResolver) -> list[str]:
    violations: list[str] = []
    if decisions.get("apiVersion") != CONTRACT_API_VERSION:
        violations.append(f"decisions: apiVersion must be {CONTRACT_API_VERSION}")
    if not _non_empty(decisions.get("purpose")):
        violations.append("decisions: purpose is required and empty")
    entries = decisions.get("decisions")
    if not isinstance(entries, list) or not entries:
        return violations + ["decisions: no decisions listed"]

    seen: set[str] = set()
    for row in entries:
        row_id = row.get("id")
        label = f"decision {row_id}"
        if not isinstance(row_id, str) or not DECISION_ID.match(row_id):
            violations.append(f"decisions: id {row_id!r} is not SCHEDULING-DEC-NN")
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


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    contracts = root / "products" / "scheduling" / "contracts"

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

    if failures:
        for failure in failures:
            print(f"contracts: {failure}", file=sys.stderr)
        return 1
    print("Scheduling product contracts are internally consistent and source-mapped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
