#!/usr/bin/env python3
"""Validate Relay V2 product catalogs and cross-file traceability.

Contract, runtime, source-schema, generation, fixture, and packaging semantics
belong to the shared Rust tooling. This script deliberately checks only the
tracked product catalog and the references that join those catalogs together.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - environment failure
    raise SystemExit("PyYAML is required to validate Relay V2 product catalogs") from exc


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PRODUCT_ROOT.parents[1]
PROJECTS = ("social-assistance", "business-registry", "civil-event")
INVALID_SOURCE_ROW_CLASSES = {
    "wrong-type",
    "missing-required",
    "unexpected-value",
    "excessive-size",
}
SIMPLE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RUST_TEST = re.compile(
    r"#\[(?:tokio::)?test(?:\([^\]]*\))?\]"
    r"(?:\s*#\[[^\]]+\])*\s*(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def mapping(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label}: expected mapping")
        return {}
    return value


def sequence(value: Any, label: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{label}: expected sequence")
        return []
    return value


def require_exact_keys(
    value: dict[str, Any], expected: set[str], label: str, errors: list[str]
) -> None:
    missing = sorted(expected - value.keys())
    unknown = sorted(value.keys() - expected)
    if missing:
        errors.append(f"{label}: missing keys {', '.join(missing)}")
    if unknown:
        errors.append(f"{label}: unknown keys {', '.join(unknown)}")


def executable_test_resolves(reference: Any, label: str, errors: list[str]) -> None:
    test = mapping(reference, label, errors)
    require_exact_keys(test, {"path", "name"}, label, errors)
    raw_path = test.get("path")
    name = test.get("name")
    if not isinstance(raw_path, str) or not raw_path.startswith("crates/"):
        errors.append(f"{label}: path must be a repository-relative crate source path")
        return
    if not isinstance(name, str) or not SIMPLE_IDENTIFIER.fullmatch(name):
        errors.append(f"{label}: name must be one exact Rust test function")
        return
    path = (REPOSITORY_ROOT / raw_path).resolve()
    try:
        path.relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        errors.append(f"{label}: path escapes the repository")
        return
    if not path.is_file():
        errors.append(f"{label}: test source does not exist: {raw_path}")
        return
    names = RUST_TEST.findall(path.read_text(encoding="utf-8"))
    if names.count(name) != 1:
        errors.append(f"{label}: exact executable test does not resolve: {raw_path}::{name}")


def journey_steps(errors: list[str]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for project_name in PROJECTS:
        project = PRODUCT_ROOT / "acceptance" / project_name
        for required in ("registry.yaml", "runtime.yaml", "fixture.sql", "expected-http.yaml"):
            if not (project / required).is_file():
                errors.append(f"{project_name}: missing required project file {required}")
        journey = mapping(load_yaml(project / "expected-http.yaml"), f"{project_name} journey", errors)
        authorizations = mapping(
            journey.get("authorizations"), f"{project_name} journey authorizations", errors
        )
        identifiers: set[str] = set()
        for index, raw in enumerate(
            sequence(journey.get("steps"), f"{project_name} journey steps", errors)
        ):
            step = mapping(raw, f"{project_name} journey step[{index}]", errors)
            identifier = step.get("id")
            if not isinstance(identifier, str) or not identifier or identifier in identifiers:
                errors.append(f"{project_name}: journey step ids must be unique and non-empty")
                continue
            identifiers.add(identifier)
            authorization = step.get("authorizationFixture")
            if authorization is not None and authorization not in authorizations:
                errors.append(
                    f"{project_name}: {identifier} references unknown authorization fixture {authorization}"
                )
        result[project_name] = identifiers
    return result


def validate_catalogs(errors: list[str]) -> None:
    layout = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/package-layout.yaml"), "package layout", errors
    )
    require_exact_keys(
        layout,
        {
            "schemaVersion",
            "product",
            "requiredDocuments",
            "requiredContracts",
            "acceptanceProjects",
            "projectFiles",
            "generatedFilesCommitted",
            "semanticHashSnapshotsCommitted",
            "generatedFilePolicy",
            "excludedInputs",
        },
        "package layout",
        errors,
    )
    expected_projects = {name: f"acceptance/{name}" for name in PROJECTS}
    actual_projects = {
        item.get("id"): item.get("path")
        for item in sequence(layout.get("acceptanceProjects"), "acceptance projects", errors)
        if isinstance(item, dict)
    }
    if actual_projects != expected_projects:
        errors.append(
            f"package layout: expected acceptance projects {expected_projects}, got {actual_projects}"
        )
    required_documents = set(
        sequence(layout.get("requiredDocuments"), "required documents", errors)
    )
    for required in {
        "CONCEPT.md",
        "DEFINITION-OF-DONE.md",
        "CONFIGURATION-EXAMPLES.md",
        "IMPLEMENTATION.md",
        "STANDARDS-ALIGNMENT.md",
    }:
        if required not in required_documents or not (PRODUCT_ROOT / required).is_file():
            errors.append(f"package layout: missing maintained document {required}")
    if layout.get("generatedFilesCommitted") is not False:
        errors.append("package layout: generated runtime files must not be committed")
    if layout.get("semanticHashSnapshotsCommitted") is not True:
        errors.append("package layout: reviewed semantic hash snapshots must be committed")

    inventory = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/artifact-inventory.yaml"),
        "artifact inventory",
        errors,
    )
    artifact_ids: set[str] = set()
    for index, raw in enumerate(
        sequence(inventory.get("artifacts"), "artifact inventory", errors)
    ):
        artifact = mapping(raw, f"artifact[{index}]", errors)
        required = {"id", "mediaType", "visibility", "source", "generated"}
        missing = required - artifact.keys()
        if missing:
            errors.append(f"artifact[{index}]: missing keys {', '.join(sorted(missing))}")
        identifier = artifact.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in artifact_ids:
            errors.append(f"artifact[{index}]: id must be unique and non-empty")
        else:
            artifact_ids.add(identifier)
    for required in {
        "openapi-full",
        "openapi-public",
        "representation-schema",
        "full-record-schema",
        "full-record-shacl",
        "semantic-model",
        "jsonld-context",
        "shacl-shape",
        "codelists",
        "capability-inventory",
        "audit-event-schema",
    }:
        if required not in artifact_ids:
            errors.append(f"artifact inventory: missing {required}")

    steps = journey_steps(errors)
    scenarios = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/acceptance-scenario-matrix.yaml"),
        "scenario matrix",
        errors,
    )
    expected_runner = "products/relay-v2/scripts/test-http.sh"
    if scenarios.get("execution") != expected_runner:
        errors.append(f"scenario matrix: execution must be {expected_runner}")
    runner = REPOSITORY_ROOT / expected_runner
    if not runner.is_file() or not os.access(runner, os.X_OK):
        errors.append("scenario matrix: executable HTTP journey runner is missing")
    scenario_ids: set[str] = set()
    covered: dict[str, set[str]] = {project: set() for project in PROJECTS}
    invalid_classes: dict[str, set[str]] = {project: set() for project in PROJECTS}
    for index, raw in enumerate(sequence(scenarios.get("scenarios"), "scenarios", errors)):
        scenario = mapping(raw, f"scenario[{index}]", errors)
        expected_keys = {"id", "project", "journeyStep", "assertion"}
        if "invalidSourceRowClass" in scenario:
            expected_keys.add("invalidSourceRowClass")
        require_exact_keys(scenario, expected_keys, f"scenario[{index}]", errors)
        identifier = scenario.get("id")
        project = scenario.get("project")
        step = scenario.get("journeyStep")
        if not isinstance(identifier, str) or not identifier or identifier in scenario_ids:
            errors.append(f"scenario[{index}]: id must be unique and non-empty")
        else:
            scenario_ids.add(identifier)
        if project not in steps or step not in steps.get(project, set()):
            errors.append(f"scenario[{index}]: does not resolve to an exact journey step")
        elif isinstance(step, str):
            covered[project].add(step)
        invalid_class = scenario.get("invalidSourceRowClass")
        if invalid_class is not None:
            if invalid_class not in INVALID_SOURCE_ROW_CLASSES:
                errors.append(f"scenario[{index}]: unknown invalid source-row class")
            elif project in invalid_classes:
                invalid_classes[project].add(invalid_class)
    for project in PROJECTS:
        if covered[project] != steps[project]:
            errors.append(f"scenario matrix: {project} journey coverage is not exact")
        if not invalid_classes[project]:
            errors.append(f"{project}: at least one invalid source-row refusal is required")
    covered_invalid_classes = set().union(*invalid_classes.values())
    if covered_invalid_classes != INVALID_SOURCE_ROW_CLASSES:
        errors.append(
            "acceptance journeys: invalid source-row classes must cover "
            + ", ".join(sorted(INVALID_SOURCE_ROW_CLASSES))
        )

    matrix = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/security-invariant-matrix.yaml"),
        "security invariant matrix",
        errors,
    )
    invariant_ids: set[str] = set()
    for index, raw in enumerate(
        sequence(matrix.get("invariants"), "security invariants", errors)
    ):
        invariant = mapping(raw, f"security invariant[{index}]", errors)
        require_exact_keys(
            invariant,
            {
                "id",
                "threat",
                "enforcementPoint",
                "negativeCase",
                "expected",
                "evidence",
                "tests",
            },
            f"security invariant[{index}]",
            errors,
        )
        identifier = invariant.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in invariant_ids:
            errors.append(f"security invariant[{index}]: id must be unique and non-empty")
        else:
            invariant_ids.add(identifier)
        tests = sequence(invariant.get("tests"), f"security invariant[{index}].tests", errors)
        if not tests:
            errors.append(f"security invariant[{index}]: exact executable tests are required")
        for test_index, test in enumerate(tests):
            executable_test_resolves(
                test, f"security invariant[{index}].tests[{test_index}]", errors
            )
        if any(str(value).strip().lower() in {"todo", "tbd"} for value in invariant.values()):
            errors.append(f"security invariant[{index}]: placeholder value is prohibited")
    if len(invariant_ids) < 10:
        errors.append("security invariant matrix: expected at least ten concrete invariants")

    baselines = mapping(
        load_yaml(PRODUCT_ROOT / "contracts/generated-baselines.yaml"),
        "generated baselines",
        errors,
    )
    if set(mapping(baselines.get("projects"), "generated baseline projects", errors)) != set(
        PROJECTS
    ):
        errors.append("generated baselines: all three acceptance projects must be present")


def validate_all() -> list[str]:
    errors: list[str] = []
    validate_catalogs(errors)
    return errors


def main() -> int:
    errors = validate_all()
    if errors:
        for error in errors:
            print(f"relay-v2 validation: {error}", file=sys.stderr)
        return 1
    print("relay-v2 product catalog validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
