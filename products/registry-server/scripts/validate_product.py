#!/usr/bin/env python3
"""Validate Registry Server's tracked product-contract catalog.

This deliberately validates only product-owned, declarative relationships. The
compiler will own configuration semantics and generated artifact correctness.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError as exc:  # pragma: no cover - environment failure
    raise SystemExit("PyYAML is required to validate Registry Server contracts") from exc


PRODUCT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PRODUCT_ROOT.parents[1]
CONTRACTS = PRODUCT_ROOT / "contracts"
IDENTIFIER = re.compile(r"^[A-Z][A-Z0-9-]+$")
WAVE = re.compile(r"^W[0-9]+$")
PLACEHOLDER = re.compile(r"\b(?:TODO|TBD|FIXME|placeholder)\b", re.IGNORECASE)
CONTRACT_STATES = {"enforced", "partial", "planned"}
V1_REQUIREMENT_IDS = tuple(f"RS-V1-{index:02d}" for index in range(1, 45))
ACCEPTANCE_JOURNEY_IDS = tuple(f"RS-J{index:02d}" for index in range(1, 18))
ACCEPTANCE_FIXTURES = {
    "RS-J01": ("asset-site-placement", "acceptance/asset-site-placement"),
    "RS-J02": ("asset-site-placement", "acceptance/asset-site-placement"),
    "RS-J03": ("business-establishments", "acceptance/business-establishments"),
    "RS-J04": ("inspection", "acceptance/inspection"),
    "RS-J05": ("facility", "acceptance/facility"),
    "RS-J06": ("business", "acceptance/business"),
}
RUST_TEST = re.compile(
    r"#\[(?:tokio::)?test(?:\([^\]]*\))?\]"
    r"(?:\s*#\[[^\]]+\])*\s*(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)
PACKAGE_LAYOUT_ENTRIES = {
    ("package.json", "identity", True),
    ("effective-model.json", "governed-model", True),
    ("inventories/physical-names.json", "physical-name-inventory", True),
    ("inventories/routes.json", "route-inventory", True),
    ("inventories/access.json", "access-inventory", True),
    ("inventories/queries.json", "query-inventory", True),
    ("inventories/events.json", "event-inventory", True),
    ("metadata/registry.json", "caller-safe-metadata", True),
    ("database/ddl.sql", "generated-ddl", True),
    ("database/migration-plan.json", "migration-plan", True),
    ("openapi/openapi.json", "generated-openapi", True),
    ("schemas", "entity-json-schemas", True),
    ("manifest/registry-manifest.json", "lossy-manifest-projection", False),
    ("manifest/dcat.jsonld", "dcat-catalog-projection", False),
    ("source/modules/<module-id>/<relative-sql-path>", "source-module-asset", False),
    ("tests/journeys.yaml", "fixture-journeys", True),
    ("signatures", "package-signatures", False),
}
FORBIDDEN_EMBEDDED_ROLES = {
    "deployment-trust-anchor",
    "runtime-secret",
    "migration-credential",
    "signing-key",
}
POSTGRES_ENTRYPOINT = PRODUCT_ROOT / "scripts/test-postgres.sh"
POSTGRES_TEST_COMMANDS = (
    "cargo test --locked -p registry-server --features runtime --test http_auth",
    "cargo test --locked -p registry-server --features runtime --test http_read_only",
    "cargo test --locked -p registry-server --features runtime --test runtime_config",
    "cargo test --locked -p registry-server --features runtime --test startup_http",
    "cargo test --locked -p registry-server --features runtime --test startup_ordering",
    "cargo test --locked -p registry-server --features runtime,tooling --test fixture_tooling",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_kernel",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_compiled_schema",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_partial_unique",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_constraint_races",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_read",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_revision_http",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_mutation",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_webhook_outbox",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_webhook_delivery",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_batch",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_data_facility",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_data_export",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_change_requests",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_request_authority",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_request_receipts",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_request_upgrade_retention",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_request_events",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_request_queries",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_request_read_retention",
    "cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_request_activation",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_pilot_acceptance",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_tombstone_revision",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_package",
    "cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_migration",
    "cargo test --locked -p registry-server --features postgres-test,tooling --test postgres_fixture_journeys",
    "cargo test --locked -p registry-server --features postgres-test,tooling --test schema_fingerprint_rehearsal",
    "cargo test --locked -p registry-server --features postgres-test --test postgres_startup",
)
POSTGRES_TLS_ENTRYPOINT = PRODUCT_ROOT / "scripts/test-postgres-tls.sh"
POSTGRES_TLS_TEST_COMMAND = "cargo test --locked -p registry-server --features postgres-tls-test --test postgres_tls"
CI_WORKFLOW = REPOSITORY_ROOT / ".github/workflows/ci.yml"


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def as_mapping(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{label}: expected mapping")
        return {}
    return value


def as_list(value: Any, label: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{label}: expected sequence")
        return []
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str, errors: list[str]) -> None:
    missing = sorted(expected - value.keys())
    unknown = sorted(value.keys() - expected)
    if missing:
        errors.append(f"{label}: missing keys {', '.join(missing)}")
    if unknown:
        errors.append(f"{label}: unknown keys {', '.join(unknown)}")


def nonempty_string(value: Any, label: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label}: expected a non-empty string")


def relative_path(value: Any, label: str, errors: list[str]) -> bool:
    if not isinstance(value, str) or not value or value.startswith("/") or ".." in Path(value).parts:
        errors.append(f"{label}: expected a repository-relative path without parent traversal")
        return False
    return True


def no_placeholders(value: Any, label: str, errors: list[str]) -> None:
    if isinstance(value, str) and PLACEHOLDER.search(value):
        errors.append(f"{label}: contains prohibited placeholder text")
    elif isinstance(value, dict):
        for key, child in value.items():
            no_placeholders(child, f"{label}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            no_placeholders(child, f"{label}[{index}]", errors)


def unique_ids(items: list[Any], label: str, errors: list[str]) -> set[str]:
    result: set[str] = set()
    for index, raw in enumerate(items):
        item = as_mapping(raw, f"{label}[{index}]", errors)
        identifier = item.get("id")
        if not isinstance(identifier, str) or not IDENTIFIER.fullmatch(identifier):
            errors.append(f"{label}[{index}].id: expected an uppercase stable identifier")
            continue
        if identifier in result:
            errors.append(f"{label}: duplicate identifier {identifier}")
        result.add(identifier)
    return result


def executable_test_resolves(value: Any, label: str, errors: list[str]) -> None:
    test = as_mapping(value, label, errors)
    exact_keys(test, {"path", "name"}, label, errors)
    raw_path, name = test.get("path"), test.get("name")
    if not relative_path(raw_path, f"{label}.path", errors):
        return
    if not isinstance(name, str) or not name:
        errors.append(f"{label}.name: expected one exact executable name")
        return
    source = (REPOSITORY_ROOT / raw_path).resolve()
    try:
        source.relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        errors.append(f"{label}: test path escapes repository")
        return
    if not source.is_file():
        errors.append(f"{label}: test source does not exist: {raw_path}")
        return
    if source.suffix == ".rs":
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            errors.append(f"{label}.name: expected one exact Rust test name")
            return
        matches = RUST_TEST.findall(source.read_text(encoding="utf-8")).count(name)
    elif source.suffix == ".py":
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        except SyntaxError as exc:
            errors.append(f"{label}: cannot parse Python test source: {exc.msg}")
            return
        if not name.startswith("test_"):
            errors.append(f"{label}.name: Python executable tests must start with test_")
            return
        matches = python_test_definitions(tree).count(name)
    elif source.suffix == ".sh":
        matches = int(name == source.name and bool(source.stat().st_mode & 0o111))
    else:
        errors.append(f"{label}: executable path must end in .rs, .py, or .sh")
        return
    if matches != 1:
        errors.append(f"{label}: exact executable test does not resolve: {raw_path}::{name}")


def class_base_name(base: ast.expr) -> str | None:
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name):
        return f"{base.value.id}.{base.attr}"
    return None


def python_test_definitions(tree: ast.Module) -> list[str]:
    """Return top-level tests and direct methods of TestCase subclasses only."""
    testcase_classes: set[str] = set()
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    changed = True
    while changed:
        changed = False
        for node in classes:
            bases = {class_base_name(base) for base in node.bases}
            if node.name not in testcase_classes and (
                "TestCase" in bases or "unittest.TestCase" in bases or bool(bases & testcase_classes)
            ):
                testcase_classes.add(node.name)
                changed = True
    tests = [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    ]
    for node in classes:
        if node.name in testcase_classes:
            tests.extend(
                child.name
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name.startswith("test_")
            )
    return tests


def validate_schedule(errors: list[str]) -> set[str]:
    value = as_mapping(load_yaml(CONTRACTS / "implementation-schedule.yaml"), "schedule", errors)
    exact_keys(value, {"apiVersion", "product", "currentWave", "waves"}, "schedule", errors)
    if value.get("product") != "registry-server":
        errors.append("schedule: wrong product")
    current = value.get("currentWave")
    if not isinstance(current, str) or not WAVE.fullmatch(current):
        errors.append("schedule.currentWave: expected a wave identifier")
    waves = as_list(value.get("waves"), "schedule.waves", errors)
    identifiers: set[str] = set()
    for index, raw in enumerate(waves):
        wave = as_mapping(raw, f"schedule.waves[{index}]", errors)
        exact_keys(wave, {"id", "outcome", "exitCriteria"}, f"schedule.waves[{index}]", errors)
        identifier = wave.get("id")
        if not isinstance(identifier, str) or not WAVE.fullmatch(identifier):
            errors.append(f"schedule.waves[{index}].id: expected a wave identifier")
        elif identifier in identifiers:
            errors.append(f"schedule.waves: duplicate wave {identifier}")
        else:
            identifiers.add(identifier)
        nonempty_string(wave.get("outcome"), f"schedule.waves[{index}].outcome", errors)
        criteria = as_list(wave.get("exitCriteria"), f"schedule.waves[{index}].exitCriteria", errors)
        if not criteria or any(not isinstance(item, str) or not item for item in criteria):
            errors.append(f"schedule.waves[{index}].exitCriteria: expected non-empty identifiers")
    if current not in identifiers:
        errors.append("schedule.currentWave: does not name a declared wave")
    return identifiers


def validate_evidence(value: Any, label: str, errors: list[str]) -> None:
    evidence = as_list(value, label, errors)
    if not evidence:
        errors.append(f"{label}: expected at least one executable binding")
        return
    seen: set[tuple[Any, Any]] = set()
    for index, raw in enumerate(evidence):
        item = as_mapping(raw, f"{label}[{index}]", errors)
        binding = (repr(item.get("path")), repr(item.get("name")))
        if binding in seen:
            errors.append(f"{label}: duplicate executable binding {binding}")
        seen.add(binding)
        executable_test_resolves(item, f"{label}[{index}]", errors)


def validate_definition_of_done(waves: set[str], errors: list[str]) -> set[str]:
    value = as_mapping(load_yaml(CONTRACTS / "definition-of-done.yaml"), "definition of done", errors)
    exact_keys(value, {"apiVersion", "product", "requirements"}, "definition of done", errors)
    if value.get("product") != "registry-server":
        errors.append("definition of done: wrong product")
    requirements = as_list(value.get("requirements"), "definition of done.requirements", errors)
    identifiers = unique_ids(requirements, "definition of done.requirements", errors)
    v1_identifiers = [
        item.get("id")
        for item in requirements
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and re.fullmatch(r"RS-V1-[0-9]{2}", item["id"])
    ]
    if v1_identifiers != list(V1_REQUIREMENT_IDS):
        errors.append("definition of done: must contain RS-V1-01 through RS-V1-44 exactly once in order")
    for index, raw in enumerate(requirements):
        item = as_mapping(raw, f"definition of done.requirements[{index}]", errors)
        state = item.get("state")
        expected = {"id", "phase", "state", "doneWhen", "journeys"}
        if state in {"enforced", "partial"}:
            expected.add("evidence")
        if state in {"partial", "planned"}:
            expected.add("gap")
        exact_keys(item, expected, f"definition of done.requirements[{index}]", errors)
        phase = item.get("phase")
        if phase not in waves:
            errors.append(f"definition of done.requirements[{index}].phase: unknown wave")
        if state not in CONTRACT_STATES:
            errors.append(f"definition of done.requirements[{index}].state: expected enforced, partial, or planned")
        identifier = item.get("id")
        nonempty_string(item.get("doneWhen"), f"definition of done.requirements[{index}].doneWhen", errors)
        journeys = as_list(item.get("journeys"), f"definition of done.requirements[{index}].journeys", errors)
        if not journeys or any(not isinstance(journey, str) or not journey for journey in journeys):
            errors.append(f"definition of done.requirements[{index}].journeys: expected non-empty identifiers")
        if all(isinstance(journey, str) for journey in journeys) and len(journeys) != len(set(journeys)):
            errors.append(f"definition of done.requirements[{index}].journeys: duplicate identifier")
        if state in {"enforced", "partial"}:
            validate_evidence(item.get("evidence"), f"definition of done.requirements[{index}].evidence", errors)
        if state in {"partial", "planned"}:
            nonempty_string(item.get("gap"), f"definition of done.requirements[{index}].gap", errors)
    return identifiers


def validate_acceptance(errors: list[str]) -> set[str]:
    value = as_mapping(load_yaml(CONTRACTS / "acceptance-scenario-matrix.yaml"), "acceptance matrix", errors)
    exact_keys(value, {"apiVersion", "product", "scenarios"}, "acceptance matrix", errors)
    if value.get("product") != "registry-server":
        errors.append("acceptance matrix: wrong product")
    scenarios = as_list(value.get("scenarios"), "acceptance matrix.scenarios", errors)
    identifiers = unique_ids(scenarios, "acceptance matrix.scenarios", errors)
    ordered_identifiers = [item.get("id") for item in scenarios if isinstance(item, dict)]
    if ordered_identifiers != list(ACCEPTANCE_JOURNEY_IDS):
        errors.append("acceptance matrix: must contain RS-J01 through RS-J17 exactly once in order")
    for index, raw in enumerate(scenarios):
        item = as_mapping(raw, f"acceptance matrix.scenarios[{index}]", errors)
        identifier = item.get("id")
        state = item.get("state")
        expected = {"id", "state", "doneWhen"}
        if isinstance(identifier, str) and identifier in ACCEPTANCE_FIXTURES:
            expected.update({"domain", "fixture"})
        if state in {"enforced", "partial"}:
            expected.add("evidence")
        if state in {"partial", "planned"}:
            expected.add("gap")
        exact_keys(item, expected, f"acceptance matrix.scenarios[{index}]", errors)
        if state not in CONTRACT_STATES:
            errors.append(f"acceptance matrix.scenarios[{index}].state: expected enforced, partial, or planned")
        nonempty_string(item.get("doneWhen"), f"acceptance matrix.scenarios[{index}].doneWhen", errors)
        if state in {"enforced", "partial"}:
            validate_evidence(item.get("evidence"), f"acceptance matrix.scenarios[{index}].evidence", errors)
        if state in {"partial", "planned"}:
            nonempty_string(item.get("gap"), f"acceptance matrix.scenarios[{index}].gap", errors)
        expected_fixture = ACCEPTANCE_FIXTURES.get(identifier) if isinstance(identifier, str) else None
        if expected_fixture is not None:
            if (item.get("domain"), item.get("fixture")) != expected_fixture:
                errors.append(f"acceptance matrix.{identifier}: wrong coequal domain fixture binding")
            fixture = item.get("fixture")
            if relative_path(fixture, f"acceptance matrix.scenarios[{index}].fixture", errors):
                if not (PRODUCT_ROOT / str(fixture) / "registry.yaml").is_file():
                    errors.append(f"acceptance matrix.scenarios[{index}]: fixture is missing registry.yaml")
    return identifiers


def validate_artifacts(errors: list[str]) -> None:
    value = as_mapping(load_yaml(CONTRACTS / "artifact-inventory.yaml"), "artifact inventory", errors)
    exact_keys(value, {"apiVersion", "product", "artifacts"}, "artifact inventory", errors)
    artifacts = as_list(value.get("artifacts"), "artifact inventory.artifacts", errors)
    paths: set[str] = set()
    for index, raw in enumerate(artifacts):
        item = as_mapping(raw, f"artifact inventory.artifacts[{index}]", errors)
        exact_keys(item, {"path", "kind", "state"}, f"artifact inventory.artifacts[{index}]", errors)
        path = item.get("path")
        if not relative_path(path, f"artifact inventory.artifacts[{index}].path", errors):
            continue
        if path in paths:
            errors.append(f"artifact inventory: duplicate path {path}")
        paths.add(path)
        if item.get("state") not in {"authored", "planned"}:
            errors.append(f"artifact inventory.artifacts[{index}].state: expected authored or planned")
        if item.get("state") == "authored" and not (PRODUCT_ROOT / str(path)).exists():
            errors.append(f"artifact inventory: authored artifact is missing: {path}")
        nonempty_string(item.get("kind"), f"artifact inventory.artifacts[{index}].kind", errors)


def validate_package_layout(errors: list[str]) -> None:
    value = as_mapping(load_yaml(CONTRACTS / "package-layout.yaml"), "package layout", errors)
    exact_keys(value, {"apiVersion", "product", "packageVersion", "entries", "forbiddenEmbeddedRoles"}, "package layout", errors)
    entries = as_list(value.get("entries"), "package layout.entries", errors)
    paths: set[str] = set()
    inventory: set[tuple[str, str, bool]] = set()
    for index, raw in enumerate(entries):
        item = as_mapping(raw, f"package layout.entries[{index}]", errors)
        exact_keys(item, {"path", "role", "required"}, f"package layout.entries[{index}]", errors)
        path = item.get("path")
        if relative_path(path, f"package layout.entries[{index}].path", errors):
            if path in paths:
                errors.append(f"package layout: duplicate path {path}")
            paths.add(path)
        nonempty_string(item.get("role"), f"package layout.entries[{index}].role", errors)
        if not isinstance(item.get("required"), bool):
            errors.append(f"package layout.entries[{index}].required: expected boolean")
        elif isinstance(path, str) and isinstance(item.get("role"), str):
            inventory.add((path, item["role"], item["required"]))
    if inventory != PACKAGE_LAYOUT_ENTRIES:
        missing = sorted(PACKAGE_LAYOUT_ENTRIES - inventory)
        unexpected = sorted(inventory - PACKAGE_LAYOUT_ENTRIES)
        if missing:
            errors.append(f"package layout: missing required entry tuples {missing}")
        if unexpected:
            errors.append(f"package layout: unexpected entry tuples {unexpected}")
    forbidden = as_list(value.get("forbiddenEmbeddedRoles"), "package layout.forbiddenEmbeddedRoles", errors)
    if (
        any(not isinstance(role, str) for role in forbidden)
        or set(forbidden) != FORBIDDEN_EMBEDDED_ROLES
        or len(forbidden) != len(FORBIDDEN_EMBEDDED_ROLES)
    ):
        errors.append("package layout.forbiddenEmbeddedRoles: must equal the complete forbidden role set")


def validate_postgres_entrypoint(errors: list[str]) -> None:
    if not POSTGRES_ENTRYPOINT.is_file():
        errors.append("PostgreSQL entrypoint: scripts/test-postgres.sh is missing")
        return
    if not POSTGRES_ENTRYPOINT.stat().st_mode & 0o111:
        errors.append("PostgreSQL entrypoint: scripts/test-postgres.sh is not executable")
    source = POSTGRES_ENTRYPOINT.read_text(encoding="utf-8")
    required_fragments = (
        "${REGISTRY_SERVER_TEST_DATABASE_URL:-}",
        "REGISTRY_SERVER_TEST_DATABASE_URL must be set for PostgreSQL journeys.",
        "exit 2",
        "export CARGO_INCREMENTAL=0",
        "export CARGO_PROFILE_DEV_DEBUG=0",
        "export CARGO_PROFILE_TEST_DEBUG=0",
        'export RUSTC_WRAPPER="${RUSTC_WRAPPER-}"',
    )
    for fragment in required_fragments:
        if fragment not in source:
            errors.append(f"PostgreSQL entrypoint: missing required fail-closed setting {fragment!r}")
    cargo_commands = [line.strip() for line in source.splitlines() if line.lstrip().startswith("cargo ")]
    if cargo_commands != list(POSTGRES_TEST_COMMANDS):
        errors.append(
            "PostgreSQL entrypoint: must run exactly the owned locked HTTP, kernel, "
            "startup, compiled-schema, read, mutation, and package commands"
        )


def validate_postgres_tls_entrypoint(errors: list[str]) -> None:
    if not POSTGRES_TLS_ENTRYPOINT.is_file():
        errors.append("PostgreSQL TLS entrypoint: scripts/test-postgres-tls.sh is missing")
        return
    if not POSTGRES_TLS_ENTRYPOINT.stat().st_mode & 0o111:
        errors.append("PostgreSQL TLS entrypoint: scripts/test-postgres-tls.sh is not executable")
    source = POSTGRES_TLS_ENTRYPOINT.read_text(encoding="utf-8")
    required_fragments = (
        "mktemp -d /tmp/registry-server-postgres-tls.XXXXXX",
        "trap cleanup EXIT",
        "/tmp/registry-server-postgres-tls.*)",
        'rm -rf -- "$tls_dir"',
        "docker cp",
        'pg_ctl -D "$postgres_data_directory" reload',
        'pg_isready -q -d "$database_url"',
        "openssl x509 -req",
        "subjectAltName=DNS:%s",
        "REGISTRY_SERVER_TEST_TLS_CA_DER_PATH",
        "REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH",
        "REGISTRY_SERVER_TEST_TLS_WRONG_CA_DER_PATH",
        "REGISTRY_SERVER_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL",
        "export CARGO_INCREMENTAL=0",
        "export CARGO_PROFILE_DEV_DEBUG=0",
        "export CARGO_PROFILE_TEST_DEBUG=0",
        "export RUSTC_WRAPPER=",
    )
    for fragment in required_fragments:
        if fragment not in source:
            errors.append(f"PostgreSQL TLS entrypoint: missing required proof setting {fragment!r}")
    if "TMPDIR" in source:
        errors.append("PostgreSQL TLS entrypoint: temporary cleanup must be limited to /tmp")
    cargo_commands = [line.strip() for line in source.splitlines() if line.lstrip().startswith("cargo ")]
    if cargo_commands != [POSTGRES_TLS_TEST_COMMAND]:
        errors.append("PostgreSQL TLS entrypoint: must run exactly the owned locked postgres_tls command")
    if not CI_WORKFLOW.is_file():
        errors.append("PostgreSQL TLS entrypoint: CI workflow is missing")
        return
    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    required_workflow_fragments = (
        "ports:\n          - 5432/tcp",
        "DATABASE_PORT: ${{ job.services.postgres.ports['5432'] }}",
        "REGISTRY_SERVER_TEST_DATABASE_URL=postgresql://registry_server:registry_server_test@localhost:${DATABASE_PORT}/registry_server",
        "REGISTRY_SERVER_TEST_TLS_DATABASE_URL=postgresql://registry_server:registry_server_test@localhost:${DATABASE_PORT}/registry_server",
        "REGISTRY_SERVER_TEST_TLS_HOSTNAME_MISMATCH_DATABASE_URL=postgresql://registry_server:registry_server_test@127.0.0.1:${DATABASE_PORT}/registry_server",
        "POSTGRES_CONTAINER_ID: ${{ job.services.postgres.id }}",
        "TLS_CA_PEM_PATH: ${{ runner.temp }}/registry-server-postgres-trusted-ca.pem",
        "run: products/registry-server/scripts/test-postgres-tls.sh",
    )
    for fragment in required_workflow_fragments:
        if fragment not in workflow:
            errors.append(f"PostgreSQL TLS entrypoint: CI is missing required integration {fragment!r}")


def validate_security(waves: set[str], errors: list[str]) -> None:
    matrix = as_mapping(load_yaml(CONTRACTS / "security-invariant-matrix.yaml"), "security matrix", errors)
    traceability = as_mapping(load_yaml(CONTRACTS / "security-test-traceability.yaml"), "security traceability", errors)
    exact_keys(matrix, {"apiVersion", "product", "invariants"}, "security matrix", errors)
    exact_keys(traceability, {"apiVersion", "product", "traceability"}, "security traceability", errors)
    invariants = as_list(matrix.get("invariants"), "security matrix.invariants", errors)
    rows = {row.get("id"): row for row in invariants if isinstance(row, dict) and isinstance(row.get("id"), str)}
    unique_ids(invariants, "security matrix.invariants", errors)
    if set(rows) != {f"RS-SEC-{index:02d}" for index in range(1, 23)}:
        errors.append("security matrix: must contain the complete closed product invariant identifiers")
    negatives: set[str] = set()
    for index, raw in enumerate(invariants):
        item = as_mapping(raw, f"security matrix.invariants[{index}]", errors)
        state = item.get("state")
        if state == "planned":
            exact_keys(item, {"id", "state", "targetWave", "threat", "enforcementPoint", "refusal", "negativeId"}, f"security matrix.invariants[{index}]", errors)
        elif state == "enforced":
            exact_keys(item, {"id", "state", "targetWave", "threat", "enforcementPoint", "refusal", "negativeId", "negativeTest"}, f"security matrix.invariants[{index}]", errors)
            executable_test_resolves(item.get("negativeTest"), f"security matrix.invariants[{index}].negativeTest", errors)
        else:
            errors.append(f"security matrix.invariants[{index}].state: expected planned or enforced")
            continue
        if item.get("targetWave") not in waves:
            errors.append(f"security matrix.invariants[{index}].targetWave: unknown wave")
        for key in ("threat", "enforcementPoint", "refusal"):
            nonempty_string(item.get(key), f"security matrix.invariants[{index}].{key}", errors)
        negative = item.get("negativeId")
        if not isinstance(negative, str) or not IDENTIFIER.fullmatch(negative):
            errors.append(f"security matrix.invariants[{index}].negativeId: expected stable identifier")
        elif negative in negatives:
            errors.append(f"security matrix: duplicate negative identifier {negative}")
        else:
            negatives.add(negative)
    traces = as_list(traceability.get("traceability"), "security traceability.traceability", errors)
    unique_ids(traces, "security traceability.traceability", errors)
    trace_rows = {row.get("id"): row for row in traces if isinstance(row, dict) and isinstance(row.get("id"), str)}
    if set(trace_rows) != set(rows):
        errors.append("security traceability: must have one row for every invariant")
    for identifier, invariant in rows.items():
        trace = trace_rows.get(identifier)
        if not isinstance(trace, dict):
            continue
        state = invariant.get("state")
        expected = {"id", "state", "negativeId"} if state == "planned" else {"id", "state", "negativeId", "negativeTest"}
        exact_keys(trace, expected, f"security traceability.{identifier}", errors)
        if trace.get("state") != state or trace.get("negativeId") != invariant.get("negativeId"):
            errors.append(f"security traceability.{identifier}: lifecycle does not match invariant")
        if state == "enforced":
            executable_test_resolves(trace.get("negativeTest"), f"security traceability.{identifier}.negativeTest", errors)
            if trace.get("negativeTest") != invariant.get("negativeTest"):
                errors.append(f"security traceability.{identifier}: negative test does not match invariant")


def validate_fixture(errors: list[str]) -> None:
    fixture = PRODUCT_ROOT / "acceptance/asset-site-placement/registry.yaml"
    document = as_mapping(load_yaml(fixture), "asset fixture", errors)
    exact_keys(
        document,
        {
            "apiVersion",
            "kind",
            "registry",
            "package",
            "manifestProjection",
            "modules",
            "entities",
            "accessProfiles",
            "vocabularies",
        },
        "asset fixture",
        errors,
    )
    if document.get("apiVersion") != "registry.registrystack.org/v1alpha1" or document.get("kind") != "RegistryProject":
        errors.append("asset fixture: must identify the strict Registry Project authoring form")
    registry = as_mapping(document.get("registry"), "asset fixture.registry", errors)
    exact_keys(registry, {"id", "version", "defaultLanguage"}, "asset fixture.registry", errors)
    if registry.get("id") != "asset-site-placement":
        errors.append("asset fixture: wrong non-person project identity")
    package = as_mapping(document.get("package"), "asset fixture.package", errors)
    exact_keys(
        package,
        {"environment", "instanceId", "sequence", "sourceRevision"},
        "asset fixture.package",
        errors,
    )
    expected_package = {
        "environment": "acceptance",
        "instanceId": "asset-site-placement-acceptance",
        "sequence": 1,
        "sourceRevision": "asset-site-placement-acceptance-0.1.0",
    }
    if type(package.get("sequence")) is not int:
        errors.append("asset fixture.package.sequence: expected integer")
    if package != expected_package:
        errors.append("asset fixture.package: must equal the committed acceptance package identity")
    entities = as_list(document.get("entities"), "asset fixture.entities", errors)
    entity_ids = {item.get("id") for item in entities if isinstance(item, dict)}
    required_entities = {"asset-item", "asset-site", "asset-placement", "inspection-event"}
    if entity_ids != required_entities:
        errors.append("asset fixture: must declare exactly the complete non-person entity set")
    routes = {item.get("route") for item in entities if isinstance(item, dict)}
    if routes != {"assets", "sites", "placements", "inspections"}:
        errors.append("asset fixture: routes must be explicit and configuration-owned")
    create_only = [item for item in entities if isinstance(item, dict) and item.get("id") == "inspection-event"]
    if len(create_only) != 1 or create_only[0].get("mutationMode") != "create_only":
        errors.append("asset fixture: inspection event must prove create-only configuration")
    placement = next((item for item in entities if isinstance(item, dict) and item.get("id") == "asset-placement"), {})
    temporal = placement.get("temporal") if isinstance(placement, dict) else None
    if not isinstance(temporal, dict) or temporal.get("scopeFields") != ["asset"]:
        errors.append("asset fixture: placement must declare scoped valid-time")
    profiles = as_list(document.get("accessProfiles"), "asset fixture.accessProfiles", errors)
    if [profile.get("id") for profile in profiles if isinstance(profile, dict)] != [
        "asset-operator",
        "site-planner",
    ]:
        errors.append("asset fixture: must declare the exact two configured access profiles")


def validate_all() -> list[str]:
    errors: list[str] = []
    for contract in CONTRACTS.glob("*.yaml"):
        no_placeholders(load_yaml(contract), contract.name, errors)
    waves = validate_schedule(errors)
    requirements = validate_definition_of_done(waves, errors)
    journeys = validate_acceptance(errors)
    validate_artifacts(errors)
    validate_package_layout(errors)
    validate_postgres_entrypoint(errors)
    validate_postgres_tls_entrypoint(errors)
    validate_security(waves, errors)
    validate_fixture(errors)
    for requirement in as_list(load_yaml(CONTRACTS / "definition-of-done.yaml").get("requirements"), "definition requirements", errors):
        if isinstance(requirement, dict):
            for journey in requirement.get("journeys", []):
                if journey not in journeys:
                    errors.append(f"definition of done: {requirement.get('id')} references unknown journey {journey}")
    if "RS-W0-CONTRACTS" not in requirements:
        errors.append("definition of done: W0 contract requirement is missing")
    schedule = as_mapping(load_yaml(CONTRACTS / "implementation-schedule.yaml"), "schedule", errors)
    for index, raw_wave in enumerate(as_list(schedule.get("waves"), "schedule.waves", errors)):
        wave = as_mapping(raw_wave, f"schedule.waves[{index}]", errors)
        for criterion in as_list(wave.get("exitCriteria"), f"schedule.waves[{index}].exitCriteria", errors):
            if criterion not in requirements:
                errors.append(f"schedule.waves[{index}]: exit criterion does not resolve: {criterion}")
    return errors


def main() -> int:
    errors = validate_all()
    if errors:
        print("Registry Server product contract validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Registry Server product contracts are internally complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
