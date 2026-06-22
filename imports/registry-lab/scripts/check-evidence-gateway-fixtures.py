#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate governed evidence binding fixtures used by lab smoke/release checks.

This is a declarative contract check for fixture/policy binding coverage. It is
not a substitute for live PDP runtime proof, which remains in smoke/release
checks that start the Lab services.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "config" / "evidence-gateway"
PROFILE_PATH = FIXTURE_ROOT / "odrl-enforcement-profile.v1.json"
REQUIRED_BINDINGS = {
    "combined-support-eligibility/v1",
    "birth-registration-evidence/v1",
    "birth-certificate-evidence/v1",
    "marriage-certificate-evidence/v1",
}
REQUIRED_PACK_IDS = {
    "combined-support-eligibility/v1": "combined-support-eligibility/v1",
    "birth-registration-evidence/v1": "birth-registration-evidence/v1",
    "birth-certificate-evidence/v1": "birth-certificate-evidence/v1",
    "marriage-certificate-evidence/v1": "marriage-certificate-evidence/v1",
}
MATCHING_MODE_STATUSES = {"implemented", "fixture_data_only", "not_implemented"}
MATCHING_MODE_NAMES = {"identifier", "demographic", "party_demographic"}
BASELINE_POLICY_ID = "lab.combined-support-eligibility.governed-evidence.v1"
BASELINE_POLICY_HASH = "sha256:77a93c25e2d8b3c734176a8646628af65dd2a50396f2710e2fc26c5847259e5c"
BASELINE_RELAY_CONFIGS = [
    ROOT / "config" / "relay" / "civil-registry-relay.yaml",
    ROOT / "config" / "relay" / "health-registry-relay.yaml",
    ROOT / "config" / "relay" / "social-protection-registry-relay.yaml",
    ROOT / "config" / "coolify" / "relay" / "civil-registry-relay.yaml",
    ROOT / "config" / "coolify" / "relay" / "health-registry-relay.yaml",
    ROOT / "config" / "coolify" / "relay" / "social-protection-registry-relay.yaml",
]
BASELINE_METADATA_FILES = [
    ROOT / "config" / "relay" / "civil-registry-relay.metadata.yaml",
    ROOT / "config" / "relay" / "health-registry-relay.metadata.yaml",
    ROOT / "config" / "relay" / "social-protection-registry-relay.metadata.yaml",
    ROOT / "config" / "coolify" / "relay" / "civil-registry-relay.metadata.yaml",
    ROOT / "config" / "coolify" / "relay" / "health-registry-relay.metadata.yaml",
    ROOT / "config" / "coolify" / "relay" / "social-protection-registry-relay.metadata.yaml",
]
REGISTRY_DATA_CONNECTION_RELAY_CONFIGS = {
    "civil": [
        ROOT / "config" / "relay" / "civil-registry-relay.yaml",
        ROOT / "config" / "coolify" / "relay" / "civil-registry-relay.yaml",
    ],
    "health": [
        ROOT / "config" / "relay" / "health-registry-relay.yaml",
        ROOT / "config" / "coolify" / "relay" / "health-registry-relay.yaml",
    ],
    "social_protection": [
        ROOT / "config" / "relay" / "social-protection-registry-relay.yaml",
        ROOT / "config" / "coolify" / "relay" / "social-protection-registry-relay.yaml",
    ],
}
WAVE_A_BINDINGS = {"birth-certificate-evidence/v1", "marriage-certificate-evidence/v1"}
LEGACY_REQUIRED_CASE_TYPES = {"success", "denial", "redaction", "credential", "audit"}
WAVE_A_REQUIRED_CASE_TYPES = {"success", "denial", "audit"}
PERMIT_CASE_TYPES = {"success", "redaction", "credential", "audit"}
REQUIRED_DENIAL_CODES = {
    "pdp.assurance_insufficient",
    "pdp.consent_required",
    "pdp.evidence_stale",
    "pdp.jurisdiction_not_permitted",
    "pdp.legal_basis_required",
    "pdp.purpose_not_permitted",
    "pdp.unsupported_policy_term",
}
FRESHNESS_REQUEST_KEYS = {
    "freshness_observed_at",
    "source_age",
    "source_age_seconds",
    "source_observed_at",
}
DENIAL_CODE_POLICY_TERM = {
    "pdp.assurance_insufficient": "registry:pdp:assurance",
    "pdp.consent_required": "registry:pdp:consent",
    "pdp.evidence_stale": "registry:pdp:source_age",
    "pdp.jurisdiction_not_permitted": "odrl:spatial",
    "pdp.legal_basis_required": "registry:pdp:legal_basis",
    "pdp.purpose_not_permitted": "odrl:purpose",
}
PRODUCTION_ODRL_CONSTRAINT_TERMS = {
    "odrl:purpose",
    "odrl:spatial",
}
PRODUCTION_PDP_GATE_TERMS = {
    "registry:pdp:assurance",
    "registry:pdp:checked_scope",
    "registry:pdp:consent",
    "registry:pdp:credential_format",
    "registry:pdp:legal_basis",
    "registry:pdp:redaction",
    "registry:pdp:relationship_purpose",
    "registry:pdp:requested_disclosure",
    "registry:pdp:route_identity",
    "registry:pdp:source_age",
    "registry:pdp:source_binding",
}
PRODUCTION_PROFILE_TERMS = PRODUCTION_ODRL_CONSTRAINT_TERMS | PRODUCTION_PDP_GATE_TERMS
LEGACY_LAB_ODRL_TERMS = {
    "registry:assuranceLevel",
    "registry:audit",
    "registry:freshnessSeconds",
    "registry:jurisdiction",
    "registry:legalBasis",
    "registry:redaction",
    "registry:sourceBinding",
}


def fail(message: str) -> None:
    raise SystemExit(f"evidence gateway fixture check failed: {message}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as fh:
            body = json.load(fh)
    except FileNotFoundError:
        fail(f"missing {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is not valid JSON: {exc}")
    if not isinstance(body, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return body


def canonical_policy_hash(policy: dict[str, Any]) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_no_private_internal_copy(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    require("registry-internal" not in text, f"{path.relative_to(ROOT)} mentions registry-internal")


def json_strings(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for entry in value for item in json_strings(entry)}
    if isinstance(value, dict):
        return {item for entry in value.values() for item in json_strings(entry)}
    return set()


def collect_left_operands(value: Any) -> set[str]:
    operands: set[str] = set()
    if isinstance(value, list):
        for entry in value:
            operands.update(collect_left_operands(entry))
    if isinstance(value, dict):
        left_operand = value.get("leftOperand")
        if isinstance(left_operand, str):
            operands.add(left_operand)
        for entry in value.values():
            operands.update(collect_left_operands(entry))
    return operands


def collect_constraints(value: Any) -> list[dict[str, Any]]:
    constraints: list[dict[str, Any]] = []
    if isinstance(value, list):
        for entry in value:
            constraints.extend(collect_constraints(entry))
    if isinstance(value, dict):
        left_operand = value.get("leftOperand")
        if isinstance(left_operand, str):
            constraints.append(value)
        for entry in value.values():
            constraints.extend(collect_constraints(entry))
    return constraints


def collect_keys(value: Any, keys: set[str], path: str = "$") -> list[str]:
    matches: list[str] = []
    if isinstance(value, list):
        for index, entry in enumerate(value):
            matches.extend(collect_keys(entry, keys, f"{path}[{index}]"))
    if isinstance(value, dict):
        for key, entry in value.items():
            next_path = f"{path}.{key}"
            if key in keys:
                matches.append(next_path)
            matches.extend(collect_keys(entry, keys, next_path))
    return matches


def leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def yaml_scalar(line: str, key: str) -> str | None:
    stripped = line.strip()
    prefix = f"{key}:"
    if stripped == prefix:
        return ""
    if stripped.startswith(f"{prefix} "):
        return stripped[len(prefix) + 1 :].strip().strip("'\"")
    return None


def yaml_section_has_key(path: Path, section: str, nested_key: str) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines()
    section_indent: int | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = leading_spaces(line)
        if section_indent is not None and indent <= section_indent:
            section_indent = None
        if section_indent is not None and stripped == f"{nested_key}:":
            return True
        if stripped == f"{section}:":
            section_indent = indent
    return False


def yaml_list_item_block(path: Path, section: str, item_id: str) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    section_indent: int | None = None
    item_indent: int | None = None
    block: list[str] = []
    collecting = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if collecting:
                block.append(line)
            continue
        indent = leading_spaces(line)
        if section_indent is not None and indent <= section_indent:
            break
        if section_indent is None:
            if stripped == f"{section}:":
                section_indent = indent
            continue
        if stripped.startswith("- id:"):
            if collecting and item_indent is not None and indent == item_indent:
                break
            if yaml_scalar(stripped[2:].strip(), "id") == item_id:
                collecting = True
                item_indent = indent
                block = [line]
                continue
        if collecting:
            block.append(line)
    return block


def yaml_block_scalar(block: list[str], key: str) -> str | None:
    for line in block:
        value = yaml_scalar(line, key)
        if value:
            return value
    return None


def collect_relay_entity_fields(path: Path) -> dict[str, set[str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    entities_indent: int | None = None
    current_entity: str | None = None
    fields_indent: int | None = None
    entity_indent: int | None = None
    fields_by_entity: dict[str, set[str]] = {}

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = leading_spaces(line)
        if entities_indent is not None and indent <= entities_indent:
            entities_indent = None
            current_entity = None
            fields_indent = None
        if entities_indent is None:
            if stripped == "entities:":
                entities_indent = indent
            continue
        if stripped.startswith("- name:") and indent == entities_indent + 2:
            current_entity = yaml_scalar(stripped[2:].strip(), "name")
            entity_indent = indent
            fields_indent = None
            if current_entity:
                fields_by_entity.setdefault(current_entity, set())
            continue
        if current_entity and entity_indent is not None and indent <= entity_indent and not stripped.startswith("- name:"):
            current_entity = None
            fields_indent = None
            continue
        if current_entity and stripped == "fields:":
            fields_indent = indent
            continue
        if current_entity and fields_indent is not None:
            if indent <= fields_indent:
                fields_indent = None
                continue
            if stripped.startswith("- name:"):
                field = yaml_scalar(stripped[2:].strip(), "name")
                if field:
                    fields_by_entity[current_entity].add(field)
    return fields_by_entity


def collect_notary_registry_freshness_sources(path: Path) -> list[tuple[str, str, str]]:
    current_connection: str | None = None
    current_entity: str | None = None
    sources: list[tuple[str, str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        connection = yaml_scalar(line, "connection")
        if connection:
            current_connection = connection
            current_entity = None
            continue
        entity = yaml_scalar(line, "entity")
        if entity and current_connection:
            current_entity = entity
            continue
        observed_at_field = yaml_scalar(line, "source_observed_at_field")
        if observed_at_field and current_connection in REGISTRY_DATA_CONNECTION_RELAY_CONFIGS and current_entity:
            sources.append((current_connection, current_entity, observed_at_field))
    return sources


def parse_timestamp(label: str, value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    require(isinstance(value, str), f"{label} must be an RFC3339 timestamp string")
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        fail(f"{label} must be an RFC3339 timestamp")
    if parsed.tzinfo is None:
        fail(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def source_observed_at(record: dict[str, Any]) -> datetime | None:
    if "observed_at" in record:
        return parse_timestamp(f"{record.get('id')} observed_at", record.get("observed_at"))
    metadata = record.get("source_metadata")
    require(isinstance(metadata, dict), f"{record.get('id')} missing source_metadata")
    require(metadata.get("freshness_source"), f"{record.get('id')} source_metadata missing freshness_source")
    require(metadata.get("freshness_source") != "request", f"{record.get('id')} must not use request freshness source")
    return parse_timestamp(f"{record.get('id')} source_metadata.observed_at", metadata.get("observed_at"))


def source_age_limit_seconds(policy_constraints: list[dict[str, Any]]) -> int | None:
    limits = [
        constraint.get("rightOperand")
        for constraint in policy_constraints
        if constraint.get("leftOperand") == "registry:pdp:source_age"
    ]
    if not limits:
        return None
    limit = limits[0]
    require(isinstance(limit, int) and limit >= 0, "registry:pdp:source_age rightOperand must be a non-negative integer")
    return limit


def collect_pdp_gates(evidence_pack: dict[str, Any]) -> list[dict[str, Any]]:
    gates = evidence_pack.get("pdp_gates") or []
    require(isinstance(gates, list), "evidence_pack.pdp_gates must be a list when present")
    normalized: list[dict[str, Any]] = []
    for gate in gates:
        require(isinstance(gate, dict), "evidence_pack.pdp_gates entries must be objects")
        term = gate.get("term")
        require(term in PRODUCTION_PDP_GATE_TERMS, f"evidence_pack.pdp_gates has unsupported term {term!r}")
        normalized.append(
            {
                "leftOperand": term,
                "operator": gate.get("operator", "odrl:isA"),
                "rightOperand": gate.get("rightOperand"),
            }
        )
    return normalized


def request_context_value(request: dict[str, Any], term: str) -> Any:
    if term == "odrl:purpose":
        return request.get("purpose")
    if term == "odrl:spatial":
        return request.get("jurisdiction")
    if term == "registry:pdp:assurance":
        return request.get("assurance_level")
    if term == "registry:pdp:checked_scope":
        return request.get("checked_scopes")
    if term == "registry:pdp:consent":
        return request.get("consent_ref")
    if term == "registry:pdp:credential_format":
        return request.get("format")
    if term == "registry:pdp:legal_basis":
        return request.get("legal_basis_ref")
    if term == "registry:pdp:redaction":
        return request.get("redaction")
    if term == "registry:pdp:requested_disclosure":
        return request.get("disclosure")
    if term == "registry:pdp:route_identity":
        return request.get("route_identity")
    if term == "registry:pdp:source_binding":
        return request.get("source_binding")
    return None


def validate_request_context(
    case_id: str,
    request: dict[str, Any],
    policy_constraints: list[dict[str, Any]],
    *,
    skip_term: str | None = None,
) -> None:
    for constraint in policy_constraints:
        term = constraint.get("leftOperand")
        if term == skip_term or term == "registry:pdp:source_age":
            continue
        expected = constraint.get("rightOperand")
        actual = request_context_value(request, term)
        if term == "registry:pdp:checked_scope" and isinstance(actual, list):
            require(expected in actual, f"{case_id} request checked_scopes must include policy-required {expected!r}")
        else:
            require(actual == expected, f"{case_id} request {term} must match policy-required context {expected!r}")


def validate_fresh_source_records(
    case_id: str,
    records: list[dict[str, Any]],
    reference_time: datetime,
    max_age_seconds: int,
) -> None:
    for record in records:
        observed_at = source_observed_at(record)
        require(observed_at is not None, f"{case_id} positive source record {record.get('id')} missing observed_at")
        age_seconds = (reference_time - observed_at).total_seconds()
        require(age_seconds >= 0, f"{case_id} source record {record.get('id')} observed_at is in the future")
        require(age_seconds <= max_age_seconds, f"{case_id} source record {record.get('id')} is stale")


def freshness_failure_mode(
    case_id: str,
    records: list[dict[str, Any]],
    reference_time: datetime,
    max_age_seconds: int,
) -> str:
    observed_values = [source_observed_at(record) for record in records]
    if any(observed_at is None for observed_at in observed_values):
        return "missing_timestamp"
    if any((reference_time - observed_at).total_seconds() > max_age_seconds for observed_at in observed_values if observed_at):
        return "stale_timestamp"
    fail(f"{case_id} expects pdp.evidence_stale but referenced source metadata is fresh")


def validate_production_odrl_terms(label: str, value: Any) -> None:
    legacy_terms = sorted(json_strings(value) & LEGACY_LAB_ODRL_TERMS)
    require(not legacy_terms, f"{label} uses legacy lab ODRL terms: {', '.join(legacy_terms)}")


def validate_relay_metadata_contracts() -> None:
    for path in BASELINE_RELAY_CONFIGS:
        text = path.read_text(encoding="utf-8")
        label = str(path.relative_to(ROOT))
        require("ecosystem_binding:" in text, f"{label} must select combined-support-eligibility/v1 metadata ecosystem binding")
        require("id: combined-support-eligibility/v1" in text, f"{label} must select combined-support-eligibility/v1 metadata ecosystem binding")
        require("version: v1" in text, f"{label} must select combined-support-eligibility/v1 version v1")

    for path in BASELINE_METADATA_FILES:
        label = str(path.relative_to(ROOT))
        block = yaml_list_item_block(path, "ecosystem_bindings", "combined-support-eligibility/v1")
        require(block, f"{label} missing combined-support-eligibility/v1 ecosystem binding")
        require(
            yaml_block_scalar(block, "policy_id") == BASELINE_POLICY_ID,
            f"{label} combined-support-eligibility/v1 policy_id must match evidence-gateway binding fixture",
        )
        require(
            yaml_block_scalar(block, "policy_hash") == BASELINE_POLICY_HASH,
            f"{label} combined-support-eligibility/v1 policy_hash must match evidence-gateway binding fixture",
        )

    for path in sorted((ROOT / "config" / "relay").glob("*.metadata.yaml")) + sorted(
        (ROOT / "config" / "coolify" / "relay").glob("*.metadata.yaml")
    ):
        text = path.read_text(encoding="utf-8")
        label = str(path.relative_to(ROOT))
        require("output_profile:" not in text, f"{label} uses output_profile, which Manifest drops from relay metadata")
        require(
            not yaml_section_has_key(path, "evidence_offerings", "evidence_pack"),
            f"{label} has evidence_offerings.evidence_pack, which Manifest drops from relay metadata",
        )


def validate_registry_data_freshness_projection() -> None:
    relay_fields_by_connection = {
        connection: [collect_relay_entity_fields(path) for path in paths]
        for connection, paths in REGISTRY_DATA_CONNECTION_RELAY_CONFIGS.items()
    }
    notary_paths = sorted((ROOT / "config" / "notary").glob("*.yaml")) + sorted(
        (ROOT / "config" / "coolify" / "notary").glob("*.yaml")
    )
    for path in notary_paths:
        for connection, entity, observed_at_field in collect_notary_registry_freshness_sources(path):
            for relay_fields in relay_fields_by_connection[connection]:
                require(
                    observed_at_field in relay_fields.get(entity, set()),
                    (
                        f"{path.relative_to(ROOT)} requires {connection}.{entity}.{observed_at_field} "
                        "for source freshness, but the paired relay entity does not project it"
                    ),
                )


def validate_pack_metadata(binding_id: str, evidence_pack: dict[str, Any]) -> tuple[str, str]:
    pack_id = evidence_pack.get("pack_id")
    expected_pack_id = REQUIRED_PACK_IDS.get(binding_id)
    require(isinstance(pack_id, str) and pack_id, f"{binding_id} missing pack_id")
    require(pack_id == expected_pack_id, f"{binding_id} pack_id must be {expected_pack_id!r}")
    require(evidence_pack.get("pack_version") == "v1", f"{binding_id} pack_version must be v1")
    require(
        isinstance(evidence_pack.get("pack_title"), str) and evidence_pack["pack_title"],
        f"{binding_id} missing pack_title",
    )
    source_basis = evidence_pack.get("source_basis")
    require(isinstance(source_basis, dict), f"{binding_id} missing source_basis")
    require(
        isinstance(source_basis.get("family"), str) and source_basis["family"],
        f"{binding_id} source_basis.family missing",
    )
    require(
        isinstance(source_basis.get("evidence_type"), str) and source_basis["evidence_type"],
        f"{binding_id} source_basis.evidence_type missing",
    )
    require(
        isinstance(source_basis.get("adaptation"), str) and source_basis["adaptation"],
        f"{binding_id} source_basis.adaptation missing",
    )

    matching_modes = evidence_pack.get("matching_modes")
    require(isinstance(matching_modes, list) and matching_modes, f"{binding_id} missing matching_modes")
    implemented = 0
    mode_summaries: list[str] = []
    for mode in matching_modes:
        require(isinstance(mode, dict), f"{binding_id} matching_modes entries must be objects")
        mode_name = mode.get("mode")
        status = mode.get("status")
        require(mode_name in MATCHING_MODE_NAMES, f"{binding_id} has unsupported matching mode {mode_name!r}")
        require(status in MATCHING_MODE_STATUSES, f"{binding_id} has unsupported matching mode status {status!r}")
        require(
            isinstance(mode.get("input"), str) and mode["input"],
            f"{binding_id} {mode_name} matching mode missing input",
        )
        if status == "implemented":
            implemented += 1
            require(
                isinstance(mode.get("identifier_scheme"), str) and mode["identifier_scheme"],
                f"{binding_id} implemented matching mode must name identifier_scheme",
            )
        else:
            require(
                isinstance(mode.get("reason"), str) and mode["reason"],
                f"{binding_id} non-implemented matching mode missing reason",
            )
        mode_summaries.append(f"{mode_name}:{status}")
    require(implemented > 0, f"{binding_id} must have at least one implemented matching mode")
    return pack_id, "/".join(mode_summaries)


def validate_binding(path: Path, profile: dict[str, Any]) -> tuple[str, str, str]:
    require_no_private_internal_copy(path)
    binding_doc = load_json(path)
    validate_production_odrl_terms(path.name, binding_doc)
    binding = binding_doc.get("binding")
    evidence_pack = binding_doc.get("evidence_pack")
    odrl_policy = binding_doc.get("odrl_policy")
    require(isinstance(binding, dict), f"{path.name} missing binding object")
    require(isinstance(evidence_pack, dict), f"{path.name} missing evidence_pack object")
    require(isinstance(odrl_policy, dict), f"{path.name} missing odrl_policy object")

    binding_id = binding.get("id")
    binding_version = binding.get("version")
    require(binding_id in REQUIRED_BINDINGS, f"{path.name} has unexpected binding id {binding_id!r}")
    require(binding_version == "v1", f"{binding_id} must be version v1")
    require(binding.get("type") == "governed-evidence", f"{binding_id} must be governed-evidence")
    pack_id, matching_summary = validate_pack_metadata(binding_id, evidence_pack)

    policy_id = evidence_pack.get("policy_id")
    policy_hash = evidence_pack.get("policy_hash")
    require(isinstance(policy_id, str) and policy_id, f"{binding_id} missing policy_id")
    require(policy_hash == canonical_policy_hash(odrl_policy), f"{binding_id} policy_hash does not match odrl_policy")

    enforcement = evidence_pack.get("odrl_enforcement")
    require(isinstance(enforcement, dict), f"{binding_id} missing odrl_enforcement")
    require(enforcement.get("profile") == profile.get("id"), f"{binding_id} uses wrong ODRL enforcement profile")
    require(enforcement.get("unsupported_terms_fail_closed") is True, f"{binding_id} must fail closed on unsupported ODRL terms")
    require("supported_terms" not in enforcement, f"{binding_id} must use production constraint_terms, not supported_terms")
    constraint_terms = set(enforcement.get("constraint_terms") or [])
    profile_terms = set(profile.get("supported_terms") or [])
    require(bool(constraint_terms), f"{binding_id} must declare constraint_terms")
    require(
        constraint_terms <= profile_terms,
        f"{binding_id} declares ODRL constraint terms outside the production profile",
    )
    require(
        constraint_terms <= PRODUCTION_ODRL_CONSTRAINT_TERMS,
        f"{binding_id} declares registry-specific PDP terms as ODRL constraint terms",
    )
    policy_terms = collect_left_operands(odrl_policy)
    registry_policy_terms = sorted(policy_terms & PRODUCTION_PDP_GATE_TERMS)
    require(
        not registry_policy_terms,
        f"{binding_id} ODRL policy uses registry-specific PDP terms: {', '.join(registry_policy_terms)}",
    )
    require(
        policy_terms <= constraint_terms,
        f"{binding_id} policy uses undeclared ODRL constraint terms: {', '.join(sorted(policy_terms - constraint_terms))}",
    )
    policy_constraints = collect_constraints(odrl_policy) + collect_pdp_gates(evidence_pack)

    for key in ("synthetic_data", "golden_fixtures"):
        relative = binding.get(key)
        require(isinstance(relative, str) and relative, f"{binding_id} missing {key}")
        require((ROOT / relative).is_file(), f"{binding_id} references missing {relative}")
    for relative in binding.get("source_configs") or []:
        require((ROOT / relative).is_file(), f"{binding_id} references missing source config {relative}")

    synthetic_path = ROOT / binding["synthetic_data"]
    golden_path = ROOT / binding["golden_fixtures"]
    synthetic_records = validate_synthetic(synthetic_path, binding_id)
    validate_golden(
        golden_path,
        binding_id,
        binding_version,
        policy_id,
        policy_hash,
        synthetic_records,
        policy_constraints,
    )
    return binding_id, pack_id, matching_summary


def validate_synthetic(path: Path, binding_id: str) -> dict[str, dict[str, Any]]:
    require_no_private_internal_copy(path)
    synthetic = load_json(path)
    require(synthetic.get("binding_id") == binding_id, f"{path.name} binding_id mismatch")
    records = synthetic.get("records")
    require(isinstance(records, list) and records, f"{path.name} must contain records")
    ids = [record.get("id") for record in records if isinstance(record, dict)]
    require(len(ids) == len(records), f"{path.name} has a record without id")
    require(len(ids) == len(set(ids)), f"{path.name} record ids must be unique")
    records_by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        require(isinstance(record, dict), f"{path.name} contains non-object record")
        source_observed_at(record)
        records_by_id[record["id"]] = record
    return records_by_id


def validate_golden(
    path: Path,
    binding_id: str,
    binding_version: str,
    policy_id: str,
    policy_hash: str,
    synthetic_records: dict[str, dict[str, Any]],
    policy_constraints: list[dict[str, Any]],
) -> None:
    require_no_private_internal_copy(path)
    golden = load_json(path)
    require(golden.get("binding_id") == binding_id, f"{path.name} binding_id mismatch")
    require(golden.get("policy_id") == policy_id, f"{path.name} policy_id mismatch")
    require(golden.get("policy_hash") == policy_hash, f"{path.name} policy_hash mismatch")
    reference_time = parse_timestamp(f"{path.name} freshness_reference_time", golden.get("freshness_reference_time"))
    require(reference_time is not None, f"{path.name} missing freshness_reference_time")
    max_age_seconds = source_age_limit_seconds(policy_constraints)
    cases = golden.get("cases")
    require(isinstance(cases, list) and cases, f"{path.name} must contain cases")
    case_types = {case.get("type") for case in cases if isinstance(case, dict)}
    required_case_types = WAVE_A_REQUIRED_CASE_TYPES if binding_id in WAVE_A_BINDINGS else LEGACY_REQUIRED_CASE_TYPES
    missing = required_case_types - case_types
    require(not missing, f"{path.name} missing case types: {', '.join(sorted(missing))}")

    case_ids: set[str] = set()
    denial_codes: set[str] = set()
    freshness_failure_modes: set[str] = set()
    for case in cases:
        require(isinstance(case, dict), f"{path.name} contains non-object case")
        case_id = case.get("id")
        case_type = case.get("type")
        require(isinstance(case_id, str) and case_id, f"{path.name} has case without id")
        require(case_id not in case_ids, f"{path.name} duplicate case id {case_id}")
        case_ids.add(case_id)
        require(case_type in LEGACY_REQUIRED_CASE_TYPES, f"{case_id} has unsupported case type {case_type!r}")
        synthetic_data_refs = case.get("synthetic_data_refs")
        require(synthetic_data_refs, f"{case_id} must name synthetic_data_refs")
        require(isinstance(synthetic_data_refs, list), f"{case_id} synthetic_data_refs must be a list")
        case_records: list[dict[str, Any]] = []
        for ref in synthetic_data_refs:
            require(ref in synthetic_records, f"{case_id} references unknown synthetic data {ref!r}")
            case_records.append(synthetic_records[ref])
        request = case.get("request")
        expected = case.get("expected")
        require(isinstance(request, dict), f"{case_id} missing request")
        require(isinstance(expected, dict), f"{case_id} missing expected")
        require(request.get("binding_id") == binding_id, f"{case_id} request binding_id mismatch")
        request_freshness_keys = collect_keys(request, FRESHNESS_REQUEST_KEYS)
        require(
            not request_freshness_keys,
            f"{case_id} must not provide request-supplied freshness keys: {', '.join(request_freshness_keys)}",
        )
        audit = expected.get("audit")
        require(isinstance(audit, dict), f"{case_id} expected audit missing")
        require(audit.get("binding_id") == binding_id, f"{case_id} audit binding_id mismatch")
        require(audit.get("policy_id") == policy_id, f"{case_id} audit policy_id mismatch")
        if case_type in PERMIT_CASE_TYPES:
            validate_request_context(case_id, request, policy_constraints)
            if max_age_seconds is not None:
                validate_fresh_source_records(case_id, case_records, reference_time, max_age_seconds)
        if case_type in {"success", "audit"}:
            require(audit.get("policy_hash") == policy_hash, f"{case_id} audit policy_hash mismatch")
            require(audit.get("binding_version") == binding_version, f"{case_id} audit binding_version mismatch")
            require(audit.get("evaluated_rule_ids"), f"{case_id} audit must include evaluated_rule_ids")
        if case_type == "denial":
            problem = expected.get("problem")
            require(isinstance(problem, dict), f"{case_id} denial missing problem")
            code = problem.get("code")
            require(code in REQUIRED_DENIAL_CODES, f"{case_id} denial code must be one of the stable PDP codes")
            denial_codes.add(code)
            validate_request_context(case_id, request, policy_constraints, skip_term=DENIAL_CODE_POLICY_TERM.get(code))
            if code == "pdp.evidence_stale":
                require(max_age_seconds is not None, f"{case_id} expects freshness denial but policy has no source_age limit")
                freshness_failure_modes.add(freshness_failure_mode(case_id, case_records, reference_time, max_age_seconds))
                require(
                    expected.get("zero_source_reads") is False,
                    f"{case_id} stale source freshness denial must not claim zero_source_reads",
                )
            else:
                require(expected.get("zero_source_reads") is True, f"{case_id} denial must assert zero_source_reads")
            if code == "pdp.unsupported_policy_term":
                unsupported_terms = set(request.get("odrl_terms") or [])
                require(bool(unsupported_terms - PRODUCTION_PROFILE_TERMS), f"{case_id} must name an unsupported ODRL term")
        if case_type == "redaction":
            require(expected.get("absent_fields"), f"{case_id} redaction must list absent_fields")
            require(audit.get("redacted_fields"), f"{case_id} redaction audit must list redacted_fields")
        if case_type == "credential":
            require(binding_id not in WAVE_A_BINDINGS, f"{case_id} Wave A fixtures must not cover deferred SD-JWT credentials")
            require(expected.get("credential_format") == "application/dc+sd-jwt", f"{case_id} must cover SD-JWT VC credential format")
    if binding_id in WAVE_A_BINDINGS:
        required_denial_codes = {"pdp.purpose_not_permitted", "pdp.jurisdiction_not_permitted"}
        allowed_denial_codes = required_denial_codes
    elif binding_id == "combined-support-eligibility/v1":
        required_denial_codes = REQUIRED_DENIAL_CODES - {"pdp.jurisdiction_not_permitted"}
        allowed_denial_codes = required_denial_codes
    else:
        required_denial_codes = REQUIRED_DENIAL_CODES
        allowed_denial_codes = REQUIRED_DENIAL_CODES
    missing_denials = required_denial_codes - denial_codes
    unexpected_denials = denial_codes - allowed_denial_codes
    require(not missing_denials, f"{path.name} missing denial codes: {', '.join(sorted(missing_denials))}")
    require(not unexpected_denials, f"{path.name} has unexpected denial codes: {', '.join(sorted(unexpected_denials))}")
    if max_age_seconds is not None and binding_id not in WAVE_A_BINDINGS:
        missing_modes = {"missing_timestamp", "stale_timestamp"} - freshness_failure_modes
        require(not missing_modes, f"{path.name} missing freshness denial modes: {', '.join(sorted(missing_modes))}")


def main() -> int:
    profile = load_json(PROFILE_PATH)
    validate_production_odrl_terms(PROFILE_PATH.name, profile)
    require(profile.get("id") == "registry-evidence-gateway-pdp/v1", "unexpected ODRL enforcement profile id")
    require(profile.get("unsupported_terms_fail_closed") is True, "ODRL profile must fail closed on unsupported terms")
    profile_terms = set(profile.get("supported_terms") or [])
    missing_terms = PRODUCTION_PROFILE_TERMS - profile_terms
    extra_terms = profile_terms - PRODUCTION_PROFILE_TERMS
    require(not missing_terms, f"ODRL profile missing production terms: {', '.join(sorted(missing_terms))}")
    require(not extra_terms, f"ODRL profile has non-production terms: {', '.join(sorted(extra_terms))}")

    binding_paths = sorted((FIXTURE_ROOT / "bindings").glob("*.json"))
    validated_bindings = [validate_binding(path, profile) for path in binding_paths]
    found = {binding_id for binding_id, _, _ in validated_bindings}
    missing = REQUIRED_BINDINGS - found
    require(not missing, f"missing binding fixtures: {', '.join(sorted(missing))}")
    validate_relay_metadata_contracts()
    validate_registry_data_freshness_projection()
    pack_summary = ", ".join(
        f"{binding_id}->{pack_id} [{matching_summary}]"
        for binding_id, pack_id, matching_summary in sorted(validated_bindings)
    )
    print(f"evidence gateway fixtures OK: {', '.join(sorted(found))}")
    print(f"pack identity and matching modes OK: {pack_summary}")
    print("relay metadata binding selectors OK: local and hosted combined-support-eligibility/v1 selectors are aligned")
    print("relay metadata policy hashes OK: combined-support-eligibility/v1 matches the evidence-gateway binding fixture")
    print("manifest metadata shape OK: ignored output_profile and offering evidence_pack fields are absent")
    print("registry-data freshness projections OK: Notary observed_at fields are exposed by paired Relay entities")
    print(f"production enforcement profile terms OK: {', '.join(sorted(PRODUCTION_PROFILE_TERMS))}")
    print("registry-specific PDP gates OK: absent from ODRL policy constraints")
    print(f"stable PDP denial codes OK: {', '.join(sorted(REQUIRED_DENIAL_CODES))}")
    print("freshness source metadata OK: request-supplied freshness keys are forbidden")
    print("freshness denial modes OK: missing_timestamp, stale_timestamp")
    print("declarative binding contract OK; live PDP runtime proof is not executed by this checker")
    return 0


if __name__ == "__main__":
    sys.exit(main())
