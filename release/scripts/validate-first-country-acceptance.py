#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate redaction-safe first-country acceptance records.

The validator checks only the closed public record. Restricted evidence,
authority, and the facts committed by evidence digests remain the
responsibility of the named owner roles and publication reviewer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path
from typing import Any

from closed_json_schema import (
    SchemaValidationError,
    validate_against_schema as validate_closed_schema,
)


ROOT = Path(__file__).resolve().parents[2]
PACKET_DIR = ROOT / "release" / "conformance" / "first-country"
SCHEMA_PATH = PACKET_DIR / "acceptance-record.schema.json"
TEMPLATE_PATH = PACKET_DIR / "acceptance-record.template.json"
SCHEMA_VERSION = "registry.release.first_country_acceptance.v1"
ZERO_SHA256 = "sha256:" + "0" * 64
ZERO_COMMIT = "0" * 40
MAX_RECORD_BYTES = 512 * 1024

LIMITATIONS = (
    "bounded-non-production-only",
    "exact-candidate-only",
    "exact-project-environment-source-profile-only",
    "no-production-authorization",
    "no-broad-interoperability",
    "not-upstream-product-certification",
    "not-general-country-system-conformance",
    "offline-fixtures-not-live-evidence",
    "signing-not-governance-approval",
    "digests-not-independent-evidence",
)

IMPLEMENTER_ROLES = (
    "independent-country-implementer",
    "country-technical-owner",
    "approved-operator",
    "registry-stack-evidence-reviewer",
)
SOURCE_CASE_ROLES = (
    "approved-operator",
    "source-system-owner",
    "country-technical-owner",
    "registry-stack-evidence-reviewer",
)
PROMOTION_ROLES = (
    "approved-operator",
    "product-signing-authority",
    "country-technical-owner",
    "registry-stack-evidence-reviewer",
)
RECOVERY_ROLES = (
    "approved-operator",
    "recovery-owner",
    "country-technical-owner",
    "registry-stack-evidence-reviewer",
)
TEARDOWN_ROLES = (
    "approved-operator",
    "recovery-owner",
    "source-system-owner",
    "country-technical-owner",
    "registry-stack-evidence-reviewer",
)

# The ordered set deliberately separates combined requirements from the
# readiness packet. A pass therefore proves both missing and wrong denials,
# and each safe source-failure class, rather than accepting one sample.
CASE_CONTRACT: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    (
        "offline-clean-journey",
        "offline-journey-complete",
        "offline-no-contact",
        IMPLEMENTER_ROLES,
    ),
    (
        "missing-caller-credential-denial",
        "caller-authorization-denied",
        "denied-before-data-operation",
        SOURCE_CASE_ROLES,
    ),
    (
        "wrong-caller-credential-denial",
        "caller-authorization-denied",
        "denied-before-data-operation",
        SOURCE_CASE_ROLES,
    ),
    (
        "missing-purpose-denial",
        "purpose-authorization-denied",
        "denied-before-data-operation",
        SOURCE_CASE_ROLES,
    ),
    (
        "wrong-purpose-denial",
        "purpose-authorization-denied",
        "denied-before-data-operation",
        SOURCE_CASE_ROLES,
    ),
    (
        "disallowed-service-policy-denial",
        "service-policy-denied",
        "denied-before-data-operation",
        SOURCE_CASE_ROLES,
    ),
    (
        "allowed-relay-consultation",
        "allowed-minimized-result",
        "consulted-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "no-match",
        "no-match",
        "consulted-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "ambiguity",
        "ambiguity-without-unsupported-claim",
        "consulted-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "subject-mismatch",
        "subject-mismatch-safe-failure",
        "consulted-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "source-unavailable",
        "source-unavailable-safe-failure",
        "source-failed-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "source-rejected",
        "source-rejected-safe-failure",
        "source-failed-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "source-malformed",
        "source-malformed-safe-failure",
        "source-failed-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "source-late",
        "source-late-safe-failure",
        "source-failed-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "notary-value-claim",
        "notary-value-approved-disclosure",
        "consulted-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "notary-predicate-claim",
        "notary-predicate-true-false-null-without-value",
        "consulted-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "notary-redacted-claim",
        "notary-redacted-without-hidden-value",
        "consulted-within-profile",
        SOURCE_CASE_ROLES,
    ),
    (
        "consultation-contract-mismatch",
        "contract-mismatch-before-access",
        "denied-before-data-operation",
        SOURCE_CASE_ROLES,
    ),
    (
        "promotion",
        "promotion-non-widening",
        "no-data-operation-operational",
        PROMOTION_ROLES,
    ),
    (
        "rollback-recovery",
        "rollback-recovery-restored",
        "no-data-operation-operational",
        RECOVERY_ROLES,
    ),
    (
        "teardown",
        "teardown-completed",
        "no-data-operation-operational",
        TEARDOWN_ROLES,
    ),
)


class AcceptanceError(RuntimeError):
    """A first-country acceptance record is invalid or unsafe."""


def require_regular_file(path: Path, *, max_bytes: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise AcceptanceError(f"required file is unavailable: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise AcceptanceError("required path must be a regular, non-symlink file")
    if info.st_size <= 0 or info.st_size > max_bytes:
        raise AcceptanceError(
            f"file size must be between 1 and {max_bytes} bytes"
        )


def load_json(path: Path, *, max_bytes: int = MAX_RECORD_BYTES) -> Any:
    require_regular_file(path, max_bytes=max_bytes)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"could not read valid JSON: {exc}") from exc


def assert_closed_schema(value: Any, label: str = "schema") -> None:
    if isinstance(value, dict):
        if (
            value.get("type") == "object"
            and value.get("additionalProperties") is not False
        ):
            raise AcceptanceError(f"{label} contains an open object schema")
        if value.get("type") == "object":
            properties = set(value.get("properties", {}))
            required = set(value.get("required", []))
            if properties != required:
                raise AcceptanceError(
                    f"{label} must require every field in its closed object schema"
                )
        for name, item in value.items():
            assert_closed_schema(item, f"{label}.{name}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_closed_schema(item, f"{label}[{index}]")


def load_schema() -> dict[str, Any]:
    value = load_json(SCHEMA_PATH)
    if not isinstance(value, dict):
        raise AcceptanceError("acceptance schema must be an object")
    if value.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise AcceptanceError("acceptance schema must use JSON Schema draft 2020-12")
    if value.get("additionalProperties") is not False:
        raise AcceptanceError("acceptance schema must be closed")
    assert_closed_schema(value)
    return value


def validate_shape(record: Any, schema: dict[str, Any]) -> dict[str, Any]:
    try:
        validate_closed_schema(record, schema, schema, "record")
    except SchemaValidationError as exc:
        raise AcceptanceError(str(exc)) from None
    if not isinstance(record, dict):
        raise AcceptanceError("record must be an object")
    return record


def canonical_binding_sha256(binding: dict[str, Any]) -> str:
    encoded = json.dumps(
        binding,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def digest_fields(value: Any, label: str = "record") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for name, item in value.items():
            child = f"{label}.{name}"
            if name.endswith("_sha256") and isinstance(item, str):
                found.append((child, item))
            found.extend(digest_fields(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(digest_fields(item, f"{label}[{index}]"))
    return found


def require_exact_roles(
    actual: list[str], expected: tuple[str, ...], label: str
) -> None:
    if actual != list(expected):
        raise AcceptanceError(f"{label} must use the exact ordered owner-role set")


def validate_common(record: dict[str, Any]) -> None:
    if record["schema_version"] != SCHEMA_VERSION:
        raise AcceptanceError("record has an unsupported schema version")
    computed = canonical_binding_sha256(record["binding"])
    if record["acceptance_binding_sha256"] != computed:
        raise AcceptanceError(
            "acceptance_binding_sha256 does not match the canonical binding"
        )
    if list(record["evidence_limitations"]) != list(LIMITATIONS):
        raise AcceptanceError(
            "record must retain the exact ordered evidence limitation set"
        )
    cases = record["cases"]
    if [item["case_id"] for item in cases] != [
        contract[0] for contract in CASE_CONTRACT
    ]:
        raise AcceptanceError("record cases must use the closed ordered case set")
    for case, (_, _, _, roles) in zip(cases, CASE_CONTRACT):
        if case["acceptance_binding_sha256"] != computed:
            raise AcceptanceError(
                f"{case['case_id']} is not bound to the canonical acceptance identity"
            )
        require_exact_roles(
            case["owner_roles"], roles, f"{case['case_id']}.owner_roles"
        )
    require_exact_roles(
        record["human_acceptance"]["owner_roles"],
        IMPLEMENTER_ROLES,
        "human_acceptance.owner_roles",
    )
    teardown_case = cases[-1]
    teardown = record["teardown"]
    for field in (
        "source_call_classification",
        "public_evidence_sha256",
        "restricted_evidence_sha256",
        "owner_attestation_sha256",
        "owner_roles",
    ):
        if teardown[field] != teardown_case[field]:
            raise AcceptanceError(
                f"teardown.{field} must match the closed teardown case"
            )


def validate_template(record: dict[str, Any]) -> None:
    validate_common(record)
    if (
        record["record_kind"] != "template"
        or record["is_evidence"] is not False
        or record["evidence_state"] != "planned_not_executed"
        or record["overall_outcome"] != "not_executed"
    ):
        raise AcceptanceError("template must remain explicit non-evidence")
    if record["binding"]["candidate"]["release_tag"] != "v0.0.0":
        raise AcceptanceError("template must retain the reserved release sentinel")
    if record["binding"]["candidate"]["source_commit"] != ZERO_COMMIT:
        raise AcceptanceError("template must retain the reserved commit sentinel")
    if (
        record["binding"]["source_profile"]["approved_input_class"]
        != "not-selected"
    ):
        raise AcceptanceError("template must retain the unselected input sentinel")
    for label, digest in digest_fields(record["binding"]):
        if digest != ZERO_SHA256:
            raise AcceptanceError(f"{label} must retain the zero-digest sentinel")
    for label, digest in digest_fields(record):
        if label in {
            "record.acceptance_binding_sha256",
            *(
                f"record.cases[{index}].acceptance_binding_sha256"
                for index in range(len(CASE_CONTRACT))
            ),
        }:
            continue
        if digest != ZERO_SHA256:
            raise AcceptanceError(f"{label} must retain the zero-digest sentinel")
    candidate = record["binding"]["candidate"]
    if any(
        candidate[field] is not False
        for field in (
            "candidate_assets_verified",
            "authenticity_verified",
            "exact_candidate_approved",
        )
    ):
        raise AcceptanceError("template must not attest candidate verification")
    for section, fields in (
        (
            record["binding"]["project"],
            (
                "generated_files_unchanged",
                "generated_files_edited",
                "product_code_changes_required",
            ),
        ),
        (
            record["binding"]["environment"],
            ("secret_values_retained", "authority_widening_detected"),
        ),
        (
            record["binding"]["source_profile"],
            (
                "exact_version_bound",
                "exact_read_operation_bound",
                "non_production_only",
                "zero_one_call_probe_approved",
            ),
        ),
    ):
        if any(section[field] is not False for field in fields):
            raise AcceptanceError("template must not attest unexecuted prerequisites")
    if any(record["scope_claims"].values()):
        raise AcceptanceError("template must not make acceptance or scope claims")
    human = record["human_acceptance"]
    if (
        human["outcome"] != "not_executed"
        or human["published_candidate_artifacts_only"]
        or human["private_maintainer_instructions_used"]
        or any(
            human[field]
            for field in (
                "authored_intent_understood",
                "environment_binding_understood",
                "generated_artifacts_understood",
                "signed_product_inputs_understood",
                "operator_trust_understood",
                "runtime_state_understood",
            )
        )
        or human["country_owner_usability_acceptance"] != "not_reviewed"
        or human["maintainability_acceptance"] != "not_reviewed"
    ):
        raise AcceptanceError("template must not claim human acceptance")
    for case in record["cases"]:
        if (
            case["outcome"] != "not_executed"
            or case["result_class"] != "not-executed"
            or case["source_call_classification"] != "unknown"
        ):
            raise AcceptanceError("template cases must remain unexecuted")
    storage = record["evidence_handling"]["restricted_storage"]
    retention = record["evidence_handling"]["retention"]
    deletion = record["evidence_handling"]["deletion"]
    redaction = record["evidence_handling"]["redaction"]
    if (
        storage["approved"]
        or retention["approved"]
        or retention["failed_run_retention_approved"]
        or deletion["procedure_approved"]
        or deletion["completion_state"] != "not_scheduled"
        or redaction["canary_scan_passed"]
        or redaction["public_private_split_confirmed"]
    ):
        raise AcceptanceError("template must not claim evidence-handling approval")
    for acceptance in (
        record["governance"]["privacy_acceptance"],
        record["governance"]["legal_acceptance"],
        record["governance"]["country_technical_acceptance"],
    ):
        if acceptance["status"] != "not_reviewed":
            raise AcceptanceError("template must not claim governance acceptance")
    publication = record["publication_review"]
    if (
        publication["status"] != "not_executed"
        or publication["public_restricted_comparison_confirmed"]
        or publication["forbidden_content_absent"]
    ):
        raise AcceptanceError("template must not claim publication review")
    teardown = record["teardown"]
    if (
        teardown["attempted"]
        or teardown["finally_path"]
        or teardown["outcome"] != "not_executed"
        or teardown["within_approved_bound"]
        or teardown["source_call_classification"] != "unknown"
    ):
        raise AcceptanceError("template must not claim teardown evidence")


def require_non_sentinel_evidence(record: dict[str, Any]) -> None:
    candidate = record["binding"]["candidate"]
    if (
        candidate["release_tag"] == "v0.0.0"
        or candidate["source_commit"] == ZERO_COMMIT
    ):
        raise AcceptanceError("evidence must bind a non-sentinel exact candidate")
    for label, digest in digest_fields(record):
        if digest == ZERO_SHA256:
            raise AcceptanceError(f"{label} uses the reserved non-evidence digest")


def require_distinct_evidence_domains(record: dict[str, Any]) -> None:
    candidate = record["binding"]["candidate"]
    candidate_digests = [
        candidate[field]
        for field in (
            "registryctl_asset_sha256",
            "relay_product_sha256",
            "notary_product_sha256",
            "worker_set_sha256",
            "image_lock_sha256",
            "release_capsule_sha256",
            "release_provenance_sha256",
            "candidate_evidence_sha256",
        )
    ]
    if len(set(candidate_digests)) != len(candidate_digests):
        raise AcceptanceError(
            "candidate artifacts and candidate verification evidence must have "
            "distinct digests"
        )

    public_digests: set[str] = set()
    restricted_digests: set[str] = set()
    for case in record["cases"]:
        evidence_digests = [
            case[field]
            for field in (
                "source_call_evidence_sha256",
                "public_evidence_sha256",
                "restricted_evidence_sha256",
                "owner_attestation_sha256",
            )
        ]
        if len(set(evidence_digests)) != len(evidence_digests):
            raise AcceptanceError(
                f"{case['case_id']} must bind distinct public, restricted, "
                "source-call, and owner-attestation evidence"
            )
        public_digests.add(case["public_evidence_sha256"])
        restricted_digests.update(
            {
                case["restricted_evidence_sha256"],
                case["source_call_evidence_sha256"],
                case["owner_attestation_sha256"],
            }
        )

    human = record["human_acceptance"]
    human_digests = [
        human[field]
        for field in (
            "public_evidence_sha256",
            "restricted_evidence_sha256",
            "owner_attestation_sha256",
        )
    ]
    if len(set(human_digests)) != len(human_digests):
        raise AcceptanceError(
            "human acceptance must bind distinct public, restricted, and owner evidence"
        )
    public_digests.add(human["public_evidence_sha256"])
    restricted_digests.update(
        {
            human["restricted_evidence_sha256"],
            human["owner_attestation_sha256"],
        }
    )

    redaction = record["evidence_handling"]["redaction"]
    redaction_digests = [
        redaction[field]
        for field in (
            "public_summary_sha256",
            "restricted_index_sha256",
            "scan_evidence_sha256",
        )
    ]
    if len(set(redaction_digests)) != len(redaction_digests):
        raise AcceptanceError(
            "redaction must bind distinct public summary, restricted index, "
            "and scan evidence"
        )
    public_digests.add(redaction["public_summary_sha256"])
    restricted_digests.update(
        {
            redaction["restricted_index_sha256"],
            redaction["scan_evidence_sha256"],
        }
    )

    if public_digests & restricted_digests:
        raise AcceptanceError(
            "public and restricted evidence domains must use distinct digests"
        )
    if record["publication_review"]["review_evidence_sha256"] in (
        public_digests | restricted_digests
    ):
        raise AcceptanceError(
            "publication review evidence must be distinct from reviewed evidence"
        )


def validate_evidence(record: dict[str, Any]) -> str:
    validate_common(record)
    if record["record_kind"] != "candidate_acceptance_evidence":
        raise AcceptanceError("validate requires a candidate acceptance record")
    if record["is_evidence"] is not True:
        raise AcceptanceError("candidate acceptance record must set is_evidence true")
    if record["evidence_state"] not in {
        "passed_non_production",
        "failed_non_production",
    }:
        raise AcceptanceError("candidate evidence has an invalid evidence state")
    require_non_sentinel_evidence(record)
    require_distinct_evidence_domains(record)

    candidate = record["binding"]["candidate"]
    if any(
        candidate[field] is not True
        for field in (
            "candidate_assets_verified",
            "authenticity_verified",
            "exact_candidate_approved",
        )
    ):
        raise AcceptanceError("candidate identity is not fully verified and approved")
    project = record["binding"]["project"]
    if (
        project["generated_files_unchanged"] is not True
        or project["generated_files_edited"] is not False
        or project["product_code_changes_required"] is not False
    ):
        raise AcceptanceError(
            "project must retain reviewed generated files and require no "
            "product-code change"
        )
    environment = record["binding"]["environment"]
    if (
        environment["secret_values_retained"] is not False
        or environment["authority_widening_detected"] is not False
    ):
        raise AcceptanceError(
            "environment evidence must retain no secret values or widened authority"
        )
    profile = record["binding"]["source_profile"]
    if any(
        profile[field] is not True
        for field in (
            "exact_version_bound",
            "exact_read_operation_bound",
            "non_production_only",
            "zero_one_call_probe_approved",
        )
    ):
        raise AcceptanceError("source profile is not fully bounded and approved")
    if profile["approved_input_class"] not in {
        "synthetic",
        "owner-approved-non-personal",
    }:
        raise AcceptanceError("source profile lacks an approved safe input class")

    storage = record["evidence_handling"]["restricted_storage"]
    retention = record["evidence_handling"]["retention"]
    deletion = record["evidence_handling"]["deletion"]
    redaction = record["evidence_handling"]["redaction"]
    if storage["approved"] is not True:
        raise AcceptanceError("restricted evidence storage is not approved")
    if storage["owner_role"] != "approved-operator":
        raise AcceptanceError(
            "restricted evidence storage lacks the approved operator role"
        )
    if (
        retention["approved"] is not True
        or retention["failed_run_retention_approved"] is not True
    ):
        raise AcceptanceError("run and failed-run retention are not approved")
    if retention["owner_role"] != "privacy-legal-owner":
        raise AcceptanceError("retention lacks the privacy and legal owner role")
    if (
        deletion["procedure_approved"] is not True
        or deletion["completion_state"]
        not in {"scheduled-within-approved-policy", "completed"}
    ):
        raise AcceptanceError("evidence deletion is not approved and accounted for")
    if deletion["owner_role"] != "privacy-legal-owner":
        raise AcceptanceError("deletion lacks the privacy and legal owner role")
    if (
        redaction["canary_scan_passed"] is not True
        or redaction["public_private_split_confirmed"] is not True
    ):
        raise AcceptanceError("public/private redaction evidence is incomplete")

    governance = record["governance"]
    expected_governance_roles = {
        "privacy_acceptance": "privacy-legal-owner",
        "legal_acceptance": "privacy-legal-owner",
        "country_technical_acceptance": "country-technical-owner",
    }
    for name, role in expected_governance_roles.items():
        acceptance = governance[name]
        if acceptance["status"] != "accepted" or acceptance["owner_role"] != role:
            raise AcceptanceError(
                f"governance.{name} lacks bounded acceptance by the required role"
            )
    if governance["production_authorization"] != "not-granted":
        raise AcceptanceError("record must not claim production authorization")

    publication = record["publication_review"]
    if (
        publication["status"] != "passed"
        or publication["public_restricted_comparison_confirmed"] is not True
        or publication["forbidden_content_absent"] is not True
        or publication["owner_role"] != "publication-reviewer"
    ):
        raise AcceptanceError("publication review is not complete")

    all_cases_passed = True
    for case, (_, result_class, source_class, _) in zip(
        record["cases"], CASE_CONTRACT
    ):
        if case["outcome"] == "passed":
            if case["result_class"] != result_class:
                raise AcceptanceError(
                    f"{case['case_id']} does not use its reviewed result class"
                )
            if case["source_call_classification"] != source_class:
                raise AcceptanceError(
                    f"{case['case_id']} does not use its reviewed source-call "
                    "classification"
                )
        elif case["outcome"] == "failed":
            all_cases_passed = False
            if case["result_class"] != "execution-failed":
                raise AcceptanceError(
                    f"{case['case_id']} failed without the failure result class"
                )
            if case["source_call_classification"] not in {
                source_class,
                "unknown",
                "unexpected-data-operation-contact",
                "source-call-bound-breached",
            }:
                raise AcceptanceError(
                    f"{case['case_id']} failed with a contradictory source-call "
                    "classification"
                )
        else:
            all_cases_passed = False
            if (
                case["result_class"] != "not-executed"
                or case["source_call_classification"] != "unknown"
            ):
                raise AcceptanceError(
                    f"{case['case_id']} is unexecuted but claims an observed result"
                )

    human = record["human_acceptance"]
    human_success_facts = (
        human["published_candidate_artifacts_only"] is True
        and human["private_maintainer_instructions_used"] is False
        and all(
            human[field] is True
            for field in (
                "authored_intent_understood",
                "environment_binding_understood",
                "generated_artifacts_understood",
                "signed_product_inputs_understood",
                "operator_trust_understood",
                "runtime_state_understood",
            )
        )
        and human["country_owner_usability_acceptance"] == "accepted"
        and human["maintainability_acceptance"] == "accepted"
    )
    human_passed = human["outcome"] == "passed" and human_success_facts
    if human["outcome"] == "passed" and not human_success_facts:
        raise AcceptanceError(
            "passed human acceptance lacks independent usability evidence"
        )
    if human["outcome"] == "failed" and human_success_facts:
        raise AcceptanceError(
            "failed human acceptance contradicts its success attestations"
        )
    if human["outcome"] == "not_executed" and (
        human["published_candidate_artifacts_only"]
        or human["private_maintainer_instructions_used"]
        or any(
            human[field]
            for field in (
                "authored_intent_understood",
                "environment_binding_understood",
                "generated_artifacts_understood",
                "signed_product_inputs_understood",
                "operator_trust_understood",
                "runtime_state_understood",
            )
        )
        or human["country_owner_usability_acceptance"] != "not_reviewed"
        or human["maintainability_acceptance"] != "not_reviewed"
    ):
        raise AcceptanceError(
            "unexecuted human acceptance must not contain outcome attestations"
        )

    teardown = record["teardown"]
    teardown_case = record["cases"][-1]
    if teardown["attempted"] is not True or teardown["finally_path"] is not True:
        raise AcceptanceError(
            "candidate evidence must record a teardown attempt from a finally path"
        )
    if teardown["outcome"] == "completed":
        if (
            teardown_case["outcome"] != "passed"
            or teardown_case["result_class"] != "teardown-completed"
            or teardown["within_approved_bound"] is not True
        ):
            raise AcceptanceError(
                "completed teardown contradicts the closed teardown case"
            )
    elif teardown["outcome"] == "failed":
        if (
            teardown_case["outcome"] != "failed"
            or teardown_case["result_class"] != "execution-failed"
        ):
            raise AcceptanceError("failed teardown contradicts its closed case")
    else:
        raise AcceptanceError(
            "candidate evidence must record completed or failed teardown"
        )
    teardown_passed = (
        teardown["outcome"] == "completed"
        and teardown["within_approved_bound"] is True
        and teardown["source_call_classification"]
        == "no-data-operation-operational"
    )
    complete = all_cases_passed and human_passed and teardown_passed
    claims = record["scope_claims"]
    nonproduction_claims_safe = (
        claims["production_authorized"] is False
        and claims["broad_interoperability"] is False
        and claims["upstream_product_certification"] is False
    )
    if not nonproduction_claims_safe:
        raise AcceptanceError("record contains an unsafe scope claim")

    if record["evidence_state"] == "passed_non_production":
        if record["overall_outcome"] != "passed" or not complete:
            raise AcceptanceError(
                "passing state requires every case, human acceptance, and "
                "teardown to pass"
            )
        if any(
            claims[field] is not True
            for field in (
                "platform_complete",
                "country_ready",
                "first_country_success",
            )
        ):
            raise AcceptanceError(
                "passing acceptance evidence must explicitly close the three "
                "bounded states"
            )
        return "passed"

    if record["overall_outcome"] != "failed" or complete:
        raise AcceptanceError(
            "failed state requires a failed or unexecuted case, human gate, or teardown"
        )
    if any(
        claims[field] is not False
        for field in (
            "platform_complete",
            "country_ready",
            "first_country_success",
        )
    ):
        raise AcceptanceError("failed evidence must remain non-closing")
    return "failed"


def check_packet() -> None:
    schema = load_schema()
    template = validate_shape(load_json(TEMPLATE_PATH), schema)
    validate_template(template)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "check-packet",
        help="validate the checked-in closed schema and non-evidence template",
    )
    validate = commands.add_parser(
        "validate",
        help="validate one sanitized candidate acceptance evidence record",
    )
    validate.add_argument("record", type=Path)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        schema = load_schema()
        template = validate_shape(load_json(TEMPLATE_PATH), schema)
        validate_template(template)
        if args.command == "check-packet":
            print("first-country acceptance source packet validation passed")
        else:
            record = validate_shape(load_json(args.record), schema)
            outcome = validate_evidence(record)
            if outcome == "passed":
                print(
                    "first-country acceptance validation passed "
                    "(bounded non-production only)"
                )
            else:
                print(
                    "first-country failed-run record is valid non-closing evidence"
                )
    except (AcceptanceError, KeyError, OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
