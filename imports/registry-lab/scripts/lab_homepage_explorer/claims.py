#!/usr/bin/env python3
"""Allowlisted Claims Explorer helpers for the Registry Lab homepage."""

from __future__ import annotations

import csv
from copy import deepcopy
from pathlib import Path
from typing import Any

from .common import (
    CLAIM_RESULT_FORMAT,
    PURPOSE,
    ExplorerInputError,
    auth_header_pair,
    credential_display,
    credential_for_execution,
    display_auth_header_pair,
    env_url,
    error_payload,
    http_json,
    joined_url,
    require_keys,
    request_source,
    safe_curl,
    service_url,
    source_response,
    unknown_id_error,
)


CLAIM_SERVICE_ORDER = [
    "civil-notary",
    "social-protection-notary",
    "shared-eligibility-notary",
    "dhis2-notary",
    "opencrvs-notary",
    "agriculture-notary",
]

DISCLOSURE_LABELS = {
    "predicate": "just yes/no",
    "value": "a specific value",
    "redacted": "confirmation without value",
    "credential": "wallet-ready credential",
}

REPO_ROOT = Path(__file__).resolve().parents[2]
CivilRow = dict[str, str]


def _source(registry: str, dataset: str, entity: str, lookup_field: str, required_scope: str, connector_type: str) -> dict[str, str]:
    return {
        "registry": registry,
        "dataset": dataset,
        "entity": entity,
        "lookup_field": lookup_field,
        "required_scope": required_scope,
        "connector_type": connector_type,
    }


def _claim(
    claim_id: str,
    title: str,
    disclosures: list[str],
    relay_fields_used: list[str],
    source: dict[str, str],
    *,
    value_type: str = "boolean",
) -> dict[str, Any]:
    default_disclosure = "predicate" if "predicate" in disclosures else disclosures[0]
    return {
        "id": claim_id,
        "title": title,
        "value_type": value_type,
        "default_disclosure": default_disclosure,
        "allowed_disclosures": disclosures,
        "formats": [CLAIM_RESULT_FORMAT],
        "relay_fields_used": relay_fields_used,
        "source": source,
    }

CLAIM_SERVICES: dict[str, dict[str, Any]] = {
    "civil-notary": {
        "id": "civil-notary",
        "label": "Civil Notary",
        "service_id": "civil-notary",
        "base_url": "https://civil-notary.lab.registrystack.org",
        "runtime_url_env": "CIVIL_EVIDENCE_URL",
        "runtime_default_url": "http://127.0.0.1:4321",
        "client_credential_id": "civil-notary-evidence",
        "runtime_token_env": "CIVIL_EVIDENCE_CLIENT_BEARER",
        "default_subject": "NID-1001",
        "default_identifier_scheme": "national_id",
        "default_purpose": PURPOSE,
        "related_registry_ids": ["civil"],
        "availability": "runtime",
        "default_claim": "person-is-alive",
        "claims": {
            "person-is-alive": {
                "id": "person-is-alive",
                "title": "Vital Status Attestation",
                "value_type": "boolean",
                "default_disclosure": "predicate",
                "allowed_disclosures": ["predicate", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": ["deceased"],
                "source": {
                    "registry": "Civil Registry",
                    "dataset": "civil_registry",
                    "entity": "civil_person",
                    "lookup_field": "NATIONAL_ID",
                    "required_scope": "civil_registry:evidence_verification",
                    "connector_type": "dci",
                },
            }
        },
    },
    "social-protection-notary": {
        "id": "social-protection-notary",
        "label": "Social Protection Notary",
        "service_id": "social-protection-notary",
        "base_url": "https://social-notary.lab.registrystack.org",
        "client_credential_id": "social-protection-evidence",
        "default_subject": "NID-1001",
        "default_identifier_scheme": "national_id",
        "default_purpose": PURPOSE,
        "related_registry_ids": ["social-protection"],
        "availability": "hosted",
        "default_claim": "beneficiary-active",
        "claims": {
            "program-enrollment-status": {
                "id": "program-enrollment-status",
                "title": "Program Enrollment Attestation",
                "value_type": "string",
                "default_disclosure": "value",
                "allowed_disclosures": ["value", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": ["enrollment_status"],
                "source": _source("Social Protection Registry", "social_protection_registry", "program_enrollment", "national_id", "social_protection_registry:evidence_verification", "registry_data_api"),
            },
            "household-eligibility-band": {
                "id": "household-eligibility-band",
                "title": "Welfare Classification Attestation",
                "value_type": "string",
                "default_disclosure": "value",
                "allowed_disclosures": ["value", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": ["eligibility_band"],
                "source": _source("Social Protection Registry", "social_protection_registry", "household", "national_id", "social_protection_registry:evidence_verification", "registry_data_api"),
            },
            "beneficiary-active": {
                "id": "beneficiary-active",
                "title": "Program Enrollment Active Attestation",
                "value_type": "boolean",
                "default_disclosure": "predicate",
                "allowed_disclosures": ["predicate", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": ["enrollment_status"],
                "source": _source("Social Protection Registry", "social_protection_registry", "program_enrollment", "national_id", "social_protection_registry:evidence_verification", "registry_data_api"),
            },
            "household-composition": {
                "id": "household-composition",
                "title": "Household Composition Attestation",
                "value_type": "integer",
                "default_disclosure": "value",
                "allowed_disclosures": ["value", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": ["household_size"],
                "source": _source("Social Protection Registry", "social_protection_registry", "household", "national_id", "social_protection_registry:evidence_verification", "registry_data_api"),
            },
            "caregiver-link": {
                "id": "caregiver-link",
                "title": "Parent Or Guardian Link Attestation",
                "value_type": "boolean",
                "default_disclosure": "predicate",
                "allowed_disclosures": ["predicate", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": ["id", "household_id", "relationship", "alive"],
                "source": _source("Social Protection Registry", "social_protection_registry", "person", "national_id", "social_protection_registry:evidence_verification", "registry_data_api"),
            },
            "disability-determination": {
                "id": "disability-determination",
                "title": "Disability Determination Attestation",
                "value_type": "string",
                "default_disclosure": "value",
                "allowed_disclosures": ["value", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": ["support_category"],
                "source": _source("Social Protection Registry", "social_protection_registry", "disability_determination", "national_id", "social_protection_registry:evidence_verification", "registry_data_api"),
            },
            "functioning-assessment": {
                "id": "functioning-assessment",
                "title": "Functioning Assessment Attestation",
                "value_type": "boolean",
                "default_disclosure": "value",
                "allowed_disclosures": ["value", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": ["disability_identifier_met"],
                "source": _source("Social Protection Registry", "social_protection_registry", "functioning_profile", "national_id", "social_protection_registry:evidence_verification", "registry_data_api"),
            },
        },
    },
    "shared-eligibility-notary": {
        "id": "shared-eligibility-notary",
        "label": "Shared Eligibility Notary",
        "service_id": "shared-eligibility-notary",
        "base_url": "https://shared-notary.lab.registrystack.org",
        "runtime_url_env": "SHARED_EVIDENCE_URL",
        "runtime_default_url": "http://127.0.0.1:4323",
        "client_credential_id": "shared-evidence",
        "runtime_token_env": "SHARED_EVIDENCE_CLIENT_BEARER",
        "default_subject": "NID-1001",
        "default_identifier_scheme": "national_id",
        "default_purpose": PURPOSE,
        "related_registry_ids": ["civil", "social-protection", "health"],
        "availability": "runtime",
        "default_claim": "eligible-for-combined-support",
        "claims": {
            "civil-record-present": _claim("civil-record-present", "Civil record present", ["predicate", "redacted"], ["national_id"], _source("Civil Registry", "civil_registry", "civil_person", "NATIONAL_ID", "civil_registry:evidence_verification", "registry_data_api")),
            "social-program-active": _claim("social-program-active", "Program Enrollment Attestation", ["predicate", "redacted"], ["enrollment_status"], _source("Social Protection Registry", "social_protection_registry", "program_enrollment", "national_id", "social_protection_registry:evidence_verification", "registry_data_api")),
            "health-service-available": _claim("health-service-available", "Service Availability Attestation", ["predicate", "redacted"], ["license_status", "pediatric_service_available", "practitioner_credential_active"], _source("Health Registry", "health_registry", "health_facility", "national_id", "health_registry:evidence_verification", "registry_data_api")),
            "eligible-for-combined-support": _claim("eligible-for-combined-support", "Combined Support Eligibility Attestation", ["predicate", "redacted"], ["civil-record-present", "social-program-active", "health-service-available"], _source("Combined eligibility sources", "multiple", "multiple", "national_id", "shared:evidence_verification", "registry_data_api")),
        },
    },
    "dhis2-notary": {
        "id": "dhis2-notary",
        "label": "DHIS2 Notary",
        "service_id": "dhis2-notary",
        "base_url": "https://dhis2-notary.lab.registrystack.org",
        "client_credential_id": "dhis2-bearer",
        "default_subject": "PQfMcpmXeFE",
        "default_identifier_scheme": "dhis2_tracked_entity",
        "default_purpose": "https://demo.example.gov/purpose/dhis2-openfn-health-evidence",
        "related_registry_ids": ["health"],
        "availability": "hosted",
        "default_claim": "dhis2-child-program-active",
        "claims": {
            "dhis2-child-program-active": _claim("dhis2-child-program-active", "Health Programme Participation Attestation", ["predicate", "redacted"], ["program_status"], _source("DHIS2", "dhis2_tracker", "person", "tracked_entity", "dhis2_health:evidence_verification", "dhis2")),
            "dhis2-child-age-band": _claim("dhis2-child-age-band", "Child age band", ["value", "redacted"], ["birth_date"], _source("DHIS2", "dhis2_tracker", "person", "tracked_entity", "dhis2_health:evidence_verification", "dhis2"), value_type="string"),
            "dhis2-programme-code": _claim("dhis2-programme-code", "Programme code", ["value", "redacted"], ["programme_code"], _source("DHIS2", "dhis2_tracker", "person", "tracked_entity", "dhis2_health:evidence_verification", "dhis2"), value_type="string"),
        },
    },
    "opencrvs-notary": {
        "id": "opencrvs-notary",
        "label": "OpenCRVS DCI Notary",
        "service_id": "opencrvs-notary",
        "base_url": "https://opencrvs-notary.lab.registrystack.org",
        "client_credential_id": "opencrvs-api-key",
        "default_subject": "BIRTH-1001",
        "default_identifier_scheme": "birth_registration_id",
        "default_purpose": PURPOSE,
        "related_registry_ids": ["civil"],
        "availability": "hosted",
        "default_claim": "opencrvs-birth-record-exists",
        "claims": {
            "opencrvs-birth-record-exists": _claim("opencrvs-birth-record-exists", "Birth Registration Attestation", ["predicate", "redacted"], ["record_id"], _source("OpenCRVS", "civil_registry", "birth_registration", "registration_id", "civil_registry:evidence_verification", "dci")),
            "opencrvs-date-of-birth": _claim("opencrvs-date-of-birth", "Date of birth", ["value", "redacted"], ["birth_date"], _source("OpenCRVS", "civil_registry", "birth_registration", "registration_id", "civil_registry:evidence_verification", "dci"), value_type="date"),
            "opencrvs-age-band": _claim("opencrvs-age-band", "Age Eligibility Attestation", ["value", "redacted"], ["birth_date"], _source("OpenCRVS", "civil_registry", "birth_registration", "registration_id", "civil_registry:evidence_verification", "dci"), value_type="string"),
        },
    },
    "agriculture-notary": {
        "id": "agriculture-notary",
        "label": "Agriculture Notary",
        "service_id": "agriculture-notary",
        "base_url": "https://agriculture-notary.lab.registrystack.org",
        "runtime_url_env": "AGRI_EVIDENCE_URL",
        "runtime_default_url": "http://127.0.0.1:4324",
        "client_credential_id": "agri-evidence",
        "runtime_token_env": "AGRI_EVIDENCE_CLIENT_BEARER",
        "default_subject": "FARMER-1001",
        "default_identifier_scheme": "farmer_id",
        "default_purpose": "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
        "related_registry_ids": ["agriculture"],
        "availability": "hosted",
        "default_claim": "eligible-for-climate-smart-input-voucher",
        "claims": {
            "farmer-registered": _claim("farmer-registered", "Farmer registered", ["predicate", "redacted"], ["registration_status"], _source("NAgDI Agricultural Registries", "agri_registry", "farmer", "farmer_id", "agri_registry:evidence_verification", "registry_data_api")),
            "eligible-for-climate-smart-input-voucher": _claim("eligible-for-climate-smart-input-voucher", "Eligible for climate-smart input voucher", ["predicate", "redacted"], ["farmer-registered", "active-farm-parcel", "voucher-entitlement-current"], _source("NAgDI Agricultural Registries", "agri_registry", "voucher_eligibility_snapshot", "farmer_id", "agri_registry:evidence_verification", "registry_data_api")),
            "eligible-for-livestock-movement-permit": _claim("eligible-for-livestock-movement-permit", "Eligible for livestock movement permit", ["predicate", "redacted"], ["registered-livestock-holder", "registered-herd", "herd-vaccination-current"], _source("NAgDI Agricultural Registries", "agri_registry", "livestock_movement_snapshot", "farmer_id", "agri_registry:evidence_verification", "registry_data_api")),
        },
    },
}


def claim_service_ids() -> list[str]:
    return list(CLAIM_SERVICE_ORDER)


def claim_service_config(service_id: str) -> dict[str, Any]:
    if service_id not in CLAIM_SERVICES:
        raise ExplorerInputError(
            "explorer.unknown_claim_service",
            "Unknown claim service id.",
            field="service_id",
            allowed=claim_service_ids(),
        )
    return CLAIM_SERVICES[service_id]


def claim_catalog_payload(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "claim_services": [_service_summary(CLAIM_SERVICES[service_id], config) for service_id in CLAIM_SERVICE_ORDER],
        "default_service_id": "civil-notary",
        "default_format": CLAIM_RESULT_FORMAT,
    }


def claim_metadata_payload(config: dict[str, Any], service_id: str) -> dict[str, Any]:
    if service_id not in CLAIM_SERVICES:
        return unknown_id_error("claim_service", service_id, claim_service_ids())
    service = CLAIM_SERVICES[service_id]
    payload = _service_summary(service, config)
    payload["claims"] = deepcopy(list(service["claims"].values()))
    return {"ok": True, "claim_service": payload}


def default_civil_claims_payload(config: dict[str, Any], *, run_live: bool = False, timeout: float = 8.0) -> dict[str, Any]:
    service = CLAIM_SERVICES["civil-notary"]
    claim = service["claims"][service["default_claim"]]
    request = build_evaluation_request(
        config,
        "civil-notary",
        service["default_claim"],
        subject=service["default_subject"],
        identifier_scheme=service["default_identifier_scheme"],
        disclosure="predicate",
        result_format=CLAIM_RESULT_FORMAT,
        purpose=service["default_purpose"],
    )
    base_payload = {
        **request,
        "comparison": {
            "relay_fields_visible": 7,
            "notary_fields_returned": 1,
            "raw_row_returned_by_notary": "no",
        },
        "data_minimization": data_minimization_readout(claim),
    }
    if not run_live:
        answer = preview_evaluation_answer(
            "civil-notary",
            service["default_claim"],
            service["default_subject"],
            service["default_identifier_scheme"],
        )
        return {
            **base_payload,
            "mode": "preview",
            "answer": answer,
            "source": deepcopy(claim["source"]),
            "unavailable": retry_unavailable_payload(service),
            "response_source": {
                "status": "preview",
                "headers": {"content-type": "application/json; charset=utf-8"},
                "body": {"results": [answer]},
                "error": "",
            },
        }
    headers = _execution_headers(config, service, request["request_source"]["headers"])
    result = http_json("POST", request["request_source"]["url"], headers, request["request_source"]["body"], timeout=timeout)
    if result.status is None:
        return {
            **base_payload,
            "mode": "retry",
            "unavailable": retry_unavailable_payload(service),
            "response_source": source_response(result),
        }
    return {**base_payload, "mode": "live", "response_source": source_response(result)}


def retry_unavailable_payload(service: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": f"{service['label']} is unavailable from this homepage process.",
        "message": "The explorer can retry the same allowlisted evaluation when the service and demo token are available.",
        "retry": {
            "service_id": service["id"],
            "claim_id": service["default_claim"],
            "subject": service["default_subject"],
        },
    }


def preview_evaluation_answer(service_id: str, claim_id: str, subject: str, identifier_scheme: str) -> dict[str, Any]:
    """Answer from local demo fixtures when the homepage cannot call a live Notary."""
    if service_id == "civil-notary" and claim_id == "person-is-alive" and identifier_scheme == "national_id":
        row = _civil_person_by_national_id(subject)
        if row is None:
            return {
                "claim_id": claim_id,
                "satisfied": False,
                "preview": True,
                "subject_found": False,
                "reason": "subject_not_found",
            }
        return {
            "claim_id": claim_id,
            "satisfied": row.get("deceased", "").lower() != "true",
            "preview": True,
            "subject_found": True,
        }

    service = CLAIM_SERVICES[service_id]
    if subject != service["default_subject"] or identifier_scheme != service["default_identifier_scheme"]:
        return {
            "claim_id": claim_id,
            "satisfied": False,
            "preview": True,
            "subject_found": False,
            "reason": "preview_subject_not_found",
        }
    return {"claim_id": claim_id, "satisfied": True, "preview": True, "subject_found": True}


def _civil_person_by_national_id(national_id: str) -> CivilRow | None:
    path = REPO_ROOT / "data" / "civil" / "civil-persons.csv"
    if not path.exists():
        return None
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row.get("national_id") == national_id:
                return row
    return None


def validate_evaluation_input(service_id: str, body: dict[str, Any]) -> dict[str, Any]:
    require_keys(body, {"claim_id", "subject", "identifier_scheme", "disclosure", "format", "purpose"})
    service = claim_service_config(service_id)
    claim_id = str(body.get("claim_id", service["default_claim"]))
    if claim_id not in service["claims"]:
        raise ExplorerInputError(
            "explorer.unsupported_claim",
            "This claim is not available for the selected claim service.",
            field="claim_id",
            allowed=sorted(service["claims"]),
        )
    claim = service["claims"][claim_id]
    subject = str(body.get("subject", "")).strip()
    if not subject:
        raise ExplorerInputError("explorer.missing_subject", "Subject value is required.", field="subject")
    identifier_scheme = str(body.get("identifier_scheme", service["default_identifier_scheme"])).strip()
    if not identifier_scheme:
        raise ExplorerInputError("explorer.missing_identifier_scheme", "Identifier scheme is required.", field="identifier_scheme")
    disclosure = str(body.get("disclosure", claim["default_disclosure"]))
    if disclosure not in claim["allowed_disclosures"]:
        raise ExplorerInputError(
            "explorer.unsupported_disclosure",
            "This disclosure value is not supported for the selected claim.",
            field="disclosure",
            allowed=claim["allowed_disclosures"],
        )
    result_format = str(body.get("format", CLAIM_RESULT_FORMAT))
    if result_format not in claim["formats"]:
        raise ExplorerInputError(
            "explorer.unsupported_format",
            "This format is not supported for the selected claim.",
            field="format",
            allowed=claim["formats"],
        )
    return {
        "service": service,
        "claim": claim,
        "claim_id": claim_id,
        "subject": subject,
        "identifier_scheme": identifier_scheme,
        "disclosure": disclosure,
        "format": result_format,
        "purpose": str(body.get("purpose", service["default_purpose"])),
    }


def build_evaluation_request(
    config: dict[str, Any],
    service_id: str,
    claim_id: str,
    *,
    subject: str,
    identifier_scheme: str,
    disclosure: str,
    result_format: str,
    purpose: str,
) -> dict[str, Any]:
    validated = validate_evaluation_input(
        service_id,
        {
            "claim_id": claim_id,
            "subject": subject,
            "identifier_scheme": identifier_scheme,
            "disclosure": disclosure,
            "format": result_format,
            "purpose": purpose,
        },
    )
    service = validated["service"]
    credential = credential_for_execution(
        config,
        service["client_credential_id"],
        runtime_env=service.get("runtime_token_env", ""),
    )
    display_name, display_value = display_auth_header_pair(credential)
    body = evaluation_body(
        validated["subject"],
        validated["claim_id"],
        id_scheme=validated["identifier_scheme"],
        disclosure=validated["disclosure"],
        result_format=validated["format"],
    )
    headers = {display_name: display_value, "Content-Type": "application/json", "Data-Purpose": validated["purpose"]}
    url = evaluation_url(config, service)
    request = request_source("POST", url, headers, body)
    return {
        "ok": True,
        "service_id": service_id,
        "claim_id": validated["claim_id"],
        "claim": deepcopy(validated["claim"]),
        "request_source": request,
        "curl": safe_curl("POST", url, headers, body),
        "technical": {
            "disclosure": validated["disclosure"],
            "format": validated["format"],
            "credential_id": service["client_credential_id"],
        },
    }


def run_evaluation(config: dict[str, Any], service_id: str, body: dict[str, Any], *, timeout: float = 8.0) -> dict[str, Any]:
    validated = validate_evaluation_input(service_id, body)
    built = build_evaluation_request(
        config,
        service_id,
        validated["claim_id"],
        subject=validated["subject"],
        identifier_scheme=validated["identifier_scheme"],
        disclosure=validated["disclosure"],
        result_format=validated["format"],
        purpose=validated["purpose"],
    )
    headers = _execution_headers(config, validated["service"], built["request_source"]["headers"])
    credential = credential_for_execution(
        config,
        validated["service"]["client_credential_id"],
        runtime_env=validated["service"].get("runtime_token_env", ""),
    )
    if not credential.get("token"):
        answer = preview_evaluation_answer(
            service_id,
            validated["claim_id"],
            validated["subject"],
            validated["identifier_scheme"],
        )
        return {
            **built,
            "mode": "preview",
            "answer": answer,
            "source": deepcopy(validated["claim"]["source"]),
            "data_minimization": data_minimization_readout(validated["claim"]),
            "unavailable": retry_unavailable_payload(validated["service"]),
            "response_source": {
                "status": "preview",
                "headers": {"content-type": "application/json; charset=utf-8"},
                "body": {"results": [answer]},
                "error": "",
            },
        }
    result = http_json("POST", built["request_source"]["url"], headers, built["request_source"]["body"], timeout=timeout)
    return {
        **built,
        "mode": "live" if result.status is not None else "retry",
        "answer": _answer_from_response(result.body, validated["claim_id"]),
        "source": deepcopy(validated["claim"]["source"]),
        "data_minimization": data_minimization_readout(validated["claim"]),
        "response_source": source_response(result),
    }


def evaluation_body(
    subject: str,
    claim_id: str,
    *,
    id_scheme: str,
    disclosure: str,
    result_format: str = CLAIM_RESULT_FORMAT,
) -> dict[str, Any]:
    return {
        "target": {"type": "Person", "identifiers": [{"scheme": id_scheme, "value": subject}]},
        "claims": [claim_id],
        "disclosure": disclosure,
        "format": result_format,
    }


def data_minimization_readout(claim: dict[str, Any]) -> dict[str, Any]:
    returned_count = 1 if claim.get("default_disclosure") in {"predicate", "value", "redacted"} else 0
    return {
        "relay_fields_used": len(claim.get("relay_fields_used", [])),
        "returned_to_service": returned_count,
        "raw_row_returned": "no",
        "Relay fields used": len(claim.get("relay_fields_used", [])),
        "Returned to relying service": returned_count,
        "Raw row returned": "no",
    }


def claim_service_error_payload(service_id: str) -> dict[str, Any]:
    return unknown_id_error("claim_service", service_id, claim_service_ids())


def invalid_evaluation_payload(error: ExplorerInputError) -> dict[str, Any]:
    return error.payload()


def evaluation_url(config: dict[str, Any], service: dict[str, Any]) -> str:
    credential_id = service["client_credential_id"]
    if service.get("runtime_url_env"):
        return env_url(service["runtime_url_env"], service["runtime_default_url"], "/v1/evaluations")
    credential = credential_for_execution(config, credential_id)
    if credential.get("service_url"):
        return service_url(config, credential_id, "/v1/evaluations", fallback_base_url=service["base_url"])
    return joined_url(service["base_url"], "/v1/evaluations")


def controlled_exception_payload(error: Exception) -> dict[str, Any]:
    if isinstance(error, ExplorerInputError):
        return error.payload()
    return error_payload("explorer.invalid_evaluation", "The explorer evaluation request is invalid.")


def _service_summary(service: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": service["id"],
        "label": service["label"],
        "service_id": service["service_id"],
        "base_url": service["base_url"],
        "default_claim": service["default_claim"],
        "default_subject": service["default_subject"],
        "default_identifier_scheme": service["default_identifier_scheme"],
        "default_purpose": service["default_purpose"],
        "related_registry_ids": list(service["related_registry_ids"]),
        "availability": service["availability"],
        "credential": credential_display(
            config,
            service["client_credential_id"],
            runtime_env=service.get("runtime_token_env", ""),
        ),
        "claims": [
            {
                "id": claim["id"],
                "title": claim["title"],
                "default_disclosure": claim["default_disclosure"],
                "allowed_disclosures": list(claim["allowed_disclosures"]),
                "formats": list(claim["formats"]),
                "source": deepcopy(claim["source"]),
            }
            for claim in service["claims"].values()
        ],
    }


def _execution_headers(config: dict[str, Any], service: dict[str, Any], display_headers: dict[str, str]) -> dict[str, str]:
    credential = credential_for_execution(
        config,
        service["client_credential_id"],
        runtime_env=service.get("runtime_token_env", ""),
    )
    auth_name, auth_value = auth_header_pair(credential)
    if credential.get("display_policy") == "public" and credential.get("auth_header"):
        auth_name, auth_value = credential["auth_header"].split(": ", 1)
    headers = dict(display_headers)
    headers[auth_name] = auth_value
    return headers


def _answer_from_response(body: Any, claim_id: str) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    results = body.get("results") or body.get("claim_results") or []
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict) and item.get("claim_id") == claim_id:
                return item
        if results and isinstance(results[0], dict):
            return results[0]
    return body
