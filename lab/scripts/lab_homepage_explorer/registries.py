#!/usr/bin/env python3
"""Allowlisted Relay explorer helpers for the Registry Lab homepage."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from zipfile import ZipFile
import xml.etree.ElementTree as ET

from . import discovery
from .common import (
    EXPLORER_MAX_LIMIT,
    PURPOSE,
    ExplorerInputError,
    credential_display,
    credential_for_execution,
    display_auth_header_pair,
    error_payload,
    filters_to_query,
    http_json,
    request_source,
    safe_curl,
    service_url,
    source_response,
    unknown_id_error,
    validate_filters,
    validate_limit,
)


REGISTRY_ORDER = ["civil", "social-protection", "health", "agriculture"]
REPO_ROOT = Path(__file__).resolve().parents[2]


def _field(name: str, field_type: str = "string", filter_ops: list[str] | None = None, *, sensitive: bool = False) -> dict[str, Any]:
    return {"name": name, "type": field_type, "filter_ops": list(filter_ops or []), "sensitive": sensitive}


def _entity_definition(entity_id: str, title: str, fields: list[dict[str, Any]]) -> dict[str, Any]:
    return {"id": entity_id, "title": title, "fields": fields}

REGISTRIES: dict[str, dict[str, Any]] = {
    "civil": {
        "id": "civil",
        "label": "Civil",
        "service_id": "civil-relay",
        "base_url": "https://civil-relay.lab.registrystack.org",
        "metadata_credential_id": "civil-metadata",
        "row_reader_credential_id": "civil-row-reader",
        "evidence_credential_id": "civil-evidence-only",
        "default_dataset": "civil_registry",
        "default_entity": "civil_person",
        "default_limit": 1,
        "purpose": PURPOSE,
        "related_claim_service_ids": ["civil-notary", "shared-eligibility-notary"],
        "datasets": {
            "civil_registry": {
                "id": "civil_registry",
                "title": "Civil Registry",
                "entities": {
                    "civil_person": _entity_definition(
                        "civil_person",
                        "Civil Person",
                        [
                            _field("national_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("given_name", filter_ops=["eq"], sensitive=True),
                            _field("surname", filter_ops=["eq"], sensitive=True),
                            _field("birth_date", "date", ["eq", "gte", "lte"], sensitive=True),
                            _field("life_stage", filter_ops=["eq", "in"]),
                            _field("deceased", "boolean", ["eq"], sensitive=True),
                            _field("district", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "civil_person_detail": _entity_definition(
                        "civil_person_detail",
                        "Civil Person Detail",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("national_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("given_name", filter_ops=["eq"], sensitive=True),
                            _field("surname", filter_ops=["eq"], sensitive=True),
                            _field("birth_date", "date", ["eq", "gte", "lte"], sensitive=True),
                            _field("sex", filter_ops=["eq", "in"], sensitive=True),
                            _field("district", filter_ops=["eq", "in"]),
                            _field("place_of_birth", filter_ops=["eq", "in"], sensitive=True),
                            _field("life_stage", filter_ops=["eq", "in"]),
                            _field("deceased", "boolean", ["eq"], sensitive=True),
                            _field("death_date", "date", ["eq", "gte", "lte"], sensitive=True),
                        ],
                    ),
                    "civil_identifier": _entity_definition(
                        "civil_identifier",
                        "Civil Identifier",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("person_id", filter_ops=["eq", "in"]),
                            _field("scheme", filter_ops=["eq", "in"]),
                            _field("value", filter_ops=["eq"], sensitive=True),
                            _field("status", filter_ops=["eq"]),
                            _field("issued_on", "date", ["eq", "gte", "lte"]),
                            _field("valid_until", "date", ["eq", "gte", "lte"]),
                        ],
                    ),
                    "birth_event": _entity_definition(
                        "birth_event",
                        "Birth Event",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("child_person_id", filter_ops=["eq", "in"]),
                            _field("mother_person_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("father_person_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("place_of_birth", filter_ops=["eq", "in"], sensitive=True),
                            _field("date_of_birth", "date", ["eq", "gte", "lte"], sensitive=True),
                            _field("sex_at_birth", filter_ops=["eq", "in"], sensitive=True),
                            _field("attendant_or_place_type", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "death_event": _entity_definition(
                        "death_event",
                        "Death Event",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("deceased_person_id", filter_ops=["eq", "in"]),
                            _field("date_of_death", "date", ["eq", "gte", "lte"], sensitive=True),
                            _field("place_of_death", filter_ops=["eq", "in"], sensitive=True),
                            _field("registration_date", "date", ["eq", "gte", "lte"]),
                            _field("authority", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "marriage_event": _entity_definition(
                        "marriage_event",
                        "Marriage Event",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("spouse_1_person_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("spouse_2_person_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("marriage_date", "date", ["eq", "gte", "lte"], sensitive=True),
                            _field("marriage_place", filter_ops=["eq", "in"], sensitive=True),
                            _field("registration_date", "date", ["eq", "gte", "lte"]),
                            _field("authority", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "civil_status_record": _entity_definition(
                        "civil_status_record",
                        "Civil Status Record",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("record_type", filter_ops=["eq", "in"]),
                            _field("registration_number", filter_ops=["eq"], sensitive=True),
                            _field("person_id", filter_ops=["eq", "in"]),
                            _field("event_id", filter_ops=["eq", "in"]),
                            _field("authority", filter_ops=["eq", "in"]),
                            _field("registration_status", filter_ops=["eq", "in"]),
                            _field("registration_date", "date", ["eq", "gte", "lte"]),
                        ],
                    ),
                    "certificate": _entity_definition(
                        "certificate",
                        "Certificate",
                        [
                            _field("id", filter_ops=["eq", "in"], sensitive=True),
                            _field("record_id", filter_ops=["eq", "in"]),
                            _field("issue_date", "date", ["eq", "gte", "lte"]),
                            _field("issuing_office", filter_ops=["eq", "in"]),
                            _field("certificate_type", filter_ops=["eq", "in"]),
                            _field("valid_until", "date", ["eq", "gte", "lte"]),
                        ],
                    ),
                    "relationship": _entity_definition(
                        "relationship",
                        "Relationship",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("subject_person_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("related_person_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("relationship_type", filter_ops=["eq", "in"], sensitive=True),
                            _field("source_record_id", filter_ops=["eq", "in"]),
                            _field("effective_from", "date", ["eq", "gte", "lte"]),
                            _field("effective_until", "date", ["eq", "gte", "lte"]),
                            _field("relationship_status", filter_ops=["eq", "in"]),
                        ],
                    ),
                },
                "aggregates": {},
            }
        },
        "comparison": {
            "relay_fields_visible": 7,
            "related_claim": "person-is-alive",
            "notary_fields_returned": 1,
            "raw_row_returned_by_notary": "no",
        },
    },
    "social-protection": {
        "id": "social-protection",
        "label": "Social Protection",
        "service_id": "social-relay",
        "base_url": "https://social-relay.lab.registrystack.org",
        "metadata_credential_id": "social-metadata",
        "row_reader_credential_id": "social-row-reader",
        "aggregate_reader_credential_id": "social-aggregate-reader",
        "evidence_credential_id": "social-evidence-only",
        "default_dataset": "social_protection_registry",
        "default_entity": "household",
        "default_aggregate": "households_by_eligibility_band",
        "default_limit": 1,
        "purpose": PURPOSE,
        "related_claim_service_ids": ["social-protection-notary", "shared-eligibility-notary"],
        "datasets": {
            "social_protection_registry": {
                "id": "social_protection_registry",
                "title": "Social Protection Registry",
                "entities": {
                    "household": _entity_definition(
                        "household",
                        "Household",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("national_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("district", filter_ops=["eq", "in"]),
                            _field("poverty_score", "number", ["eq", "gte", "lte"], sensitive=True),
                            _field("eligibility_band", filter_ops=["eq", "in"]),
                            _field("household_size", "integer", sensitive=True),
                            _field("active_members", "integer", sensitive=True),
                            _field("deceased_member_count", "integer", sensitive=True),
                        ],
                    ),
                    "person": _entity_definition(
                        "person",
                        "Person",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("household_id", filter_ops=["eq", "in"]),
                            _field("national_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("relationship", filter_ops=["eq", "in"], sensitive=True),
                            _field("age", "integer", ["eq", "gte", "lte"], sensitive=True),
                            _field("alive", "boolean", ["eq"], sensitive=True),
                            _field("disability_status", filter_ops=["eq", "in"], sensitive=True),
                        ],
                    ),
                    "program_enrollment": _entity_definition(
                        "program_enrollment",
                        "Program Enrollment",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("household_id", filter_ops=["eq", "in"]),
                            _field("person_id", filter_ops=["eq", "in"]),
                            _field("national_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("program_code", filter_ops=["eq", "in"]),
                            _field("enrollment_status", filter_ops=["eq", "in"]),
                            _field("benefit_amount", "number", ["eq", "gte", "lte"], sensitive=True),
                            _field("enrolled_on", "date", ["eq", "gte", "lte"]),
                        ],
                    ),
                    "household_membership": _entity_definition(
                        "household_membership",
                        "Household Membership",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("household_id", filter_ops=["eq", "in"]),
                            _field("person_id", filter_ops=["eq", "in"]),
                            _field("relationship_type", filter_ops=["eq", "in"], sensitive=True),
                            _field("start_date", "date", ["eq", "gte", "lte"]),
                            _field("end_date", "date", ["eq", "gte", "lte"]),
                            _field("membership_status", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "socio_economic_profile": _entity_definition(
                        "socio_economic_profile",
                        "Socio-Economic Profile",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("household_id", filter_ops=["eq", "in"]),
                            _field("observation_date", "date", ["eq", "gte", "lte"]),
                            _field("instrument", filter_ops=["eq", "in"]),
                            _field("collected_by", filter_ops=["eq", "in"], sensitive=True),
                            _field("source_version", filter_ops=["eq", "in"]),
                            _field("profile_status", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "scoring_event": _entity_definition(
                        "scoring_event",
                        "Scoring Event",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("profile_id", filter_ops=["eq", "in"]),
                            _field("scoring_rule", filter_ops=["eq", "in"]),
                            _field("scoring_version", filter_ops=["eq", "in"]),
                            _field("score_band", filter_ops=["eq", "in"]),
                            _field("valid_from", "date", ["eq", "gte", "lte"]),
                            _field("valid_until", "date", ["eq", "gte", "lte"]),
                            _field("scoring_status", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "program": _entity_definition(
                        "program",
                        "Program",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("display_name", filter_ops=["eq"]),
                            _field("authority", filter_ops=["eq", "in"]),
                            _field("benefit_type", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "entitlement": _entity_definition(
                        "entitlement",
                        "Entitlement",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("enrollment_id", filter_ops=["eq", "in"]),
                            _field("benefit_modality", filter_ops=["eq", "in"]),
                            _field("amount", "number", ["eq", "gte", "lte"], sensitive=True),
                            _field("amount_band", filter_ops=["eq", "in"]),
                            _field("currency", filter_ops=["eq", "in"]),
                            _field("coverage_start", "date", ["eq", "gte", "lte"]),
                            _field("coverage_end", "date", ["eq", "gte", "lte"]),
                            _field("entitlement_status", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "payment_event": _entity_definition(
                        "payment_event",
                        "Payment Event",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("entitlement_id", filter_ops=["eq", "in"]),
                            _field("cycle", filter_ops=["eq", "in"]),
                            _field("status", filter_ops=["eq", "in"]),
                            _field("delivery_channel", filter_ops=["eq", "in"]),
                            _field("payment_date", "date", ["eq", "gte", "lte"]),
                            _field("reconciled", "boolean", ["eq"]),
                        ],
                    ),
                    "functioning_profile": _entity_definition(
                        "functioning_profile",
                        "Functioning Profile",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("person_id", filter_ops=["eq", "in"]),
                            _field("national_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("instrument_code", filter_ops=["eq", "in"]),
                            _field("administration_date", "date", ["eq", "gte", "lte"]),
                            _field("respondent_relationship", filter_ops=["eq", "in"], sensitive=True),
                            _field("domain_severities", sensitive=True),
                            _field("disability_identifier_met", "boolean", ["eq"], sensitive=True),
                            _field("domains_triggering_identifier", sensitive=True),
                            _field("source_version", filter_ops=["eq", "in"]),
                        ],
                    ),
                    "disability_determination": _entity_definition(
                        "disability_determination",
                        "Disability Determination",
                        [
                            _field("id", filter_ops=["eq", "in"]),
                            _field("person_id", filter_ops=["eq", "in"]),
                            _field("national_id", filter_ops=["eq", "in"], sensitive=True),
                            _field("authority", filter_ops=["eq", "in"]),
                            _field("determination_status", filter_ops=["eq", "in"]),
                            _field("support_category", filter_ops=["eq", "in"], sensitive=True),
                            _field("valid_from", "date", ["eq", "gte", "lte"]),
                            _field("valid_until", "date", ["eq", "gte", "lte"]),
                            _field("review_due", "date", ["eq", "gte", "lte"]),
                        ],
                    ),
                },
                "aggregates": {
                    "households_by_eligibility_band": {
                        "id": "households_by_eligibility_band",
                        "title": "Households by eligibility band",
                        "measures": ["household_count", "average_poverty_score"],
                        "group_by": ["eligibility_band", "district"],
                        "allowed_filters": {
                            "eligibility_band": ["eq", "in"],
                            "district": ["eq", "in"],
                            "poverty_score": ["gte", "lte", "between"],
                        },
                    }
                },
            }
        },
        "comparison": {
            "relay_fields_visible": 8,
            "related_claim": "household-eligibility-band",
            "notary_fields_returned": 1,
            "raw_row_returned_by_notary": "no",
        },
    },
    "health": {
        "id": "health",
        "label": "Health",
        "service_id": "health-relay",
        "base_url": "https://health-relay.lab.registrystack.org",
        "metadata_credential_id": "health-metadata",
        "row_reader_credential_id": "health-row-reader",
        "evidence_credential_id": "health-evidence-only",
        "default_dataset": "health_registry",
        "default_entity": "health_facility",
        "default_limit": 1,
        "purpose": PURPOSE,
        "related_claim_service_ids": ["shared-eligibility-notary"],
        "datasets": {
            "health_registry": {
                "id": "health_registry",
                "title": "Applicant Service Availability Projection",
                "entities": {
                    "health_facility": {
                        "id": "health_facility",
                        "title": "Applicant Service Availability",
                        "fields": [
                            {"name": "id", "type": "string", "filter_ops": ["eq", "in"], "sensitive": False},
                            {"name": "national_id", "type": "string", "filter_ops": ["eq", "in"], "sensitive": True},
                            {"name": "facility_name", "type": "string", "filter_ops": [], "sensitive": False},
                            {"name": "district", "type": "string", "filter_ops": ["eq", "in"], "sensitive": False},
                            {"name": "license_status", "type": "string", "filter_ops": ["eq", "in"], "sensitive": False},
                            {"name": "maternal_service_available", "type": "boolean", "filter_ops": ["eq"], "sensitive": False},
                            {"name": "pediatric_service_available", "type": "boolean", "filter_ops": ["eq"], "sensitive": False},
                            {"name": "practitioner_credential_active", "type": "boolean", "filter_ops": ["eq"], "sensitive": False},
                            {"name": "updated_on", "type": "date", "filter_ops": [], "sensitive": False},
                        ],
                    }
                },
                "aggregates": {},
            }
        },
        "comparison": {
            "relay_fields_visible": 9,
            "related_claim": "health-service-available",
            "notary_fields_returned": 1,
            "raw_row_returned_by_notary": "no",
        },
    },
    "agriculture": {
        "id": "agriculture",
        "label": "Agriculture",
        "service_id": "agri-relay",
        "base_url": "https://agri-relay.lab.registrystack.org",
        "metadata_credential_id": "agri-metadata",
        "row_reader_credential_id": "agri-row-reader",
        "aggregate_reader_credential_id": "agri-aggregate-reader",
        "evidence_credential_id": "agri-evidence-only",
        "default_dataset": "agri_registry",
        "default_entity": "farmer",
        "default_limit": 1,
        "purpose": "https://demo.example.gov/purpose/nagdi/climate-smart-input-support",
        "related_claim_service_ids": ["agriculture-notary"],
        "datasets": {
            "agri_registry": {
                "id": "agri_registry",
                "title": "NAgDI Agricultural Registries",
                "entities": {
                    "farmer": {
                        "id": "farmer",
                        "title": "Farmer",
                        "fields": [
                            {"name": "id", "type": "string", "filter_ops": ["eq", "in"], "sensitive": False},
                            {"name": "national_id", "type": "string", "filter_ops": ["eq", "in"], "sensitive": True},
                            {"name": "given_name", "type": "string", "filter_ops": ["eq"], "sensitive": True},
                            {"name": "family_name", "type": "string", "filter_ops": ["eq"], "sensitive": True},
                            {"name": "district", "type": "string", "filter_ops": ["eq", "in"], "sensitive": False},
                            {"name": "registration_status", "type": "string", "filter_ops": ["eq", "in"], "sensitive": False},
                            {"name": "smallholder_status", "type": "string", "filter_ops": ["eq", "in"], "sensitive": False},
                        ],
                    }
                },
                "aggregates": {},
            }
        },
        "comparison": {
            "relay_fields_visible": 7,
            "related_claim": "eligible-for-climate-smart-input-voucher",
            "notary_fields_returned": 1,
            "raw_row_returned_by_notary": "no",
        },
    },
}


def registry_ids() -> list[str]:
    return list(REGISTRY_ORDER)


def _registry_catalog(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not config:
        return REGISTRIES
    return discovery.discover_relay_registries(config, REGISTRIES, REGISTRY_ORDER)


def registry_config(registry_id: str) -> dict[str, Any]:
    return registry_config_for({}, registry_id)


def registry_config_for(config: dict[str, Any], registry_id: str) -> dict[str, Any]:
    registries = _registry_catalog(config)
    if registry_id not in registries:
        raise ExplorerInputError(
            "explorer.unknown_registry",
            "Unknown registry id.",
            field="registry_id",
            allowed=registry_ids(),
        )
    return registries[registry_id]


def registry_catalog_payload(config: dict[str, Any]) -> dict[str, Any]:
    registries = _registry_catalog(config)
    return {
        "ok": True,
        "registries": [_registry_summary(registries[registry_id], config) for registry_id in REGISTRY_ORDER],
        "default_registry_id": "civil",
        "max_limit": EXPLORER_MAX_LIMIT,
    }


def registry_metadata_payload(config: dict[str, Any], registry_id: str) -> dict[str, Any]:
    if registry_id not in REGISTRIES:
        return unknown_id_error("registry", registry_id, registry_ids())
    registry = registry_config_for(config, registry_id)
    payload = _registry_summary(registry, config)
    payload["datasets"] = deepcopy(list(registry["datasets"].values()))
    return {"ok": True, "registry": payload}


def default_civil_relay_payload(config: dict[str, Any]) -> dict[str, Any]:
    registry = registry_config_for(config, "civil")
    dataset_id = registry["default_dataset"]
    entity_id = registry["default_entity"]
    limit = registry["default_limit"]
    credential_id = registry["row_reader_credential_id"]
    path = record_path(dataset_id, entity_id, limit=limit, filters=[])
    request = _relay_request_source(config, registry, credential_id, path, registry["purpose"])
    fields = registry["datasets"][dataset_id]["entities"][entity_id]["fields"]
    return {
        "ok": True,
        "mode": "preview",
        "registry_id": "civil",
        "dataset_id": dataset_id,
        "entity_id": entity_id,
        "limit": limit,
        "fields": deepcopy(fields),
        "comparison": deepcopy(registry["comparison"]),
        "summary": {
            "http_status": "not_run",
            "records_returned": 0,
            "acting_as": "a row-reader service allowed to inspect seeded civil records",
            "request_purpose": "present",
            "fields_visible": len(fields),
        },
        "request_source": request,
        "curl": safe_curl(request["method"], request["url"], request["headers"]),
    }


def entity_schema_payload(registry_id: str, dataset_id: str, entity_id: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    registry = registry_config_for(config or {}, registry_id)
    dataset = _dataset(registry, dataset_id)
    entity = _entity(dataset, entity_id)
    return {
        "ok": True,
        "registry_id": registry_id,
        "dataset_id": dataset_id,
        "entity_id": entity_id,
        "entity": deepcopy(entity),
        "fields": deepcopy(entity.get("fields", [])),
    }


def record_query_payload(
    config: dict[str, Any],
    registry_id: str,
    dataset_id: str,
    entity_id: str,
    *,
    limit: Any = None,
    filters: list[dict[str, str]] | None = None,
    credential_id: str = "",
    purpose: str = "",
) -> dict[str, Any]:
    built = build_record_request(
        config,
        registry_id,
        dataset_id,
        entity_id,
        limit=limit,
        filters=filters,
        credential_id=credential_id,
        purpose=purpose,
    )
    validated = built["validated"]
    registry = registry_config_for(config, registry_id)
    dataset = _dataset(registry, dataset_id)
    entity = _entity(dataset, entity_id)
    sample_rows = _sample_records(registry_id, dataset_id, entity_id, EXPLORER_MAX_LIMIT, config=config)
    rows = _filter_sample_records(sample_rows, validated["filters"])[:validated["limit"]]
    fields = deepcopy(entity.get("fields", []))
    response = {
        "status": "preview",
        "headers": {"content-type": "application/json; charset=utf-8"},
        "body": {
            "records": rows,
            "limit": validated["limit"],
            "filters": validated["filters"],
            "dataset_id": dataset_id,
            "entity_id": entity_id,
        },
        "error": "",
    }
    return {
        **built,
        "mode": "preview",
        "registry_id": registry_id,
        "dataset_id": dataset_id,
        "entity_id": entity_id,
        "dataset": {"id": dataset_id, "title": dataset.get("title", dataset_id)},
        "entity": deepcopy(entity),
        "fields": fields,
        "records": rows,
        "rows": rows,
        "status": "preview",
        "comparison": deepcopy(registry["comparison"]),
        "summary": {
            "http_status": "preview",
            "records_returned": len(rows),
            "acting_as": _acting_as(validated["credential_id"]),
            "request_purpose": "present" if purpose or registry.get("purpose") else "absent",
            "fields_visible": len(fields),
        },
        "request": built["request_source"],
        "response": response,
        "response_source": response,
    }


def aggregates_payload(registry_id: str, dataset_id: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    registry = registry_config_for(config or {}, registry_id)
    dataset = _dataset(registry, dataset_id)
    return {
        "ok": True,
        "registry_id": registry_id,
        "dataset_id": dataset_id,
        "aggregates": deepcopy(list(dataset.get("aggregates", {}).values())),
    }


def aggregate_payload(
    config: dict[str, Any],
    registry_id: str,
    dataset_id: str,
    aggregate_id: str,
    *,
    filters: list[dict[str, str]] | None = None,
    purpose: str = "",
) -> dict[str, Any]:
    built = build_aggregate_request(
        config,
        registry_id,
        dataset_id,
        aggregate_id,
        filters=filters,
        purpose=purpose,
    )
    validated = validate_aggregate_query(registry_id, dataset_id, aggregate_id, filters, config)
    rows = _sample_aggregate_records(registry_id, aggregate_id)
    response = {
        "status": "preview",
        "headers": {"content-type": "application/json; charset=utf-8"},
        "body": {"observations": rows, "aggregate_id": aggregate_id},
        "error": "",
    }
    return {
        **built,
        "mode": "preview",
        "registry_id": registry_id,
        "dataset_id": dataset_id,
        "aggregate_id": aggregate_id,
        "aggregate": deepcopy(validated["aggregate"]),
        "observations": rows,
        "rows": rows,
        "status": "preview",
        "request": built["request_source"],
        "response": response,
        "response_source": response,
    }


def validate_record_query(
    registry_id: str,
    dataset_id: str,
    entity_id: str,
    raw_limit: Any,
    filters: list[dict[str, str]],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    registry = registry_config_for(config or {}, registry_id)
    dataset = _dataset(registry, dataset_id)
    entity = _entity(dataset, entity_id)
    limit = validate_limit(raw_limit, default=registry.get("default_limit", 1), max_limit=EXPLORER_MAX_LIMIT)
    allowed_filters = _allowed_entity_filters(entity)
    validated_filters = validate_filters(filters, allowed_filters)
    return {
        "registry": registry,
        "dataset": dataset,
        "entity": entity,
        "limit": limit,
        "filters": validated_filters,
    }


def build_record_request(
    config: dict[str, Any],
    registry_id: str,
    dataset_id: str,
    entity_id: str,
    *,
    limit: Any = None,
    filters: list[dict[str, str]] | None = None,
    credential_id: str = "",
    purpose: str = "",
) -> dict[str, Any]:
    validated = validate_record_query(registry_id, dataset_id, entity_id, limit, filters or [], config)
    registry = validated["registry"]
    selected_credential = credential_id or registry.get("row_reader_credential_id", "")
    _validate_registry_credential(registry, selected_credential)
    path = record_path(dataset_id, entity_id, limit=validated["limit"], filters=validated["filters"])
    request = _relay_request_source(config, registry, selected_credential, path, purpose or registry.get("purpose", PURPOSE))
    return {
        "ok": True,
        "request_source": request,
        "curl": safe_curl(request["method"], request["url"], request["headers"]),
        "validated": {
            "registry_id": registry_id,
            "dataset_id": dataset_id,
            "entity_id": entity_id,
            "limit": validated["limit"],
            "filters": validated["filters"],
            "credential_id": selected_credential,
        },
    }


def run_record_query(
    config: dict[str, Any],
    registry_id: str,
    dataset_id: str,
    entity_id: str,
    *,
    limit: Any = None,
    filters: list[dict[str, str]] | None = None,
    credential_id: str = "",
    purpose: str = "",
    timeout: float = 8.0,
) -> dict[str, Any]:
    built = build_record_request(
        config,
        registry_id,
        dataset_id,
        entity_id,
        limit=limit,
        filters=filters,
        credential_id=credential_id,
        purpose=purpose,
    )
    headers = _execution_headers(config, built["validated"]["credential_id"], built["request_source"]["headers"])
    result = http_json("GET", built["request_source"]["url"], headers, timeout=timeout)
    return {**built, "mode": "live", "response_source": source_response(result)}


def validate_aggregate_query(
    registry_id: str,
    dataset_id: str,
    aggregate_id: str,
    filters: list[dict[str, str]] | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    registry = registry_config_for(config or {}, registry_id)
    dataset = _dataset(registry, dataset_id)
    aggregate = _aggregate(dataset, aggregate_id)
    validated_filters = validate_filters(filters or [], aggregate.get("allowed_filters", {}))
    return {"registry": registry, "dataset": dataset, "aggregate": aggregate, "filters": validated_filters}


def build_aggregate_request(
    config: dict[str, Any],
    registry_id: str,
    dataset_id: str,
    aggregate_id: str,
    *,
    filters: list[dict[str, str]] | None = None,
    purpose: str = "",
) -> dict[str, Any]:
    validated = validate_aggregate_query(registry_id, dataset_id, aggregate_id, filters, config)
    registry = validated["registry"]
    credential_id = registry.get("aggregate_reader_credential_id", "")
    _validate_registry_credential(registry, credential_id)
    path = aggregate_path(dataset_id, aggregate_id, filters=validated["filters"])
    request = _relay_request_source(config, registry, credential_id, path, purpose or registry.get("purpose", PURPOSE))
    return {
        "ok": True,
        "request_source": request,
        "curl": safe_curl(request["method"], request["url"], request["headers"]),
        "validated": {
            "registry_id": registry_id,
            "dataset_id": dataset_id,
            "aggregate_id": aggregate_id,
            "filters": validated["filters"],
            "credential_id": credential_id,
        },
    }


def record_path(dataset_id: str, entity_id: str, *, limit: int, filters: list[dict[str, str]]) -> str:
    query = urlencode({"limit": limit})
    filter_query = filters_to_query(filters)
    if filter_query:
        query = f"{query}&{filter_query}"
    return f"/v1/datasets/{dataset_id}/entities/{entity_id}/records?{query}"


def aggregate_path(dataset_id: str, aggregate_id: str, *, filters: list[dict[str, str]]) -> str:
    query = filters_to_query(filters)
    suffix = f"?{query}" if query else ""
    return f"/v1/datasets/{dataset_id}/aggregates/{aggregate_id}{suffix}"


def registry_error_payload(registry_id: str) -> dict[str, Any]:
    return unknown_id_error("registry", registry_id, registry_ids())


def invalid_query_payload(error: ExplorerInputError) -> dict[str, Any]:
    return error.payload()


def _registry_summary(registry: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    credential_ids = [
        registry.get("metadata_credential_id", ""),
        registry.get("row_reader_credential_id", ""),
        registry.get("aggregate_reader_credential_id", ""),
        registry.get("evidence_credential_id", ""),
    ]
    return {
        "id": registry["id"],
        "label": registry["label"],
        "service_id": registry["service_id"],
        "base_url": registry["base_url"],
        "default_dataset": registry["default_dataset"],
        "default_entity": registry["default_entity"],
        "default_aggregate": registry.get("default_aggregate", ""),
        "default_limit": registry["default_limit"],
        "purpose": registry["purpose"],
        "related_claim_service_ids": list(registry["related_claim_service_ids"]),
        "credentials": [
            credential_display(config, credential_id)
            for credential_id in credential_ids
            if credential_id
        ],
        "comparison": deepcopy(registry["comparison"]),
        "discovery": deepcopy(registry.get("discovery", {"status": "overlay", "source": "overlay"})),
    }


def _dataset(registry: dict[str, Any], dataset_id: str) -> dict[str, Any]:
    datasets = registry.get("datasets", {})
    if dataset_id not in datasets:
        raise ExplorerInputError(
            "explorer.unsupported_dataset",
            "This dataset is not available for the selected registry.",
            field="dataset",
            allowed=sorted(datasets),
        )
    return datasets[dataset_id]


def _entity(dataset: dict[str, Any], entity_id: str) -> dict[str, Any]:
    entities = dataset.get("entities", {})
    if entity_id not in entities:
        raise ExplorerInputError(
            "explorer.unsupported_entity",
            "This entity is not available for the selected dataset.",
            field="entity",
            allowed=sorted(entities),
        )
    return entities[entity_id]


def _aggregate(dataset: dict[str, Any], aggregate_id: str) -> dict[str, Any]:
    aggregates = dataset.get("aggregates", {})
    if aggregate_id not in aggregates:
        raise ExplorerInputError(
            "explorer.unsupported_aggregate",
            "This aggregate is not available for the selected dataset.",
            field="aggregate",
            allowed=sorted(aggregates),
        )
    return aggregates[aggregate_id]


def _allowed_entity_filters(entity: dict[str, Any]) -> dict[str, list[str]]:
    return {
        field["name"]: list(field.get("filter_ops", []))
        for field in entity.get("fields", [])
        if field.get("filter_ops")
    }


def _entity_field_types(registry_id: str, dataset_id: str, entity_id: str, config: dict[str, Any] | None = None) -> dict[str, str]:
    entity = _registry_catalog(config or {})[registry_id]["datasets"][dataset_id]["entities"][entity_id]
    return {field["name"]: field.get("type", "string") for field in entity.get("fields", [])}


def _shape_record(row: dict[str, Any], aliases: dict[str, str], field_types: dict[str, str]) -> dict[str, Any]:
    shaped: dict[str, Any] = {}
    for key, value in row.items():
        output_key = aliases.get(key, key)
        if output_key in field_types:
            shaped[output_key] = _coerce_field_value(value, field_types[output_key])
    return shaped


def _coerce_field_value(value: Any, field_type: str) -> Any:
    if value in (None, ""):
        return ""
    if field_type == "boolean":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "y"}
    if field_type == "integer":
        try:
            return int(float(str(value)))
        except ValueError:
            return value
    if field_type == "number":
        try:
            return float(str(value))
        except ValueError:
            return value
    if field_type == "date" and str(value).replace(".", "", 1).isdigit():
        try:
            return _excel_date_to_iso(float(str(value)))
        except (OverflowError, ValueError):
            return value
    return value


def _excel_date_to_iso(serial: float) -> str:
    if serial < 1 or serial > 100000:
        raise ValueError("Excel date serial is outside the supported demo fixture range.")
    return (datetime(1899, 12, 30) + timedelta(days=serial)).date().isoformat()


def _sample_xlsx_sheet(path: Path, sheet_name: str, limit: int) -> list[dict[str, Any]]:
    ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    rel_ns = {"rel": "http://schemas.openxmlformats.org/package/2006/relationships"}
    with ZipFile(path) as archive:
        shared_strings = _xlsx_shared_strings(archive, ns)
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        rel_map = {rel.attrib["Id"]: _xlsx_target_path(rel.attrib["Target"]) for rel in rels.findall("rel:Relationship", rel_ns)}
        sheets = workbook.find("s:sheets", ns)
        if sheets is None:
            return []
        for sheet in sheets.findall("s:sheet", ns):
            if sheet.attrib.get("name") != sheet_name:
                continue
            rel_id = sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id", "")
            return _read_xlsx_rows(archive, rel_map[rel_id], shared_strings, ns, limit)
    return []


def _xlsx_shared_strings(archive: ZipFile, ns: dict[str, str]) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    return ["".join(text.text or "" for text in item.findall(".//s:t", ns)) for item in root.findall("s:si", ns)]


def _xlsx_target_path(target: str) -> str:
    normalized = target.lstrip("/")
    return normalized if normalized.startswith("xl/") else f"xl/{normalized}"


def _read_xlsx_rows(archive: ZipFile, sheet_path: str, shared_strings: list[str], ns: dict[str, str], limit: int) -> list[dict[str, Any]]:
    root = ET.fromstring(archive.read(sheet_path))
    rows: list[list[Any]] = []
    for sheet_row in root.findall(".//s:sheetData/s:row", ns):
        values: list[Any] = []
        for cell in sheet_row.findall("s:c", ns):
            index = _xlsx_column_index(cell.attrib.get("r", "A1"))
            while len(values) <= index:
                values.append("")
            values[index] = _xlsx_cell_value(cell, shared_strings, ns)
        rows.append(values)
        if len(rows) >= limit + 1:
            break
    if not rows:
        return []
    headers = [str(value) for value in rows[0]]
    return [{header: row[index] if index < len(row) else "" for index, header in enumerate(headers)} for row in rows[1 : limit + 1]]


def _xlsx_column_index(ref: str) -> int:
    letters = "".join(character for character in ref if character.isalpha())
    index = 0
    for letter in letters:
        index = index * 26 + ord(letter.upper()) - 64
    return max(index - 1, 0)


def _xlsx_cell_value(cell: ET.Element, shared_strings: list[str], ns: dict[str, str]) -> Any:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return "".join(text.text or "" for text in cell.findall(".//s:t", ns))
    value = cell.find("s:v", ns)
    if value is None:
        return ""
    text = value.text or ""
    if cell_type == "s" and text.isdigit():
        index = int(text)
        if index < len(shared_strings):
            return shared_strings[index]
    return text


def _sample_records(registry_id: str, dataset_id: str, entity_id: str, limit: int, *, config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if registry_id == "civil" and dataset_id == "civil_registry":
        files = {
            "civil_person": ("civil-persons.csv", {}),
            "civil_person_detail": ("civil-person-details.csv", {"person_id": "id"}),
            "civil_identifier": ("civil-identifiers.csv", {"identifier_id": "id"}),
            "birth_event": ("birth-events.csv", {"event_id": "id"}),
            "death_event": ("death-events.csv", {"event_id": "id"}),
            "marriage_event": ("marriage-events.csv", {"event_id": "id"}),
            "civil_status_record": ("civil-status-records.csv", {"record_id": "id"}),
            "certificate": ("certificates.csv", {"certificate_number": "id"}),
            "relationship": ("relationships.csv", {"relationship_id": "id"}),
        }
        if entity_id not in files:
            return []
        filename, aliases = files[entity_id]
        path = REPO_ROOT / "data" / "civil" / filename
        if path.exists():
            with path.open(encoding="utf-8", newline="") as handle:
                fields = _entity_field_types(registry_id, dataset_id, entity_id, config)
                return [_shape_record(dict(row), aliases, fields) for _, row in zip(range(limit), csv.DictReader(handle))]
        if entity_id == "civil_person":
            return [
                {
                    "national_id": "NID-1001",
                    "given_name": "Miguel",
                    "surname": "Santos",
                    "birth_date": "2016-01-15",
                    "life_stage": "child",
                    "deceased": False,
                    "district": "north",
                }
            ][:limit]
        return []
    if registry_id == "social-protection" and dataset_id == "social_protection_registry":
        sheets = {
            "household": ("Households", {"household_id": "id"}),
            "person": ("Persons", {"person_id": "id"}),
            "program_enrollment": ("Enrollments", {"enrollment_id": "id", "status": "enrollment_status"}),
            "household_membership": ("GroupMemberships", {"membership_id": "id"}),
            "socio_economic_profile": ("SocioEconomicProfiles", {"profile_id": "id"}),
            "scoring_event": ("ScoringEvents", {"scoring_id": "id"}),
            "program": ("Programs", {"program_code": "id"}),
            "entitlement": ("Entitlements", {"entitlement_id": "id"}),
            "payment_event": ("PaymentEvents", {"payment_id": "id"}),
            "functioning_profile": ("FunctioningProfiles", {"profile_id": "id"}),
            "disability_determination": ("DisabilityDeterminations", {"determination_id": "id"}),
        }
        if entity_id not in sheets:
            return []
        sheet_name, aliases = sheets[entity_id]
        path = REPO_ROOT / "data" / "social-protection" / "social-protection.xlsx"
        if path.exists():
            fields = _entity_field_types(registry_id, dataset_id, entity_id, config)
            return [_shape_record(row, aliases, fields) for row in _sample_xlsx_sheet(path, sheet_name, limit)]
        if entity_id == "household":
            return [
                {
                    "id": "HH-1001",
                    "national_id": "NID-1001",
                    "district": "north",
                    "poverty_score": 18,
                    "eligibility_band": "high",
                    "household_size": 5,
                    "active_members": 5,
                    "deceased_member_count": 0,
                },
                {
                    "id": "HH-1002",
                    "national_id": "NID-1002",
                    "district": "south",
                    "poverty_score": 42,
                    "eligibility_band": "medium",
                    "household_size": 3,
                    "active_members": 3,
                    "deceased_member_count": 0,
                },
            ][:limit]
        return []
    if registry_id == "health" and dataset_id == "health_registry" and entity_id == "health_facility":
        return [
            {
                "id": "HF-1001",
                "national_id": "NID-1001",
                "facility_name": "North District Clinic",
                "district": "north",
                "license_status": "active",
                "maternal_service_available": True,
                "pediatric_service_available": True,
                "practitioner_credential_active": True,
                "updated_on": "2026-05-15",
            },
            {
                "id": "HF-1002",
                "national_id": "NID-1002",
                "facility_name": "South District Health Post",
                "district": "south",
                "license_status": "active",
                "maternal_service_available": False,
                "pediatric_service_available": True,
                "practitioner_credential_active": True,
                "updated_on": "2026-05-12",
            },
        ][:limit]
    if registry_id == "agriculture" and dataset_id == "agri_registry" and entity_id == "farmer":
        return [
            {
                "id": "FARMER-1001",
                "national_id": "NID-1001",
                "given_name": "Lina",
                "family_name": "Santos",
                "district": "north",
                "registration_status": "active",
                "smallholder_status": "qualified",
            },
            {
                "id": "FARMER-1002",
                "national_id": "NID-1002",
                "given_name": "Ramon",
                "family_name": "Dela Cruz",
                "district": "west",
                "registration_status": "under_review",
                "smallholder_status": "pending",
            },
        ][:limit]
    return []


def _filter_sample_records(rows: list[dict[str, Any]], filters: list[dict[str, str]]) -> list[dict[str, Any]]:
    filtered = rows
    for item in filters:
        field = item["field"]
        op = item["op"]
        value = item["value"]
        if value == "":
            continue
        filtered = [row for row in filtered if _record_matches_filter(row, field, op, value)]
    return filtered


def _record_matches_filter(row: dict[str, Any], field: str, op: str, value: str) -> bool:
    actual = row.get(field)
    if op == "in":
        allowed = {part.strip().lower() for part in value.split(",") if part.strip()}
        return str(actual).lower() in allowed
    if op in {"gte", "lte"}:
        return _compare_ordered(actual, value, op)
    return str(actual).lower() == value.lower()


def _compare_ordered(actual: Any, value: str, op: str) -> bool:
    if actual in (None, ""):
        return False
    actual_text = str(actual)
    try:
        actual_value: Any = float(actual_text)
        expected_value: Any = float(value)
    except ValueError:
        actual_value = actual_text
        expected_value = value
    if op == "gte":
        return actual_value >= expected_value
    return actual_value <= expected_value


def _sample_aggregate_records(registry_id: str, aggregate_id: str) -> list[dict[str, Any]]:
    if registry_id == "social-protection" and aggregate_id == "households_by_eligibility_band":
        return [
            {"eligibility_band": "high", "district": "central", "household_count": 4},
            {"eligibility_band": "medium", "district": "north", "household_count": 3},
        ]
    return []


def _acting_as(credential_id: str) -> str:
    if credential_id.endswith("evidence-only"):
        return "a service allowed to ask questions, not read records"
    if credential_id.endswith("aggregate-reader"):
        return "a planning service allowed to read configured aggregates"
    return "a row-reader service allowed to inspect seeded records"


def _validate_registry_credential(registry: dict[str, Any], credential_id: str) -> None:
    allowed = [
        registry.get("metadata_credential_id", ""),
        registry.get("row_reader_credential_id", ""),
        registry.get("aggregate_reader_credential_id", ""),
        registry.get("evidence_credential_id", ""),
    ]
    allowed = [item for item in allowed if item]
    if not credential_id or credential_id not in allowed:
        raise ExplorerInputError(
            "explorer.unsupported_credential",
            "This credential is not configured for the selected registry.",
            field="credential_id",
            allowed=allowed,
        )


def _relay_request_source(
    config: dict[str, Any],
    registry: dict[str, Any],
    credential_id: str,
    path: str,
    purpose: str,
) -> dict[str, Any]:
    credential = credential_for_execution(config, credential_id)
    display_name, display_value = display_auth_header_pair(credential)
    headers = {display_name: display_value}
    if purpose:
        headers["Data-Purpose"] = purpose
    url = service_url(config, credential_id, path, fallback_base_url=registry["base_url"])
    return request_source("GET", url, headers)


def _execution_headers(config: dict[str, Any], credential_id: str, display_headers: dict[str, str]) -> dict[str, str]:
    credential = credential_for_execution(config, credential_id)
    auth_name, auth_value = display_auth_header_pair(credential)
    if credential.get("display_policy") == "public":
        auth_name, auth_value = credential.get("auth_header", "").split(": ", 1) if credential.get("auth_header") else display_auth_header_pair(credential)
    headers = dict(display_headers)
    headers[auth_name] = auth_value
    return headers


def controlled_exception_payload(error: Exception) -> dict[str, Any]:
    if isinstance(error, ExplorerInputError):
        return error.payload()
    return error_payload("explorer.invalid_query", "The explorer query is invalid.")
