#!/usr/bin/env python3
"""Public attestation metadata and label checks for guided scenarios."""

from __future__ import annotations

import re
from typing import Any


RAW_COMPATIBILITY_IDS = (
    "person-is-alive",
    "opencrvs-birth-record-exists",
    "opencrvs-date-of-birth",
    "opencrvs-age-band",
    "beneficiary-active",
    "program-enrollment-status",
    "household-eligibility-band",
    "civil-record-present",
    "health-service-available",
    "social-program-active",
    "eligible-for-combined-support",
    "dhis2-child-program-active",
    "eligible-for-climate-smart-input-voucher",
    "voucher-eligibility-reason-code",
    "household-composition",
    "caregiver-link",
    "disability-determination",
    "functioning-assessment",
)

RAW_COMPATIBILITY_RE = re.compile(r"\b(" + "|".join(re.escape(item) for item in RAW_COMPATIBILITY_IDS) + r")\b")

ATTESTATIONS: dict[str, dict[str, Any]] = {
    "vital-status-attestation": {
        "offering_id": "vital-status-attestation",
        "display_name": "Vital Status Attestation",
        "source_authority": "Civil Registry",
        "jurisdiction": "Demo civil registry",
        "lookup_profiles": ["by-national-id"],
        "publicschema_anchor": "CivilStatusRecord",
        "disclosure_profile": "predicate",
        "freshness": {"source_observed_at": "live civil registry lookup", "as_of": "request time"},
        "compatibility_claim_aliases": ["person-is-alive"],
    },
    "birth-registration-attestation": {
        "offering_id": "birth-registration-attestation",
        "display_name": "Birth Registration Attestation",
        "source_authority": "OpenCRVS and civil registry",
        "jurisdiction": "Demo civil registry",
        "lookup_profiles": ["by-national-id", "by-certificate-number"],
        "publicschema_anchor": "Birth",
        "disclosure_profile": "predicate",
        "freshness": {"source_observed_at": "live registry lookup", "as_of": "request time"},
        "compatibility_claim_aliases": ["opencrvs-birth-record-exists"],
    },
    "health-programme-participation-attestation": {
        "offering_id": "health-programme-participation-attestation",
        "display_name": "Health Programme Participation Attestation",
        "source_authority": "DHIS2 health programme Notary",
        "jurisdiction": "Demo health programme",
        "lookup_profiles": ["by-source-record-id"],
        "publicschema_anchor": "Program",
        "disclosure_profile": "value or predicate",
        "freshness": {"source_observed_at": "DHIS2-backed Notary evaluation", "as_of": "request time"},
        "compatibility_claim_aliases": ["dhis2-child-program-active"],
    },
    "service-availability-attestation": {
        "offering_id": "service-availability-attestation",
        "display_name": "Service Availability Attestation",
        "source_authority": "Health service registry projection",
        "jurisdiction": "Demo service district",
        "lookup_profiles": ["by-national-id"],
        "publicschema_anchor": "HealthFacility",
        "disclosure_profile": "predicate",
        "freshness": {"source_observed_at": "local service projection", "as_of": "request time"},
        "compatibility_claim_aliases": ["health-service-available"],
    },
    "program-enrollment-attestation": {
        "offering_id": "program-enrollment-attestation",
        "display_name": "Program Enrollment Attestation",
        "source_authority": "Social protection programme MIS",
        "jurisdiction": "Demo social programme",
        "lookup_profiles": ["by-national-id", "by-program-case-id"],
        "publicschema_anchor": "Enrollment",
        "disclosure_profile": "predicate",
        "freshness": {"source_observed_at": "local programme registry", "as_of": "request time"},
        "compatibility_claim_aliases": ["beneficiary-active", "program-enrollment-status", "social-program-active"],
    },
    "household-composition-attestation": {
        "offering_id": "household-composition-attestation",
        "display_name": "Household Composition Attestation",
        "source_authority": "Social registry",
        "jurisdiction": "Demo social registry",
        "lookup_profiles": ["by-national-id", "by-household-anchor"],
        "publicschema_anchor": "Household",
        "disclosure_profile": "minimized value",
        "freshness": {"source_observed_at": "local social registry", "as_of": "request time"},
        "compatibility_claim_aliases": ["household-composition"],
    },
    "caregiver-link-attestation": {
        "offering_id": "caregiver-link-attestation",
        "display_name": "Parent Or Guardian Link Attestation",
        "source_authority": "Social registry or civil relationship registry",
        "jurisdiction": "Demo social registry",
        "lookup_profiles": ["by-child-national-id-and-caregiver-national-id"],
        "publicschema_anchor": "GroupMembership",
        "disclosure_profile": "predicate",
        "freshness": {"source_observed_at": "local household membership projection", "as_of": "request time"},
        "compatibility_claim_aliases": ["caregiver-link"],
    },
    "disability-determination-attestation": {
        "offering_id": "disability-determination-attestation",
        "display_name": "Disability Determination Attestation",
        "source_authority": "Disability assessment authority",
        "jurisdiction": "Demo social registry",
        "lookup_profiles": ["by-national-id"],
        "publicschema_anchor": "EligibilityDecision",
        "disclosure_profile": "minimized value",
        "freshness": {"source_observed_at": "local disability determination register", "as_of": "request time"},
        "compatibility_claim_aliases": ["disability-determination"],
    },
    "functioning-assessment-attestation": {
        "offering_id": "functioning-assessment-attestation",
        "display_name": "Functioning Assessment Attestation",
        "source_authority": "Assessment registry",
        "jurisdiction": "Demo social registry",
        "lookup_profiles": ["by-national-id"],
        "publicschema_anchor": "FunctioningProfile",
        "disclosure_profile": "minimized value",
        "freshness": {"source_observed_at": "local functioning assessment source", "as_of": "request time"},
        "compatibility_claim_aliases": ["functioning-assessment"],
    },
    "combined-support-eligibility-attestation": {
        "offering_id": "combined-support-eligibility-attestation",
        "display_name": "Combined Support Eligibility Attestation",
        "source_authority": "Social Protection MIS",
        "jurisdiction": "Demo social programme",
        "lookup_profiles": ["by-national-id"],
        "publicschema_anchor": "EligibilityDecision",
        "disclosure_profile": "predicate",
        "freshness": {"source_observed_at": "composed source attestation checks", "as_of": "request time"},
        "compatibility_claim_aliases": ["eligible-for-combined-support"],
    },
    "agricultural-entitlement-attestation": {
        "offering_id": "agricultural-entitlement-attestation",
        "display_name": "Agricultural Entitlement Attestation",
        "source_authority": "Agriculture MIS",
        "jurisdiction": "Demo agriculture programme",
        "lookup_profiles": ["by-source-record-id"],
        "publicschema_anchor": "Entitlement",
        "disclosure_profile": "predicate or value",
        "freshness": {"source_observed_at": "local agriculture workbook-backed Notary", "as_of": "request time"},
        "compatibility_claim_aliases": ["eligible-for-climate-smart-input-voucher"],
    },
    "benefit-conflict-attestation": {
        "offering_id": "benefit-conflict-attestation",
        "display_name": "Benefit Conflict Attestation",
        "source_authority": "Agriculture MIS",
        "jurisdiction": "Demo agriculture programme",
        "lookup_profiles": ["by-source-record-id"],
        "publicschema_anchor": "PaymentEvent",
        "disclosure_profile": "predicate or reason code",
        "freshness": {"source_observed_at": "local agriculture workbook-backed Notary", "as_of": "request time"},
        "compatibility_claim_aliases": ["voucher-eligibility-reason-code"],
    },
}


def attestation(offering_id: str) -> dict[str, Any]:
    """Return a copy of public metadata for one attestation offering."""
    item = ATTESTATIONS[offering_id]
    return {
        **{key: value for key, value in item.items() if key != "compatibility_claim_aliases"},
        "lookup_profiles": list(item.get("lookup_profiles", [])),
        "freshness": dict(item.get("freshness", {})),
    }


def public_label_violations(value: Any, path: str = "$") -> list[str]:
    """Find raw compatibility ids in public first-level story language."""
    violations: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"id", "request_preview", "request_source", "response_source", "compatibility_claim_aliases"}:
                continue
            violations.extend(public_label_violations(item, f"{path}.{key}"))
        return violations
    if isinstance(value, list):
        for index, item in enumerate(value):
            violations.extend(public_label_violations(item, f"{path}[{index}]"))
        return violations
    if isinstance(value, str):
        match = RAW_COMPATIBILITY_RE.search(value)
        if match:
            violations.append(f"{path}: {match.group(1)}")
    return violations
