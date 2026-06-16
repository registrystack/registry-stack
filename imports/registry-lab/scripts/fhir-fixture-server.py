#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Small deterministic FHIR R4 fixture server for the local Notary lab."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def bundle(entries):
    return {
        "resourceType": "Bundle",
        "type": "searchset",
        "entry": [{"search": {"mode": "match"}, "resource": entry} for entry in entries],
    }


def patient(national_id, birth_date="1990-01-01", deceased=None):
    resource = {
        "resourceType": "Patient",
        "id": national_id,
        "birthDate": birth_date,
        "identifier": [{"system": "https://example.gov/id/national-id", "value": national_id}],
    }
    if deceased is not None:
        resource["deceasedBoolean"] = deceased
    return resource


def coding(system, code):
    return {"coding": [{"system": system, "code": code}]}


def coverage(beneficiary, status="active"):
    return {
        "resourceType": "Coverage",
        "id": "coverage-person-123",
        "status": status,
        "beneficiary": {"reference": beneficiary},
        "class": [{"value": "gold"}],
    }


def related_person(patient_ref, requester_id):
    return {
        "resourceType": "RelatedPerson",
        "id": "rel-guardian-1",
        "patient": {"reference": patient_ref},
        "identifier": [{"system": "https://example.gov/id/requester-id", "value": requester_id}],
        "relationship": [coding("http://terminology.hl7.org/CodeSystem/v3-RoleCode", "GUARD")],
    }


def practitioner(provider_id):
    return {
        "resourceType": "Practitioner",
        "id": provider_id,
        "identifier": [{"system": "https://example.gov/id/provider-id", "value": provider_id}],
    }


def practitioner_role(provider_ref):
    return {
        "resourceType": "PractitionerRole",
        "id": "role-provider-123-org-1",
        "active": True,
        "practitioner": {"reference": provider_ref},
        "organization": {"reference": "Organization/org-1"},
    }


def organization(organization_id):
    return {
        "resourceType": "Organization",
        "id": organization_id,
        "identifier": [{"system": "https://example.gov/id/organization-id", "value": organization_id}],
    }


def location(organization_ref):
    return {
        "resourceType": "Location",
        "id": "location-facility-1",
        "managingOrganization": {"reference": organization_ref},
    }


def healthcare_service(location_ref):
    return {
        "resourceType": "HealthcareService",
        "id": "service-facility-1",
        "active": True,
        "location": [{"reference": location_ref}],
        "type": [coding("http://terminology.hl7.org/CodeSystem/service-type", "general-practice")],
    }


def eligibility(patient_ref):
    return {
        "resourceType": "CoverageEligibilityResponse",
        "id": "eligibility-person-123",
        "status": "active",
        "outcome": "complete",
        "patient": {"reference": patient_ref},
        "insurance": [{"item": [{"category": coding("http://terminology.hl7.org/CodeSystem/service-type", "general-practice")}]}],
    }


def episode(patient_ref):
    return {
        "resourceType": "EpisodeOfCare",
        "id": "episode-person-123",
        "status": "active",
        "patient": {"reference": patient_ref},
        "type": [coding("https://example.gov/fhir/program-code", "tb-program")],
    }


def encounter(patient_ref):
    return {
        "resourceType": "Encounter",
        "id": "encounter-person-123",
        "status": "finished",
        "subject": {"reference": patient_ref},
        "type": [coding("https://example.gov/fhir/encounter-type", "annual-wellness")],
    }


def service_request(patient_ref):
    return {
        "resourceType": "ServiceRequest",
        "id": "referral-person-123",
        "status": "active",
        "intent": "order",
        "subject": {"reference": patient_ref},
        "code": coding("https://example.gov/fhir/referral-code", "general-referral"),
    }


def appointment(patient_ref):
    return {
        "resourceType": "Appointment",
        "id": "appointment-person-123",
        "status": "booked",
        "participant": [{"actor": {"reference": patient_ref}, "status": "accepted"}],
        "serviceType": [coding("http://terminology.hl7.org/CodeSystem/service-type", "general-practice")],
    }


def diagnostic_report(patient_ref):
    return {
        "resourceType": "DiagnosticReport",
        "id": "report-person-123",
        "status": "final",
        "subject": {"reference": patient_ref},
        "code": coding("https://loinc.org", "viral-load-panel"),
    }


def immunization(patient_ref):
    return {
        "resourceType": "Immunization",
        "id": "immunization-person-123",
        "status": "completed",
        "patient": {"reference": patient_ref},
        "vaccineCode": coding("http://hl7.org/fhir/sid/cvx", "03"),
        "occurrenceDateTime": "2026-01-15T00:00:00Z",
    }


def provenance(target_ref):
    return {
        "resourceType": "Provenance",
        "id": "provenance-person-123",
        "target": [{"reference": target_ref}],
        "recorded": "2026-06-16T00:00:00Z",
        "activity": coding("https://example.gov/fhir/provenance-activity", "verify"),
    }


def claim_response(patient_ref):
    return {
        "resourceType": "ClaimResponse",
        "id": "claim-response-person-123",
        "status": "active",
        "outcome": "complete",
        "patient": {"reference": patient_ref},
        "disposition": "approved",
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/ready":
            self.send_json({"status": "ready"})
            return
        if not parsed.path.startswith("/fhir/"):
            self.send_error(404)
            return
        resource = parsed.path.removeprefix("/fhir/")
        query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        self.send_json(bundle(self.search(resource, query)))

    def send_json(self, body):
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/fhir+json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def search(self, resource, query):
        identifier = query.get("identifier", "")
        national_id = identifier.removeprefix("https://example.gov/id/national-id|")
        provider_id = identifier.removeprefix("https://example.gov/id/provider-id|")
        organization_id = identifier.removeprefix("https://example.gov/id/organization-id|")
        patient_ref = query.get("patient") or query.get("subject") or query.get("beneficiary") or query.get("target")

        if resource == "Patient" and national_id in {"person-123", "smoke-person"}:
            return [patient(national_id)]
        if resource == "Coverage" and patient_ref in {"Patient/person-123", "Patient/smoke-person"}:
            return [coverage(patient_ref)]
        if resource == "RelatedPerson" and query.get("patient") == "Patient/person-123" and query.get("identifier", "").endswith("|guardian-1"):
            return [related_person("Patient/person-123", "guardian-1")]
        if resource == "Practitioner" and provider_id in {"provider-123", "smoke-provider"}:
            return [practitioner(provider_id)]
        if resource == "PractitionerRole" and query.get("practitioner") in {"Practitioner/provider-123", "Practitioner/smoke-provider"}:
            return [practitioner_role(query["practitioner"])]
        if resource == "Organization" and organization_id in {"facility-1", "smoke-facility"}:
            return [organization(organization_id)]
        if resource == "Location" and query.get("organization") in {"Organization/facility-1", "Organization/smoke-facility"}:
            return [location(query["organization"])]
        if resource == "HealthcareService" and query.get("location", "").startswith("Location/"):
            return [healthcare_service(query["location"])]
        if resource == "CoverageEligibilityResponse" and patient_ref in {"Patient/person-123", "Patient/smoke-person"}:
            return [eligibility(patient_ref)]
        if resource == "EpisodeOfCare" and patient_ref in {"Patient/person-123", "Patient/smoke-person"}:
            return [episode(patient_ref)]
        if resource == "Encounter" and patient_ref in {"Patient/person-123", "Patient/smoke-person"}:
            return [encounter(patient_ref)]
        if resource == "ServiceRequest" and patient_ref in {"Patient/person-123", "Patient/smoke-person"}:
            return [service_request(patient_ref)]
        if resource == "Appointment" and query.get("patient") in {"Patient/person-123", "Patient/smoke-person"}:
            return [appointment(query["patient"])]
        if resource == "DiagnosticReport" and patient_ref in {"Patient/person-123", "Patient/smoke-person"}:
            return [diagnostic_report(patient_ref)]
        if resource == "Immunization" and patient_ref in {"Patient/person-123", "Patient/smoke-person"}:
            return [immunization(patient_ref)]
        if resource == "Provenance" and patient_ref in {"Patient/person-123", "Patient/smoke-person"}:
            return [provenance(patient_ref)]
        if resource == "ClaimResponse" and query.get("patient") in {"Patient/person-123", "Patient/smoke-person"}:
            return [claim_response(query["patient"])]
        return []


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
