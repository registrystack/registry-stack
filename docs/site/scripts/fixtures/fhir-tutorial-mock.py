#!/usr/bin/env python3
"""Sanitized local FHIR responses for the executable documentation replay."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FHIR_MEDIA_TYPE = "application/fhir+json"
ORGANIZATION_TYPE_SYSTEM = (
    "http://terminology.hl7.org/CodeSystem/organization-type"
)
PATIENT_ID = "patient-local-001"
COVERAGE_ID = "coverage-local-001"
ORGANIZATION_ID = "organization-local-001"


def coverage():
    return {
        "resourceType": "Coverage",
        "id": COVERAGE_ID,
        "status": "active",
        "beneficiary": {"reference": f"Patient/{PATIENT_ID}"},
    }


def organization():
    return {
        "resourceType": "Organization",
        "id": ORGANIZATION_ID,
        "active": True,
        "type": [
            {
                "coding": [
                    {"system": ORGANIZATION_TYPE_SYSTEM, "code": "prov"}
                ]
            }
        ],
    }


class FhirTutorialMock(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def send_json(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", FHIR_MEDIA_TYPE)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        target = urlsplit(self.path)
        if target.path == "/healthz" and not target.query:
            self.send_json(200, {"status": "ready"})
            return
        if self.headers.get("Accept") != FHIR_MEDIA_TYPE:
            self.send_json(406, {"resourceType": "OperationOutcome"})
            return

        query = parse_qs(target.query, keep_blank_values=True)
        if target.path == "/Coverage" and query == {
            "status": ["active"],
            "_count": ["100"],
        }:
            self.send_json(
                200,
                {
                    "resourceType": "Bundle",
                    "type": "searchset",
                    "entry": [{"resource": coverage()}],
                },
            )
        elif target.path == f"/Patient/{PATIENT_ID}" and not query:
            self.send_json(200, {"resourceType": "Patient", "id": PATIENT_ID})
        elif target.path == "/Organization" and query == {
            "active": ["true"],
            "type": [f"{ORGANIZATION_TYPE_SYSTEM}|prov"],
            "_count": ["100"],
        }:
            self.send_json(
                200,
                {
                    "resourceType": "Bundle",
                    "type": "searchset",
                    "entry": [{"resource": organization()}],
                },
            )
        elif target.path == f"/Coverage/{COVERAGE_ID}" and not query:
            self.send_json(200, coverage())
        elif target.path == f"/Organization/{ORGANIZATION_ID}" and not query:
            self.send_json(200, organization())
        else:
            self.send_json(404, {"resourceType": "OperationOutcome"})


server = ThreadingHTTPServer(("127.0.0.1", 8003), FhirTutorialMock)
server.daemon_threads = True
server.serve_forever()
