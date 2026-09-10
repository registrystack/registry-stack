"""Exercise process-safe mutation recovery through the public Python binding."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import (  # noqa: E402
    BRegPreparedCreate,
    BaseRegistryClient,
    BaseRegistryClientError,
)

RECORD_ID = "00000000-0000-4000-8000-000000000001"
REVISION = "sha256:" + "a" * 64
ETAG = '"breg-record-000000000001"'
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
PROFILE_LINK = (
    '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", '
    '</v1/schemas/company>; rel="describedby"'
)


def metadata() -> dict:
    field = {
        "id": "legal-name",
        "apiName": "legalName",
        "label": "Legal name",
        "schema": {"type": "string"},
        "required": True,
        "nullable": False,
        "readOnly": False,
        "removable": False,
    }
    sequence_field = {
        "id": "sequence",
        "apiName": "sequence",
        "label": "Sequence",
        "schema": {"type": "integer"},
        "required": False,
        "nullable": False,
        "readOnly": False,
        "removable": False,
    }
    operation = {
        "id": "records.company.create",
        "method": "POST",
        "path": "/v1/records/companies",
        "operation": "create",
        "sourceEntity": "company",
        "responseEntity": "company",
        "accessProfile": "company-writer",
        "requiredCapabilities": [],
        "entityLabel": "Companies",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["legal-name"],
        "fields": [field, sequence_field],
        "readableFields": ["legal-name", "sequence"],
        "createWritableFields": ["legal-name", "sequence"],
        "patchWritableFields": [],
        "selectors": [],
        "query": None,
        "request": {
            "fieldNames": "api",
            "queryParameters": [],
            "body": "data_envelope",
            "contentType": "application/json",
            "idempotencyKeyRequired": True,
            "mutationSemantics": "direct",
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["data"],
                "properties": {"data": {"type": "object"}},
            },
        },
    }
    return {
        "id": "business-registry",
        "version": "1.2.3",
        "revision": REVISION,
        "metadataVersion": "1",
        "entities": [
            {
                "id": "company",
                "datasetIdentifier": "legal-entities",
                "route": "companies",
                "operations": [
                    {"operation": "create", "accessProfile": "company-writer"}
                ],
                "readableFields": ["legal-name", "sequence"],
                "schema": "/v1/schemas/company",
            }
        ],
        "operations": [operation],
    }


def record() -> dict:
    return {
        "data": {
            "recordIdentifier": RECORD_ID,
            "revisionIdentifier": "1",
            "domainData": {"legalName": "Created Ltd"},
            "snapshot": f"breg1_{RECORD_ID}",
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company",
        },
    }


class RecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                requests.append((self.command, self.path, dict(self.headers), b""))
                self.respond(metadata(), 200, False)

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers["content-length"]))
                requests.append((self.command, self.path, dict(self.headers), body))
                self.respond(record(), 201, True)

            def respond(self, value: dict, status: int, is_record: bool) -> None:
                body = json.dumps(value, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("traceparent", TRACEPARENT)
                if is_record:
                    self.send_header("etag", ETAG)
                    self.send_header("link", PROFILE_LINK)
                    self.send_header("cache-control", "no-store")
                    self.send_header("vary", "authorization, accept")
                    self.send_header("location", f"/v1/records/companies/{RECORD_ID}")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(
            f"http://127.0.0.1:{self.server.server_port}"
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_create_recovery_is_pure_until_explicit_execution(self) -> None:
        original = self.client.registry_contract("company-writer").select_create(
            "records.company.create", "company-writer"
        )
        prepared = self.client.prepare_create(
            original,
            {"legalName": "Created Ltd", "sequence": 2**63},
            "persisted-create-1",
        )
        evidence = prepared.to_bytes()
        self.assertIsInstance(evidence, bytes)
        self.assertNotIn("Created Ltd", repr(prepared))
        self.assertNotIn("persisted-create-1", repr(prepared))

        fresh = self.client.registry_contract("company-writer").select_create(
            "records.company.create", "company-writer"
        )
        restored = BRegPreparedCreate.from_bytes(evidence)
        before = len(self.requests)
        recovered = self.client.recover_create(fresh, restored)
        self.assertEqual(len(self.requests), before)
        self.assertNotIn("Created Ltd", repr(recovered))
        self.assertNotIn("persisted-create-1", repr(recovered))

        result = self.client.execute_recovered_create(fresh, recovered)
        self.assertEqual(result["value"]["data"]["recordIdentifier"], RECORD_ID)
        method, path, headers, body = self.requests[-1]
        self.assertEqual((method, path), ("POST", "/v1/records/companies?accessProfile=company-writer"))
        self.assertEqual(headers["idempotency-key"], "persisted-create-1")
        self.assertEqual(
            json.loads(body),
            {"data": {"legalName": "Created Ltd", "sequence": 2**63}},
        )

    def test_invalid_or_wrong_source_evidence_is_refused_without_io(self) -> None:
        binding = self.client.registry_contract("company-writer").select_create(
            "records.company.create", "company-writer"
        )
        prepared = self.client.prepare_create(binding, {"legalName": "A"}, "create-2")
        before = len(self.requests)
        with self.assertRaises(BaseRegistryClientError) as invalid:
            BRegPreparedCreate.from_bytes(b"!" + prepared.to_bytes()[1:])
        self.assertEqual(invalid.exception.kind, "invalid_request")
        other = BaseRegistryClient("https://other.example.invalid")
        with self.assertRaises(BaseRegistryClientError) as mismatch:
            other.recover_create(binding, prepared)
        self.assertEqual(mismatch.exception.kind, "invalid_request")
        self.assertEqual(len(self.requests), before)


if __name__ == "__main__":
    unittest.main()
