"""Occurrence projection through the native Python boundary."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import (  # noqa: E402
    BaseRegistryClient,
    BaseRegistryClientError,
    occurrence_view,
)

FIXTURES = (
    Path(__file__).resolve().parents[3]
    / "registry-breg-client/tests/fixtures/occurrence-view"
)
REVISION = "sha256:" + "a" * 64
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
RECORD_ID = "6f1e0c62-0000-4000-8000-000000000001"
HIDDEN_ID = "6f1e0c62-0000-4000-8000-000000000404"
LINK = (
    '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", '
    '</v1/schemas/incorporation>; rel="describedby"'
)
CREATED_AT = "2026-10-26T08:15:30.123456Z"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class OccurrenceViewTests(unittest.TestCase):
    def test_every_generated_fixture_projects_to_its_recorded_view(self) -> None:
        for name in (
            "incorporation",
            "suspension-decision",
            "suspension-correction",
            "ownership-transfer",
        ):
            with self.subTest(name):
                self.assertEqual(
                    occurrence_view(fixture(f"{name}.input.json")),
                    fixture(f"{name}.json"),
                )

    def test_refusals_are_described_occurrence_failures(self) -> None:
        arguments = fixture("incorporation.input.json")
        arguments["descriptor"]["descriptorVersion"] = 2
        with self.assertRaises(BaseRegistryClientError) as caught:
            occurrence_view(arguments)
        self.assertEqual(caught.exception.kind, "occurrence")
        self.assertEqual(caught.exception.code, "unsupported-version")
        self.assertFalse(caught.exception.outcome_unknown)
        with self.assertRaises(BaseRegistryClientError) as caught:
            occurrence_view({"unknown": True})
        self.assertEqual(caught.exception.code, "invalid-input")
        with self.assertRaises(BaseRegistryClientError) as caught:
            occurrence_view(object())
        self.assertEqual(caught.exception.kind, "invalid-request")

    def test_metadata_accessor_and_creation_revision_read(self) -> None:
        descriptor = fixture("incorporation.input.json")["descriptor"]
        metadata = {
            "id": "fixture-registry", "version": "1", "revision": REVISION,
            "metadataVersion": "2",
            "recordTypes": [
                {
                    "id": "incorporation", "datasetIdentifier": "register",
                    "route": "incorporations", "operations": [], "readableFields": [],
                    "schema": "/v1/schemas/incorporation", "occurrence": descriptor,
                },
                {
                    "id": "note", "datasetIdentifier": "register", "route": "notes",
                    "operations": [], "readableFields": [],
                    "schema": "/v1/schemas/note",
                },
            ],
            "operations": [],
        }
        created = {
            "data": {
                "recordIdentifier": RECORD_ID, "revisionIdentifier": "1",
                "domainData": {}, "predecessorRevision": None, "lifecycle": "active",
                "packageRevision": REVISION,
                "operationIdentifier": "records.incorporation.create",
                "mutationKind": "create", "createdAt": CREATED_AT,
                "actorReference": "actor-ref-1", "requestReference": "request-ref-1",
            },
            "meta": {
                "registryIdentifier": "registry", "datasetIdentifier": "dataset",
                "entityTypeIdentifier": "incorporation",
            },
        }
        hidden = {
            "type": "https://id.registrystack.org/problems/registry-breg/resource/not_found",
            "title": "Not Found", "status": 404,
            "detail": "The requested resource was not found.",
            "code": "resource.not_found", "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                status, headers, document = 200, {}, created
                if self.path.startswith("/v1/registry"):
                    headers = {"cache-control": "no-store", "vary": "authorization, accept"}
                    document = metadata
                elif HIDDEN_ID in self.path:
                    status, document = 404, hidden
                    headers = {"cache-control": "no-store"}
                else:
                    headers = {"link": LINK}
                media = "application/problem+json" if status == 404 else "application/json"
                body = json.dumps(document).encode()
                self.send_response(status)
                self.send_header("content-type", media)
                self.send_header("traceparent", TRACEPARENT)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f"http://127.0.0.1:{server.server_port}")
            contract = client.registry_contract()
            self.assertEqual(
                contract.occurrence_descriptor("incorporation")["label"], "Incorporation"
            )
            for absent in ("note", "unknown-type"):
                with self.assertRaises(BaseRegistryClientError) as caught:
                    contract.occurrence_descriptor(absent)
                self.assertEqual(caught.exception.kind, "occurrence")
                self.assertEqual(caught.exception.code, "not-an-occurrence")

            revision = client.occurrence_creation_revision("incorporations", RECORD_ID)
            self.assertEqual(
                revision,
                {"recordId": RECORD_ID, "revision": "1", "createdAt": CREATED_AT},
            )
            self.assertIsNone(
                client.occurrence_creation_revision("incorporations", HIDDEN_ID)
            )
            arguments = fixture("incorporation.input.json")
            arguments["creationRevision"] = revision
            self.assertEqual(
                occurrence_view(arguments)["recordedAt"],
                {"status": "available", "type": "instant", "value": CREATED_AT},
            )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
