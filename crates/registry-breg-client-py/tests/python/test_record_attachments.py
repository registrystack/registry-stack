"""Record attachment downloads and revision Proposal links through the Python binding."""

import base64
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import (  # noqa: E402
    BaseRegistryClient,
    BaseRegistryClientError,
)

RECORD_ID = "00000000-0000-4000-8000-000000000001"
SLOT = "evidence"
CONTENT = b"%PDF-1.7 promoted record file"
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
PROFILE_LINK = (
    '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", '
    '</v1/schemas/application>; rel="describedby"'
)
META = {
    "registryIdentifier": "registry",
    "datasetIdentifier": "dataset",
    "recordTypeIdentifier": "application",
}
PROPOSAL = {
    "actionId": "amend",
    "proposalId": "00000000-0000-4000-8000-0000000000aa",
    "submissionVersion": 1,
}
REVISION = {
    "recordIdentifier": RECORD_ID,
    "revisionIdentifier": "2",
    "domainData": {"name": "one"},
    "proposal": PROPOSAL,
}


TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
NOT_FOUND = {
    "type": "https://id.registrystack.org/problems/registry-breg/resource/not_found",
    "title": "Not Found",
    "status": 404,
    "detail": "The requested resource was not found.",
    "code": "resource.not_found",
    "traceId": TRACE_ID,
}


def digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


class RecordAttachmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests = []
        self.digest_header = digest(CONTENT)
        self.concealed = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                owner.requests.append((self.path, self.headers.get("accept")))
                path = self.path.split("?")[0]
                attachment = "/attachments/" in path
                if attachment and owner.concealed:
                    problem = json.dumps(NOT_FOUND).encode()
                    self.send_response(404)
                    self.send_header("traceparent", TRACEPARENT)
                    self.send_header("cache-control", "no-store")
                    self.send_header("content-type", "application/problem+json")
                    self.send_header("content-length", str(len(problem)))
                    self.end_headers()
                    self.wfile.write(problem)
                    return
                if attachment:
                    payload = CONTENT
                elif path.endswith("/revisions"):
                    payload = json.dumps(
                        {"items": [REVISION], "pageInfo": {"hasNextPage": False}}
                    ).encode()
                else:
                    payload = json.dumps({"data": REVISION, "meta": META}).encode()
                self.send_response(200)
                self.send_header("traceparent", TRACEPARENT)
                self.send_header("cache-control", "no-store")
                self.send_header("content-length", str(len(payload)))
                if attachment:
                    self.send_header("content-type", "application/pdf")
                    self.send_header("content-disposition", "attachment")
                    self.send_header("x-content-type-options", "nosniff")
                    self.send_header("vary", "authorization")
                    if owner.digest_header is not None:
                        self.send_header("repr-digest", owner.digest_header)
                else:
                    self.send_header("content-type", "application/json")
                    self.send_header("link", PROFILE_LINK)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(f"http://127.0.0.1:{self.server.server_port}")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_download_uses_the_slot_route_and_returns_the_verified_digest(self) -> None:
        downloaded = self.client.download_record_attachment(
            "applications", RECORD_ID, SLOT, access_profile="auditor"
        )
        self.assertEqual(downloaded["body"], CONTENT)
        self.assertEqual(downloaded["media_type"], "application/pdf")
        self.assertEqual(downloaded["repr_digest"], digest(CONTENT))
        self.assertEqual(
            self.requests[0],
            (
                f"/v1/records/applications/{RECORD_ID}/attachments/{SLOT}?accessProfile=auditor",
                "*/*",
            ),
        )

    def test_bytes_that_miss_the_stated_digest_are_a_protocol_refusal(self) -> None:
        for header in (digest(b"other bytes"), None):
            self.digest_header = header
            with self.subTest(header=header):
                with self.assertRaises(BaseRegistryClientError) as refused:
                    self.client.download_record_attachment(
                        "applications", RECORD_ID, SLOT
                    )
                self.assertEqual(refused.exception.kind, "protocol")

    def test_a_concealed_file_surfaces_the_service_problem(self) -> None:
        self.concealed = True
        with self.assertRaises(BaseRegistryClientError) as refused:
            self.client.download_record_attachment("applications", RECORD_ID, SLOT)
        self.assertEqual(refused.exception.kind, "not-found")
        self.assertEqual(refused.exception.status, 404)
        self.assertEqual(refused.exception.code, "resource.not_found")
        self.assertEqual(refused.exception.trace_id, TRACE_ID)

    def test_a_file_larger_than_the_response_bound_is_refused_unread(self) -> None:
        client = BaseRegistryClient(
            f"http://127.0.0.1:{self.server.server_port}",
            maximum_response_bytes=len(CONTENT) - 1,
        )
        with self.assertRaises(BaseRegistryClientError) as refused:
            client.download_record_attachment("applications", RECORD_ID, SLOT)
        self.assertEqual(refused.exception.kind, "transport")
        self.assertEqual(refused.exception.transport_kind, "response-too-large")

    def test_invalid_selectors_never_reach_http(self) -> None:
        for route, record, slot in (
            ("applications", "not-a-record", SLOT),
            ("applications", RECORD_ID, "../evidence"),
            ("applications", RECORD_ID, "Evidence"),
            ("applications/other", RECORD_ID, SLOT),
        ):
            with self.subTest(route=route, record=record, slot=slot):
                with self.assertRaises(BaseRegistryClientError) as refused:
                    self.client.download_record_attachment(route, record, slot)
                self.assertEqual(refused.exception.kind, "invalid-request")
        self.assertEqual(self.requests, [])

    def test_revision_reads_keep_the_proposal_link_the_server_sent(self) -> None:
        history = json.loads(
            self.client.record_revisions("applications", RECORD_ID, "auditor")["body"]
        )
        self.assertEqual(history["items"][0]["proposal"], PROPOSAL)
        single = json.loads(
            self.client.get_record_revision(
                "applications", RECORD_ID, 2, access_profile="auditor"
            )["body"]
        )
        self.assertEqual(single["data"]["proposal"], PROPOSAL)


if __name__ == "__main__":
    unittest.main()
