"""Exercise governed request attachments through the public Python binding."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient, BaseRegistryClientError  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parents[3] / "registry-breg-client/tests/fixtures/attachments.json").read_text())
RECORD_ID = FIXTURE["record"]["data"]["recordIdentifier"]
SLOT_PATH = f"/v1/records/companies/{RECORD_ID}/attachments/supporting-file"
ETAG = '"breg-record-000000000001"'
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
CONTENT = FIXTURE["content"].encode()
PROFILE_LINK = '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/company>; rel="describedby"'


def emptied():
    value = json.loads(json.dumps(FIXTURE["record"]))
    value["data"]["domainData"]["supporting-file"] = None
    return value


class AttachmentTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.capture(b"")
                if self.path.startswith("/v1/registry"):
                    return self.respond_json(FIXTURE["metadata"], record=False)
                self.send_response(200)
                self.send_header("content-type", "application/pdf")
                self.send_header("content-disposition", "attachment")
                self.send_header("x-content-type-options", "nosniff")
                self.send_header("cache-control", "no-store")
                self.send_header("vary", "authorization")
                self.send_header("traceparent", TRACEPARENT)
                self.send_header("content-length", str(len(CONTENT)))
                self.end_headers()
                self.wfile.write(CONTENT)

            def do_PATCH(self):
                self.capture(self.rfile.read(int(self.headers["content-length"])))
                self.respond_json(FIXTURE["record"], record=True)

            def do_DELETE(self):
                self.capture(b"")
                self.respond_json(emptied(), record=True)

            def capture(self, body):
                requests.append((self.command, self.path, dict(self.headers), body))

            def respond_json(self, value, record):
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("cache-control", "no-store")
                self.send_header("vary", "authorization, accept")
                self.send_header("traceparent", TRACEPARENT)
                if record:
                    self.send_header("etag", ETAG)
                    self.send_header("link", PROFILE_LINK)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(f"http://127.0.0.1:{self.server.server_port}")
        self.metadata = self.client.registry_contract("company-writer")
        self.slot, = self.metadata.select_attachments("company", "company-writer")

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_slot_exposes_the_served_policy_and_the_record_projection(self):
        self.assertEqual(self.slot.slot_identifier, "supporting-file")
        self.assertEqual(self.slot.entity_identifier, "company")
        self.assertEqual(self.slot.access_profile, "company-writer")
        self.assertTrue(self.slot.required_for_submit)
        self.assertEqual(self.slot.maximum_bytes, 1024)
        self.assertEqual(self.slot.content_types, ["application/pdf"])
        self.assertTrue(self.slot.accepts_content_type("application/pdf"))
        self.assertFalse(self.slot.accepts_content_type("image/png"))
        self.assertEqual((self.slot.can_download, self.slot.can_upload, self.slot.can_remove), (True, True, True))
        self.assertEqual(self.slot.value_in(FIXTURE["record"]), {
            "kind": "filled",
            "value": {
                "slot_identifier": "supporting-file",
                "proposal_version": 2,
                "erased": False,
                "byte_size": len(CONTENT),
                "sha256": FIXTURE["record"]["data"]["domainData"]["supporting-file"]["sha256"],
                "content_type": "application/pdf",
                "uploaded_at": "2026-01-02T03:04:05.000000Z",
                "uploaded_by": "urn:registry:actor:filer",
                "verification_status": "approved",
            },
        })
        self.assertEqual(self.slot.value_in(emptied()), {"kind": "empty", "value": None})
        unselected = emptied()
        del unselected["data"]["domainData"]["supporting-file"]
        self.assertEqual(self.slot.value_in(unselected), {"kind": "not_selected", "value": None})
        self.assertEqual(len(self.requests), 1)

    def test_an_upload_the_slot_cannot_accept_never_reaches_the_engine(self):
        for content_type, body in (
            ("application/pdf", b""),
            ("application/pdf", b"A" * 1025),
            ("image/png", CONTENT),
            ("Application/PDF", CONTENT),
            ("application/pdf; charset=utf-8", CONTENT),
            ("*/*", CONTENT),
        ):
            with self.assertRaises(BaseRegistryClientError) as error:
                self.slot.prepare_upload(content_type, body)
            self.assertEqual(error.exception.kind, "invalid_request")
        self.assertEqual(len(self.requests), 1)

    def test_the_three_exchanges_use_the_engine_routes_and_governed_headers(self):
        upload = self.slot.prepare_upload("application/pdf", CONTENT)
        self.assertEqual(upload.content_type, "application/pdf")
        self.assertEqual(upload.byte_size, len(CONTENT))

        uploaded = self.client.upload_attachment(self.slot, RECORD_ID, ETAG, upload, "upload-1")
        self.assertEqual(uploaded["value"]["data"]["recordIdentifier"], RECORD_ID)
        self.assertEqual(uploaded["etag"], ETAG)
        method, path, headers, body = self.requests[-1]
        self.assertEqual((method, path), ("PATCH", f"{SLOT_PATH}?accessProfile=company-writer"))
        self.assertEqual(headers["content-type"], "application/pdf")
        self.assertEqual(headers["if-match"], ETAG)
        self.assertEqual(headers["idempotency-key"], "upload-1")
        self.assertEqual(body, CONTENT)

        stored = self.client.download_attachment(self.slot, RECORD_ID, 2)
        self.assertEqual(stored["media_type"], "application/pdf")
        self.assertEqual(stored["body"], CONTENT)
        method, path, _, _ = self.requests[-1]
        self.assertEqual((method, path), ("GET", f"{SLOT_PATH}?proposalVersion=2&accessProfile=company-writer"))

        removed = self.client.delete_attachment(self.slot, RECORD_ID, ETAG, "remove-1")
        self.assertIsNone(removed["value"]["data"]["domainData"]["supporting-file"])
        method, path, headers, body = self.requests[-1]
        self.assertEqual((method, path), ("DELETE", f"{SLOT_PATH}?accessProfile=company-writer"))
        self.assertEqual(headers["if-match"], ETAG)
        self.assertEqual(headers["idempotency-key"], "remove-1")
        self.assertEqual(body, b"")

    def test_slot_authority_stays_bound_to_its_source_and_served_routes(self):
        other = BaseRegistryClient("https://other.invalid/")
        before = len(self.requests)
        with self.assertRaises(BaseRegistryClientError) as error:
            other.download_attachment(self.slot, RECORD_ID, 1)
        self.assertEqual(error.exception.kind, "invalid_request")
        with self.assertRaises(BaseRegistryClientError) as error:
            self.client.download_attachment(self.slot, RECORD_ID, 0)
        self.assertEqual(error.exception.kind, "invalid_request")
        for entity, profile, code in (
            ("missing-entity", "company-writer", "not_found"),
            ("company", "auditor", "profile_mismatch"),
        ):
            with self.assertRaises(BaseRegistryClientError) as error:
                self.metadata.select_attachments(entity, profile)
            self.assertEqual(error.exception.kind, "metadata_selection")
            self.assertEqual(error.exception.code, code)
        self.assertEqual(len(self.requests), before)


if __name__ == "__main__":
    unittest.main()
