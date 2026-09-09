"""Exercise optional reviewer text through the public Python binding."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient, BaseRegistryClientError  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parents[3] / "registry-breg-client/tests/fixtures/review-reasons.json").read_text())


class ReviewReasonTests(unittest.TestCase):
    def test_reason_validation_and_explicit_wire_retry(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.respond(FIXTURE["metadata"] if self.path.startswith("/v1/registry") else FIXTURE["records"]["reject_request"])

            def do_POST(self):
                body = self.rfile.read(int(self.headers["content-length"]))
                requests.append((body, self.headers["idempotency-key"], self.headers["if-match"]))
                operation = next(name for name, record in FIXTURE["records"].items() if record["data"]["request"]["actions"][0]["href"] == self.path)
                self.respond(FIXTURE["receipts"][operation])

            def respond(self, value):
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("cache-control", "no-store")
                self.send_header("vary", "authorization, accept")
                self.send_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                if "data" in value:
                    self.send_header("link", '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/item>; rel="describedby"')
                    self.send_header("etag", '\"breg-record-000000000008\"')
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f"http://127.0.0.1:{server.server_port}")
            metadata = client.registry_contract("writer")
            authority = metadata.select_lifecycle("item", "writer")
            record = client.get_record("items", FIXTURE["records"]["reject_request"]["data"]["recordIdentifier"], access_profile="writer")
            self.assertEqual(record["value"]["data"]["request"]["decisions"], FIXTURE["records"]["reject_request"]["data"]["request"]["decisions"])
            self.assertEqual(record["value"]["data"]["request"]["history"], FIXTURE["records"]["reject_request"]["data"]["request"]["history"])
            for operation, record in FIXTURE["records"].items():
                action, = client.lifecycle_actions(authority, record)
                before = len(requests)
                if operation in ("approve_request", "apply_request"):
                    with self.assertRaises(BaseRegistryClientError) as error:
                        action.with_reason("not permitted")
                    self.assertEqual(error.exception.kind, "invalid_request")
                    continue
                for invalid in ("📝" * 4097, "\0"):
                    with self.assertRaises(BaseRegistryClientError) as error:
                        action.with_reason(invalid)
                    self.assertEqual(error.exception.kind, "invalid_request")
                for invalid in (None, 1, {}):
                    with self.assertRaises(TypeError):
                        action.with_reason(invalid)
                self.assertEqual(action.with_reason("📝" * 4096).body["reason"], "📝" * 4096)
                self.assertEqual(action.with_reason("").body["reason"], "")
                self.assertNotIn("reason", action.body)
                self.assertEqual(len(requests), before)
                reason = "  Please correct the values.\nเหตุผล 📝  "
                decision = action.with_reason(reason)
                client.execute_lifecycle_action(decision, f"decision-{operation}")
                client.execute_lifecycle_action(decision, f"decision-{operation}")
                self.assertEqual(json.loads(requests[-1][0])["reason"], reason)
                self.assertEqual(requests[-1], requests[-2])
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
