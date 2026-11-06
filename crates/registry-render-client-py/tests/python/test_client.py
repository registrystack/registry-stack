import base64
import hashlib
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from bootstrap import ensure_built

ensure_built()
import registry_render_client as client


class RenderJourney(unittest.TestCase):
    def test_one_document_uses_provider_and_invalid_input_precedes_it(self):
        requests = []
        malformed_pdf = [False]

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                requests.append(self.headers.get("Authorization"))
                self.rfile.read(int(self.headers["Content-Length"]))
                pdf = b"%PDF-python-client"
                body = json.dumps(
                    {
                        "pdfBase64": base64.b64encode(pdf).decode(),
                        "pdfSha256": "0" * 64
                        if malformed_pdf[0]
                        else hashlib.sha256(pdf).hexdigest(),
                        "dataSha256": "0" * 64,
                        "documentVersion": "receipt v1",
                        "warnings": [],
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header(
                    "traceparent",
                    "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
                )
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            caller = client.RenderClient(
                {"baseUrl": f"http://127.0.0.1:{server.server_port}"}
            )
            tokens = []

            def provider():
                tokens.append(True)
                return "canary-render-token"

            request = {"issuedAt": "2026-10-23T00:00:00Z", "data": {}}
            with self.assertRaises(client.RenderClientError):
                caller.render(provider, "../receipt", request)
            self.assertEqual(tokens, [])
            for invalid in [
                {"issuedAt": "not-a-date", "data": {}},
                {**request, "assets": {"../private": "AAAA"}},
                {**request, "assets": {"photo": "aGVsbG8="}},
            ]:
                with self.assertRaises(client.RenderClientError):
                    caller.render(provider, "receipt", invalid)
                self.assertEqual(tokens, [])
                self.assertEqual(requests, [])
            self.assertEqual(
                caller.render(provider, "receipt", request)["documentVersion"],
                "receipt v1",
            )
            self.assertEqual(requests, ["Bearer canary-render-token"])
            self.assertEqual(len(tokens), 1)
            original = RuntimeError("value-free provider refusal")

            def unavailable():
                raise original

            with self.assertRaises(RuntimeError) as captured:
                caller.render(unavailable, "receipt", request)
            self.assertIs(captured.exception, original)
            self.assertEqual(len(requests), 1)
            malformed_pdf[0] = True
            with self.assertRaises(client.RenderClientError) as captured:
                caller.render("canary-render-token", "receipt", request)
            self.assertEqual(captured.exception.kind, "protocol")
            self.assertTrue(captured.exception.outcome_unknown)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


FIRST_REVISION = b"%PDF-1.7\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
SIGNED_FILE = FIRST_REVISION + b"2 0 obj<</Type/Sig>>endobj\ntrailer<<>>\n%%EOF\n"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class SealJourney(unittest.TestCase):
    def test_seal_returns_the_checked_document_and_sends_the_correlation_key(self):
        seen = []
        tampered = [False]

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                key = self.headers.get("Idempotency-Key")
                seen.append((self.path, self.headers.get("Authorization"), key))
                self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/v1/render/receipt":
                    payload = {
                        "pdfBase64": base64.b64encode(FIRST_REVISION).decode(),
                        "pdfSha256": _sha(FIRST_REVISION),
                        "dataSha256": "0" * 64,
                        "documentVersion": "receipt v1",
                        "warnings": [],
                    }
                else:
                    payload = {
                        "pdfBase64": base64.b64encode(SIGNED_FILE).decode(),
                        "documentSha256": _sha(FIRST_REVISION),
                        "signedFileSha256": "0" * 64
                        if tampered[0]
                        else _sha(SIGNED_FILE),
                        "dataSha256": "0" * 64,
                        "documentVersion": "receipt v1",
                        "bundleHash": "b" * 64,
                        "warnings": [],
                        "seal": {
                            "id": "agency",
                            "level": "B-B",
                            "certificateSha256": "c" * 64,
                        },
                    }
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header(
                    "traceparent",
                    "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01",
                )
                if key is not None:
                    self.send_header("Idempotency-Key", key)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            caller = client.RenderClient(
                {"baseUrl": f"http://127.0.0.1:{server.server_port}"}
            )
            tokens = []

            def provider():
                tokens.append(True)
                return "canary-render-token"

            request = {"issuedAt": "2026-10-23T00:00:00Z", "data": {}}
            for key in ["", "has space", "k" * 129, 5]:
                for method in (caller.seal, caller.render):
                    with self.assertRaises(client.RenderClientError) as captured:
                        method(provider, "receipt", request, correlation_key=key)
                    self.assertEqual(captured.exception.kind, "invalid-request")
            with self.assertRaises(client.RenderClientError):
                caller.seal(provider, "../receipt", request)
            self.assertEqual(tokens, [])
            self.assertEqual(seen, [])
            sealed = caller.seal(provider, "receipt", request, correlation_key="py-key-1")
            self.assertEqual(
                sealed,
                {
                    "pdfBase64": base64.b64encode(SIGNED_FILE).decode(),
                    "documentSha256": _sha(FIRST_REVISION),
                    "signedFileSha256": _sha(SIGNED_FILE),
                    "dataSha256": "0" * 64,
                    "documentVersion": "receipt v1",
                    "bundleHash": "b" * 64,
                    "warnings": [],
                    "seal": {
                        "id": "agency",
                        "level": "B-B",
                        "certificateSha256": "c" * 64,
                    },
                },
            )
            caller.seal(provider, "receipt", request)
            caller.render(provider, "receipt", request, correlation_key="py-key-2")
            self.assertEqual(
                seen,
                [
                    ("/v1/seal/receipt", "Bearer canary-render-token", "py-key-1"),
                    ("/v1/seal/receipt", "Bearer canary-render-token", None),
                    ("/v1/render/receipt", "Bearer canary-render-token", "py-key-2"),
                ],
            )
            tampered[0] = True
            with self.assertRaises(client.RenderClientError) as captured:
                caller.seal("canary-render-token", "receipt", request)
            self.assertEqual(captured.exception.kind, "protocol")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
