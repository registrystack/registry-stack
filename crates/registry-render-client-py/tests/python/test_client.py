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
