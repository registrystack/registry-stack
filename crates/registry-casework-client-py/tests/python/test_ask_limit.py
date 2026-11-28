"""The request ask limit is a known, non-retryable problem."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()
from registry_casework_client import CaseworkClient, CaseworkClientError  # noqa: E402


class AskLimitTests(unittest.TestCase):
    def test_the_ask_limit_preserves_its_detail_without_retrying(self):
        attempts = []
        detail = "This review request has reached its limit of 50 asks. Continue the review without opening another ask."

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["content-length"]))
                attempts.append(self.path)
                body = json.dumps({
                    "type": "https://id.registrystack.org/problems/registry-casework/review/ask-limit-reached",
                    "title": "Review ask limit reached", "status": 409,
                    "detail": detail, "code": "review.ask-limit-reached",
                    "traceId": "0123456789abcdef0123456789abcdef",
                }).encode()
                self.send_response(409)
                self.send_header("content-type", "application/problem+json")
                self.send_header("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = CaseworkClient(f"http://127.0.0.1:{server.server_port}/")
            with self.assertRaises(CaseworkClientError) as caught:
                client.ask_applicant("synthetic-token", "staff", "00000000-0000-4000-8000-000000000001", 2, "ask-51", {"text": "Why?", "wants": []})
            self.assertEqual(caught.exception.kind, "problem")
            self.assertEqual(caught.exception.code, "review.ask-limit-reached")
            self.assertEqual(caught.exception.detail, detail)
            self.assertEqual(len(attempts), 1)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
