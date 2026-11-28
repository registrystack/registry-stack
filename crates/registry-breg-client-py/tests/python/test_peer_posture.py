"""Exercise posture handling over HTTP through the public Python binding."""
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()
from registry_breg_client import BaseRegistryClient


class DevelopmentPeerTests(unittest.TestCase):
    def test_the_binding_accepts_a_development_peer(self):
        class HealthHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("registry-posture", "development")
                self.send_header(
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                )
                self.end_headers()
                self.wfile.write(b'{"status":"alive"}')

        with HTTPServer(("127.0.0.1", 0), HealthHandler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                client = BaseRegistryClient(f"http://127.0.0.1:{server.server_port}")
                self.assertEqual(client.health()["value"]["status"], "alive")
            finally:
                server.shutdown()
                worker.join()
