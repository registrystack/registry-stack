# SPDX-License-Identifier: Apache-2.0
"""Event fixture transport regressions against owned synthetic loopback servers."""
import contextlib
import http.client
import http.server
import importlib.util
from pathlib import Path
import sys
import threading
import unittest

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("coordinator_event_transport", SCRIPTS / "test-breg-events.py")
events = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(SCRIPTS))
try:
    spec.loader.exec_module(events)
finally:
    sys.path.pop(0)

PATHS = ("/v1/events/event-follow-up/created", "/v1/events/event-follow-up/patched")


@contextlib.contextmanager
def local_server(handler):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def post(url, target, body, headers):
    origin = events.urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(origin.hostname, origin.port, timeout=5)
    try:
        connection.request("POST", target, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


class EventTransportTests(unittest.TestCase):
    def test_exact_event_paths_forward_wire_bytes_and_retry_the_lost_acknowledgment(self):
        received = []

        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, body, dict(self.headers.items())))
                self.send_response(204)
                self.send_header("x-coordinator-run-id", "synthetic-run")
                self.end_headers()

        body = b'{ "data": {"recordId": "synthetic-record"} }\n'
        headers = {"Content-Type": "application/json", "ce-type": "application-created-v1",
                   "x-registry-signature": "v1=synthetic-signature", "Idempotency-Key": "synthetic-key"}
        with local_server(Upstream) as upstream:
            proxy = events.DeliveryProxy({path: upstream + path for path in PATHS})
            try:
                statuses = [post(proxy.url, path, body, headers) for path in (PATHS[0], PATHS[0], PATHS[1])]
                self.assertEqual(statuses, [503, 204, 204])
                self.assertEqual([item["run"] for item in proxy.deliveries], ["synthetic-run"] * 3)
                self.assertEqual([item["status"] for item in proxy.deliveries], [204] * 3)
            finally:
                proxy.close()
        self.assertEqual([item[:2] for item in received], [(PATHS[0], body), (PATHS[0], body), (PATHS[1], body)])
        for _, _, forwarded in received:
            actual = {name.lower(): value for name, value in forwarded.items()}
            for name, value in headers.items():
                self.assertEqual(actual[name.lower()], value)
            self.assertEqual(actual["content-length"], str(len(body)))

    def test_invalid_absolute_scheme_relative_and_unlisted_targets_never_forward(self):
        received = []

        class Upstream(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                received.append(self.path)
                self.send_response(204)
                self.end_headers()

        with local_server(Upstream) as upstream:
            proxy = events.DeliveryProxy({path: upstream + path for path in PATHS})
            try:
                for target in [
                    "/v1/runs", PATHS[0] + "?extra=true", PATHS[0] + "#fragment",
                    PATHS[0] + "/extra", PATHS[0].replace("/created", "/%63reated"),
                    upstream + PATHS[0], "https://example.invalid" + PATHS[0],
                    "/" + PATHS[0], "//example.invalid" + PATHS[0], "@example.invalid",
                ]:
                    with self.subTest(target=target):
                        self.assertEqual(post(proxy.url, target, b"{}", {}), 404)
                self.assertEqual(proxy.deliveries, [])
            finally:
                proxy.close()
        self.assertEqual(received, [])

    def test_request_does_not_follow_redirect_or_forward_authorization_to_destination(self):
        received = []

        class Destination(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                received.append(("destination", self.headers.get("Authorization")))
                self.send_response(204)
                self.end_headers()

        with local_server(Destination) as destination:
            class Upstream(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_POST(self):
                    self.rfile.read(int(self.headers["Content-Length"]))
                    received.append((self.path, self.headers.get("Authorization")))
                    self.send_response(302)
                    self.send_header("Location", destination + "/unexpected")
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            with local_server(Upstream) as upstream:
                status, _, body = events.request("POST", upstream + PATHS[0], body=b"{}",
                                                 token="synthetic-token", expected=(302,))
        self.assertEqual((status, body), (302, None))
        self.assertEqual(received, [(PATHS[0], "Bearer synthetic-token")])


if __name__ == "__main__":
    unittest.main()
