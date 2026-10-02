"""Exercise every statistics operation through the native Python binding."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient, BaseRegistryClientError  # noqa: E402

TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


class StatisticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def exchange(self) -> None:
                size = int(self.headers.get("content-length", "0"))
                requests.append(
                    (
                        self.command,
                        self.path,
                        self.headers.get("accept"),
                        self.headers.get("idempotency-key"),
                        self.rfile.read(size),
                    )
                )
                publish = self.command == "POST" and self.path.endswith(
                    "/versions?accessProfile=publisher"
                )
                body = (
                    b"period,periodStart,periodEnd,value,status\r\n"
                    if self.headers.get("accept") == "text/csv"
                    else b'{"ok":true}'
                )
                self.send_response(201 if publish else 200)
                self.send_header("content-type", self.headers["accept"])
                self.send_header("traceparent", TRACEPARENT)
                if self.command == "POST":
                    self.send_header("cache-control", "no-store")
                    self.send_header("vary", "authorization, accept")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = exchange  # noqa: N815
            do_POST = exchange  # noqa: N815

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(f"http://127.0.0.1:{self.server.server_port}")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_all_statistics_methods(self) -> None:
        live = self.client.statistics_live(
            "enrolments", from_period="2025-01", to_period="2025-02",
            access_profile="analyst", format="csv"
        )
        self.assertEqual(live["media_type"], "text/csv")
        self.client.statistics_releases("enrolments", top=10, skip_token="cursor", access_profile="reader")
        self.client.statistics_latest_release("enrolments", "2025-01", "final", access_profile="reader")
        self.client.statistics_release_version("enrolments", "2025-01", 7, access_profile="reader", format="csv")
        self.client.statistics_release_series("enrolments", "2025-01", "2025-02", "any", access_profile="reader")
        self.client.statistics_publish("enrolments", "2025-01", "final", "publisher", "caller-owned-key")
        self.client.statistics_withdraw("enrolments", "2025-01", 7, "disclosure-risk", "publisher", "caller-owned-key")
        self.assertEqual(self.requests[0][1], "/v1/statistics/enrolments:live?from=2025-01&to=2025-02&accessProfile=analyst")
        self.assertEqual(json.loads(self.requests[5][4]), {"status": "final"})
        self.assertEqual(self.requests[5][3], "caller-owned-key")
        self.assertEqual(json.loads(self.requests[6][4]), {"reason": "disclosure-risk"})
        count = len(self.requests)
        with self.assertRaises(BaseRegistryClientError):
            self.client.statistics_release_version("enrolments", "2025-01", 0)
        self.assertEqual(len(self.requests), count)


if __name__ == "__main__":
    unittest.main()
