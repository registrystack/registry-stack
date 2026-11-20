import io
import socket
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "intake-status"))
from intake_status import make_server, status_payload


class IntakeStatusTest(unittest.TestCase):
    def test_returns_only_public_status(self):
        self.assertEqual(
            status_payload('{"acceptingApplications":true,"nextReviewWeekday":"Monday"}'),
            b'{"acceptingApplications":true,"nextReviewWeekday":"Monday"}\n',
        )

    def test_rejects_private_or_invalid_config(self):
        for text in (
            '{"acceptingApplications":true,"nextReviewWeekday":"Monday","applicant":"private"}',
            '{"acceptingApplications":"yes","nextReviewWeekday":"Monday"}',
            '{"acceptingApplications":true,"nextReviewWeekday":"Yesterday"}',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                status_payload(text)


class IntakeStatusServerTest(unittest.TestCase):
    def setUp(self):
        self.log = io.StringIO()
        patcher = patch("sys.stderr", self.log)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.server = make_server(("127.0.0.1", 0), "/extensions/intake-status", b'{"a":1}\n')
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def test_serves_the_exact_path_without_naming_the_runtime(self):
        with urllib.request.urlopen(self.url + "/extensions/intake-status", timeout=5) as response:
            self.assertEqual(response.read(), b'{"a":1}\n')
            self.assertEqual(response.headers["Server"], "intake-status")
            self.assertNotIn("Python", str(response.headers))
        with self.assertRaises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(self.url + "/other", timeout=5)
        refused.exception.close()
        self.assertEqual(refused.exception.code, 404)
        self.assertNotIn("Python", str(refused.exception.headers))
        self.assertIn("intake status request returned 404", self.log.getvalue())
        self.assertNotIn("/other", self.log.getvalue())

    def test_a_stalled_client_does_not_block_other_requests(self):
        stalled = socket.create_connection(("127.0.0.1", self.server.server_address[1]))
        self.addCleanup(stalled.close)
        stalled.sendall(b"GET /extensions/intake-status HTTP/1.1\r\nHost: x\r\n")
        with urllib.request.urlopen(self.url + "/extensions/intake-status", timeout=2) as response:
            self.assertEqual(response.status, 200)

    def test_server_is_threaded(self):
        from http.server import ThreadingHTTPServer

        self.assertIsInstance(self.server, ThreadingHTTPServer)
