#!/usr/bin/env python3
import http.client
import importlib.util
import json
import threading
import unittest
from pathlib import Path


SERVER_PATH = Path(__file__).parents[1] / "qualification_server.py"


def load_server_module():
    spec = importlib.util.spec_from_file_location("qualification_server", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class QualificationServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_server_module()
        cls.server = cls.module.create_server(
            "127.0.0.1",
            0,
            {"keys": [{"kty": "EC", "kid": "issuer-key"}]},
            b"source-token",
        )
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, authorization=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers = {"Authorization": authorization} if authorization else {}
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
        return response.status, body

    def test_jwks_is_public_and_exact(self):
        status, body = self.request("/.well-known/jwks.json")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"keys": [{"kty": "EC", "kid": "issuer-key"}]})

    def test_source_requires_exact_bearer(self):
        status, body = self.request("/people/adult")
        self.assertEqual((status, body), (401, {"error": "source.denied"}))
        status, body = self.request("/people/adult", "Bearer wrong")
        self.assertEqual((status, body), (401, {"error": "source.denied"}))

    def test_source_returns_bounded_fixture_without_loggable_selector(self):
        status, body = self.request("/people/adult", "Bearer source-token")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["record"]["record_id"], "adult")
        self.assertIn("address_canary", body["record"])

    def test_missing_and_ambiguous_remain_distinct(self):
        self.assertEqual(
            self.request("/people/missing", "Bearer source-token"),
            (200, {"total": 0}),
        )
        self.assertEqual(
            self.request("/people/ambiguous", "Bearer source-token"),
            (200, {"total": 2}),
        )

    def test_unrecognized_path_is_not_found(self):
        self.assertEqual(
            self.request("/admin", "Bearer source-token"),
            (404, {"error": "source.not-found"}),
        )


if __name__ == "__main__":
    unittest.main()
