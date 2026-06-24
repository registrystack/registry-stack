#!/usr/bin/env python3
"""Focused tests for the static metadata server's security headers."""

from __future__ import annotations

import importlib.util
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent / "static-metadata-server.py"
_spec = importlib.util.spec_from_file_location("static_metadata_server", MODULE_PATH)
assert _spec and _spec.loader
server = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(server)


class SecurityHeadersTest(unittest.TestCase):
    """Every static metadata response carries the browser-hardening headers (relay#88)."""

    EXPECTED_HEADERS = {
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmpdir = tempfile.TemporaryDirectory()
        root = Path(cls.tmpdir.name)
        well_known = root / ".well-known"
        well_known.mkdir()
        (well_known / "api-catalog").write_text('{"linkset": []}', encoding="utf-8")
        (root / "index.json").write_text('{"ok": true}', encoding="utf-8")

        directory = root.resolve()

        class Handler(server.StaticMetadataHandler):
            def __init__(self, *handler_args, **handler_kwargs):
                super().__init__(*handler_args, directory=str(directory), **handler_kwargs)

        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmpdir.cleanup()

    def _get(self, path: str):
        return urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5)

    def _assert_security_headers(self, response) -> None:
        for name, value in self.EXPECTED_HEADERS.items():
            self.assertEqual(response.headers.get(name), value, name)

    def test_json_file_carries_security_headers(self) -> None:
        with self._get("/index.json") as response:
            self._assert_security_headers(response)

    def test_api_catalog_keeps_linkset_type_and_gains_security_headers(self) -> None:
        with self._get("/.well-known/api-catalog") as response:
            self._assert_security_headers(response)
            self.assertIn("application/linkset+json", response.headers.get("Content-Type", ""))
            self.assertIn("api-catalog", response.headers.get("Link", ""))

    def test_server_banner_does_not_advertise_python(self) -> None:
        with self._get("/index.json") as response:
            banner = response.headers.get("Server", "")
        self.assertNotIn("Python", banner)
        self.assertNotIn("SimpleHTTP", banner)


if __name__ == "__main__":
    unittest.main()
