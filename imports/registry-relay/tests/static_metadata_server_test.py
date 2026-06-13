# SPDX-License-Identifier: Apache-2.0
"""Tests for demo/decentralized/scripts/static_metadata_server.py.

Verifies that the static metadata HTTP server adds the required
browser-hardening security headers to every response (issue #88 / LAB-008).
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import socket
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "demo" / "decentralized" / "scripts" / "static_metadata_server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("static_metadata_server", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load server module from {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    """Find an OS-assigned free TCP port."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class StaticMetadataServerSecurityHeadersTest(unittest.TestCase):
    """Integration tests: spin up the server against a temp directory and probe it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_server_module()
        cls.tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmpdir.name)

        # Minimal static file tree that mirrors the real static-metadata layout.
        well_known = tmp / ".well-known"
        well_known.mkdir()
        (well_known / "api-catalog").write_text(
            '{"linkset": []}', encoding="utf-8"
        )
        metadata = tmp / "metadata"
        metadata.mkdir()
        (metadata / "index.json").write_text(
            '{"schema_version": "registry-metadata-index/v1"}', encoding="utf-8"
        )

        cls.port = _free_port()

        handler = cls.module.SecureStaticHandler

        cls.server = cls.module.SecureThreadingHTTPServer(
            ("127.0.0.1", cls.port), handler
        )
        # Change into tmpdir so SimpleHTTPRequestHandler resolves paths correctly.
        import os

        os.chdir(cls.tmpdir.name)

        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        # Brief pause so the server is ready before the first request.
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.thread.join(timeout=2)
        cls.tmpdir.cleanup()

    def _get_headers(self, path: str) -> dict[str, str]:
        url = f"http://127.0.0.1:{self.port}{path}"
        with urllib.request.urlopen(url) as resp:  # noqa: S310
            return {k.lower(): v for k, v in resp.headers.items()}

    def test_api_catalog_response_includes_content_security_policy(self) -> None:
        headers = self._get_headers("/.well-known/api-catalog")
        self.assertIn(
            "content-security-policy",
            headers,
            "/.well-known/api-catalog must carry Content-Security-Policy",
        )
        csp = headers["content-security-policy"]
        self.assertIn(
            "default-src 'none'",
            csp,
            f"CSP must contain 'default-src 'none'', got: {csp}",
        )
        self.assertIn(
            "frame-ancestors 'none'",
            csp,
            f"CSP must contain frame-ancestors 'none', got: {csp}",
        )

    def test_api_catalog_response_includes_x_content_type_options(self) -> None:
        headers = self._get_headers("/.well-known/api-catalog")
        self.assertEqual(
            headers.get("x-content-type-options"),
            "nosniff",
            "/.well-known/api-catalog must carry X-Content-Type-Options: nosniff",
        )

    def test_api_catalog_response_includes_x_frame_options(self) -> None:
        headers = self._get_headers("/.well-known/api-catalog")
        self.assertEqual(
            headers.get("x-frame-options"),
            "DENY",
            "/.well-known/api-catalog must carry X-Frame-Options: DENY",
        )

    def test_api_catalog_response_includes_referrer_policy(self) -> None:
        headers = self._get_headers("/.well-known/api-catalog")
        self.assertEqual(
            headers.get("referrer-policy"),
            "no-referrer",
            "/.well-known/api-catalog must carry Referrer-Policy: no-referrer",
        )

    def test_metadata_index_response_includes_all_security_headers(self) -> None:
        headers = self._get_headers("/metadata/index.json")
        self.assertIn("content-security-policy", headers)
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertEqual(headers.get("referrer-policy"), "no-referrer")

    def test_security_headers_present_on_directory_listing(self) -> None:
        # SimpleHTTPRequestHandler generates HTML for directories; the security
        # headers must still be present even on generated directory-listing responses.
        headers = self._get_headers("/")
        self.assertIn("content-security-policy", headers)
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")

    def test_partial_connection_does_not_block_other_requests(self) -> None:
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as held:
            start = time.monotonic()
            headers = self._get_headers("/.well-known/api-catalog")
            elapsed = time.monotonic() - start

            self.assertLess(elapsed, 1.0)
            self.assertIn("content-security-policy", headers)


class StaticMetadataServerArgParseTest(unittest.TestCase):
    """Unit tests for argument parsing."""

    def setUp(self) -> None:
        self.module = _load_server_module()

    def test_defaults(self) -> None:
        args = self.module._parse_args([])
        self.assertEqual(args.port, 8080)
        self.assertEqual(args.bind, "0.0.0.0")
        self.assertEqual(args.directory, "/srv/static")

    def test_port_positional(self) -> None:
        args = self.module._parse_args(["9090"])
        self.assertEqual(args.port, 9090)

    def test_bind_and_directory_flags(self) -> None:
        args = self.module._parse_args(
            ["--bind", "127.0.0.1", "--directory", "/data"]
        )
        self.assertEqual(args.bind, "127.0.0.1")
        self.assertEqual(args.directory, "/data")


class StaticMetadataServerConcurrencyTest(unittest.TestCase):
    """Unit tests for the server class used by main()."""

    def setUp(self) -> None:
        self.module = _load_server_module()

    def test_server_uses_threaded_daemon_request_handling(self) -> None:
        self.assertTrue(
            issubclass(
                self.module.SecureThreadingHTTPServer,
                self.module.http.server.ThreadingHTTPServer,
            )
        )
        self.assertTrue(self.module.SecureThreadingHTTPServer.daemon_threads)
        self.assertEqual(
            self.module.SecureThreadingHTTPServer.request_queue_size,
            self.module._REQUEST_QUEUE_SIZE,
        )

    def test_accepted_connections_receive_timeout(self) -> None:
        with self.module.SecureThreadingHTTPServer(
            ("127.0.0.1", 0), self.module.SecureStaticHandler
        ) as server:
            port = server.server_address[1]
            with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                accepted, _ = server.get_request()
                try:
                    self.assertEqual(
                        accepted.gettimeout(),
                        self.module._REQUEST_TIMEOUT_SECONDS,
                    )
                finally:
                    accepted.close()
                client.close()


class StaticMetadataServerLoggingTest(unittest.TestCase):
    """Unit tests for request log hardening."""

    def setUp(self) -> None:
        self.module = _load_server_module()

    def test_log_message_translates_control_characters(self) -> None:
        handler = object.__new__(self.module.SecureStaticHandler)
        handler.client_address = ("127.0.0.1", 12345)
        output = io.StringIO()

        with contextlib.redirect_stderr(output):
            handler.log_message("GET %s", "/metadata\n/index\x1b.json")

        line = output.getvalue()
        self.assertNotIn("/metadata\n/index", line)
        self.assertNotIn("\x1b", line)
        self.assertIn(r"/metadata\x0a/index\x1b.json", line)


if __name__ == "__main__":
    unittest.main()
