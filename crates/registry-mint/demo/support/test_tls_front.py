#!/usr/bin/env python3
"""Tests for the demonstration's TLS front.

The front is deployment plumbing, but it is plumbing in a public repository, so
the two properties worth pinning are the ones a real ingress would be judged on:
it forwards only the routes the deployment declares, and it never relays a
header it cannot write safely.
"""

import importlib.util
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

SUPPORT = Path(__file__).resolve().parent


def load_module():
    specification = importlib.util.spec_from_file_location(
        "demo_tls_front", SUPPORT / "tls_front.py"
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


tls_front = load_module()


class RouteAllowlistTests(unittest.TestCase):
    def test_declared_routes_forward_to_a_constant_path(self):
        self.assertEqual("/token", tls_front.route_for("POST", "/token"))
        self.assertEqual(
            "/.well-known/jwks.json",
            tls_front.route_for("GET", "/.well-known/jwks.json"),
        )

    def test_every_forwarded_path_is_one_this_file_declares(self):
        for method in ("GET", "POST", "PUT"):
            for path in ("/token", "/.well-known/jwks.json", "/anything"):
                forwarded = tls_front.route_for(method, path)
                if forwarded is not None:
                    self.assertIn((method, forwarded), tls_front.ROUTES)

    def test_undeclared_routes_are_refused(self):
        for method, path in (
            ("GET", "/token"),  # right path, wrong method
            ("POST", "/.well-known/jwks.json"),
            ("GET", "/health"),
            ("GET", "/"),
            ("GET", "/token/../admin"),
            ("GET", "http://elsewhere.invalid/token"),  # absolute-form request line
            ("GET", "//elsewhere.invalid/token"),
            ("GET", "/.well-known/jwks.json?x=1"),
        ):
            with self.subTest(method=method, path=path):
                self.assertIsNone(tls_front.route_for(method, path))


class HeaderValidationTests(unittest.TestCase):
    def test_ordinary_headers_are_well_formed(self):
        self.assertTrue(tls_front.well_formed("Content-Type", "application/json"))

    def test_control_characters_are_rejected_in_name_or_value(self):
        for name, value in (
            ("X-Demo", "ok\r\nInjected: yes"),
            ("X-Demo", "ok\nInjected: yes"),
            ("X-Demo", "ok\r"),
            ("X-Demo", "ok\x00"),
            ("X-Demo\r\nInjected", "ok"),
            ("X-Demo\n", "ok"),
        ):
            with self.subTest(name=name, value=value):
                self.assertFalse(tls_front.well_formed(name, value))


class TlsContextTests(unittest.TestCase):
    def test_the_listener_refuses_anything_below_tls_1_2(self):
        certificate, key = write_self_signed()
        context = tls_front.tls_context(certificate, key)
        self.assertEqual(ssl.TLSVersion.TLSv1_2, context.minimum_version)


class ForwardingTests(unittest.TestCase):
    """End to end over real sockets, with a stub standing in for Mint."""

    def setUp(self):
        self.upstream = StubUpstream()
        self.upstream.start()
        self.addCleanup(self.upstream.stop)

        tls_front.UPSTREAM_PORT = self.upstream.port
        self.front = ThreadingHTTPServer(("127.0.0.1", 0), tls_front.Handler)
        threading.Thread(target=self.front.serve_forever, daemon=True).start()
        self.addCleanup(self.front.server_close)  # cleanups run last-registered first
        self.addCleanup(self.front.shutdown)
        self.port = self.front.server_address[1]

    def request(self, raw: bytes) -> bytes:
        # `Connection: close` so the read below ends at end of message rather
        # than waiting out the keep-alive.
        raw = raw[: -len(b"\r\n\r\n")] + b"\r\nConnection: close\r\n\r\n"
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as client:
            client.sendall(raw)
            chunks = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)

    def test_a_declared_route_round_trips(self):
        self.upstream.reply = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: 2\r\n\r\n{}"
        )
        response = self.request(
            b"GET /.well-known/jwks.json HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        self.assertIn(b"200 OK", response)
        self.assertIn(b"{}", response)
        self.assertEqual(["/.well-known/jwks.json"], self.upstream.seen)

    def test_an_undeclared_route_never_reaches_the_upstream(self):
        response = self.request(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertIn(b"404", response)
        self.assertEqual([], self.upstream.seen)

    def test_a_request_header_carrying_a_control_character_is_refused(self):
        response = self.request(
            b"GET /.well-known/jwks.json HTTP/1.1\r\nHost: localhost\r\n"
            b"X-Demo: first\r\n\tsecond\r\n\r\n"
        )
        self.assertIn(b"400", response)
        self.assertEqual([], self.upstream.seen)

    def test_an_upstream_header_that_cannot_be_written_safely_is_not_relayed(self):
        # An obs-folded header: `http.client` hands this back with the newline
        # still in the value, and writing it out verbatim would split the
        # response.
        self.upstream.reply = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            b"X-Demo: first\r\n\tsecond\r\n\r\n{}"
        )
        response = self.request(
            b"GET /.well-known/jwks.json HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        self.assertIn(b"502", response)
        self.assertNotIn(b"second", response)


class StubUpstream:
    """A raw socket server so a test can send bytes `http.server` would refuse."""

    def __init__(self):
        self.reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
        self.seen: list[str] = []
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.port = self.socket.getsockname()[1]
        self.running = True

    def start(self):
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while self.running:
            try:
                connection, _ = self.socket.accept()
            except OSError:
                return
            with connection:
                connection.settimeout(5)
                try:
                    request = connection.recv(65536)
                except OSError:
                    continue
                if not request:
                    continue
                self.seen.append(request.split(b" ")[1].decode())
                connection.sendall(self.reply)

    def stop(self):
        self.running = False
        self.socket.close()


def write_self_signed() -> tuple[str, str]:
    """A throwaway certificate and key, via `openssl`.

    The demonstration's own provisioning uses `cryptography`, but nothing in
    this repository's continuous integration installs it, and a test that skips
    is a test that does not hold. `openssl` is already what `run.sh` reaches for
    and is present wherever this suite runs.
    """
    openssl = shutil.which("openssl")
    if openssl is None:  # pragma: no cover - depends on the environment
        raise unittest.SkipTest("openssl is not installed")

    directory = Path(tempfile.mkdtemp())
    certificate_path = directory / "tls.pem"
    key_path = directory / "tls.key"
    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "ed25519", "-noenc",
            "-days", "1", "-subj", "/CN=localhost",
            "-keyout", str(key_path), "-out", str(certificate_path),
        ],
        check=True,
        capture_output=True,
    )
    return str(certificate_path), str(key_path)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
