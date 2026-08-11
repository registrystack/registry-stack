"""A minimal, stdlib-only HTTP stub for the Python Evidence client suite.

Not a mock framework: each test mounts exactly the routes it needs on
`StubServer.routes` and reads `StubServer.requests` back for anything it
wants to assert about what the client sent. Modeled on
`crates/registry-evidence-client-node/__test__/helpers/stub-server.js`,
adapted to Python's own `http.server` instead of Node's `http` module.
"""

from __future__ import annotations

import http.server
import sys
import threading
import time
from dataclasses import dataclass, field


TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


class _StubHTTPServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address) -> None:  # noqa: ANN001
        # The oversized-response test deliberately makes the client stop
        # reading partway through a response; on this server's background
        # thread, that surfaces as a write failing with `ConnectionResetError`
        # (or, on some platforms, `BrokenPipeError`). That is the expected
        # shape of "the client gave up first," not a defect, so only a
        # genuinely unexpected exception still gets the stdlib's default
        # traceback-to-stderr reporting.
        _, exc_value, _ = sys.exc_info()
        if isinstance(exc_value, (ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


@dataclass
class RecordedRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class StubRoute:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    # Only the GIL-release concurrency test uses this: it holds the response
    # back long enough to make two concurrent client calls observably
    # overlap (or fail to) in wall-clock time.
    delay_seconds: float = 0.0
    include_traceparent: bool = True


class StubServer:
    """One loopback HTTP server for the duration of a single test.

    `routes` is keyed `"METHOD /path"` (for example
    `"GET /v1/evidence-definitions"`), matching exactly the request line the
    Evidence client sends: no query string, no host. A request for a route
    that was not mounted gets a bare 404 with an empty body, which the client
    reports as a protocol failure regardless of which endpoint it hit.
    """

    def __init__(self, routes: dict[str, StubRoute]):
        self.routes = routes
        self.requests: list[RecordedRequest] = []
        lock = threading.Lock()
        routes_ref = self.routes
        requests_ref = self.requests

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length) if length else b""
                with lock:
                    requests_ref.append(
                        RecordedRequest(
                            method=self.command,
                            path=self.path,
                            # HTTP header names are case-insensitive, and
                            # reqwest sends them lowercase; unlike Node's
                            # `http` module (which lowercases incoming
                            # header names for you), Python's `http.server`
                            # preserves whatever casing arrived on the wire,
                            # so this normalizes it the same way for callers
                            # comparing against a literal name.
                            headers={k.lower(): v for k, v in self.headers.items()},
                            body=body,
                        )
                    )
                route = routes_ref.get(f"{self.command} {self.path}")
                if route is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if route.delay_seconds:
                    time.sleep(route.delay_seconds)
                self.send_response(route.status)
                if route.include_traceparent and not any(
                    name.lower() == "traceparent" for name in route.headers
                ):
                    self.send_header("traceparent", TRACEPARENT)
                for name, value in route.headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(route.body)))
                self.end_headers()
                if route.body:
                    self.wfile.write(route.body)

            def do_GET(self) -> None:  # noqa: N802 - stdlib's own naming convention
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

            def log_message(self, log_format: str, *args: object) -> None:
                # The stdlib default writes every request to stderr; this
                # suite's own assertions are the record of what happened, not
                # the console.
                pass

        self._httpd = _StubHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join()
