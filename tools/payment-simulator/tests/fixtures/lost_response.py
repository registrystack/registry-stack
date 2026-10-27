from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import httpx


@dataclass
class UpstreamReceipt:
    expected_status: int = 202
    event: threading.Event = field(default_factory=threading.Event)
    status_code: int | None = None
    body: bytes | None = None
    error: BaseException | None = None


class _DropAfterAcceptanceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        receipt: UpstreamReceipt = self.server.receipt  # type: ignore[attr-defined]
        target_url: str = self.server.target_url  # type: ignore[attr-defined]
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            forwarded_headers = {
                name: value
                for name, value in self.headers.items()
                if name.lower() not in {"connection", "content-length", "host"}
            }
            response = httpx.post(
                f"{target_url}{self.path}",
                headers=forwarded_headers,
                content=body,
                timeout=5.0,
            )
            receipt.status_code = response.status_code
            receipt.body = response.content
            if response.status_code != receipt.expected_status:
                raise AssertionError(
                    f"upstream returned {response.status_code}, expected {receipt.expected_status}"
                )
        except BaseException as error:
            receipt.error = error
        finally:
            receipt.event.set()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def lost_response_relay(
    target_url: str, *, expected_status: int = 202
) -> Iterator[tuple[str, UpstreamReceipt]]:
    receipt = UpstreamReceipt(expected_status=expected_status)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DropAfterAcceptanceHandler)
    server.target_url = target_url.rstrip("/")  # type: ignore[attr-defined]
    server.receipt = receipt  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", receipt
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
