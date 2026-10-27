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
        relay_path: str = self.server.relay_path  # type: ignore[attr-defined]
        upstream_url: str = self.server.upstream_url  # type: ignore[attr-defined]
        try:
            if self.path != relay_path:
                raise AssertionError(f"relay serves {relay_path}, not {self.path}")
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            forwarded_headers = {
                name: value
                for name, value in self.headers.items()
                if name.lower() not in {"connection", "content-length", "host"}
            }
            response = httpx.post(
                upstream_url,
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
        except Exception as error:
            receipt.error = error
        finally:
            receipt.event.set()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                # The client may have closed its end first; closing ours below is enough.
                pass
            self.connection.close()
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def lost_response_relay(
    target_url: str, path: str, *, expected_status: int = 202
) -> Iterator[tuple[str, UpstreamReceipt]]:
    # The relay forwards one fixed path to one fixed target, so a request cannot
    # steer it anywhere else. It yields its own URL for that path.
    receipt = UpstreamReceipt(expected_status=expected_status)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DropAfterAcceptanceHandler)
    server.relay_path = path  # type: ignore[attr-defined]
    server.upstream_url = f"{target_url.rstrip('/')}{path}"  # type: ignore[attr-defined]
    server.receipt = receipt  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}{path}", receipt
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
