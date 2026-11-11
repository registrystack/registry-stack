#!/usr/bin/env python3
"""Dev-only Unix-socket proxy for one isolated Vault Transit key.

The proxy is deliberately narrower than a general Vault proxy. It forwards only
the two operations Evidence needs for the fixed ``evidence-signing`` key and
keeps the synthetic Vault token outside the Evidence container. It is a live
qualification fixture, not a production custody design.
"""

import argparse
import http.client
import os
import socketserver
from http.server import BaseHTTPRequestHandler
from pathlib import Path


KEY_NAME = "evidence-signing"
ALLOWED = {
    ("GET", f"/v1/transit/keys/{KEY_NAME}"),
    ("POST", f"/v1/transit/sign/{KEY_NAME}/sha2-256"),
}
MAXIMUM_REQUEST_BYTES = 64 * 1024
MAXIMUM_RESPONSE_BYTES = 1024 * 1024


def is_allowed(method, path):
    return (method, path) in ALLOWED


def handler_factory(vault_host, vault_port, vault_token):
    class TransitProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *values):
            return

        def send_json_error(self, status, message):
            body = (f'{{"errors":["{message}"]}}').encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.forward()

        def do_POST(self):
            self.forward()

        def forward(self):
            if not is_allowed(self.command, self.path):
                self.send_json_error(403, "qualification proxy refused the operation")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_json_error(400, "invalid content length")
                return
            if length < 0 or length > MAXIMUM_REQUEST_BYTES:
                self.send_json_error(413, "request is too large")
                return
            body = self.rfile.read(length) if length else None
            headers = {
                "X-Vault-Token": vault_token,
                "X-Vault-Request": "true",
            }
            if body is not None:
                headers["Content-Type"] = "application/json"

            connection = http.client.HTTPConnection(vault_host, vault_port, timeout=2)
            try:
                connection.request(self.command, self.path, body=body, headers=headers)
                upstream = connection.getresponse()
                response = upstream.read(MAXIMUM_RESPONSE_BYTES + 1)
                if len(response) > MAXIMUM_RESPONSE_BYTES:
                    self.send_json_error(502, "upstream response is too large")
                    return
                self.send_response(upstream.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except (OSError, http.client.HTTPException):
                self.send_json_error(502, "transit provider is unavailable")
            finally:
                connection.close()

    return TransitProxyHandler


class ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--vault-host", required=True)
    parser.add_argument("--vault-port", type=int, default=8200)
    parser.add_argument("--token-file", type=Path, required=True)
    args = parser.parse_args()

    if args.socket.exists() or args.socket.is_symlink():
        parser.error("refusing to replace an existing socket path")
    token = args.token_file.read_text().strip()
    if not 1 <= len(token) <= 4096 or any(character.isspace() for character in token):
        parser.error("token file must hold one bounded token")

    args.socket.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handler = handler_factory(args.vault_host, args.vault_port, token)
    with ThreadingUnixServer(str(args.socket), handler) as server:
        os.chmod(args.socket, 0o600)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
