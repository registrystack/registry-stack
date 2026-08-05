#!/usr/bin/env python3
"""A TLS terminator in front of Mint, for the delegation demonstration.

Deployment plumbing, not part of the security story. Mint speaks plain HTTP and
expects an operator-controlled TLS front, and Evidence refuses a non-HTTPS token
issuer, so the demonstration supplies one. In production this is your ingress.

It forwards to Mint on loopback and adds nothing. What it does do is what an
ingress is expected to do: publish only the routes the deployment declares, and
refuse anything it cannot pass on without changing the shape of a message.
"""

import http.client
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The only routes this deployment puts through the front: Mint's key set, which
# Evidence fetches, and its token endpoint, which the client posts to. Mint's
# other routes stay on loopback.
ROUTES = (
    ("GET", "/.well-known/jwks.json"),
    ("POST", "/token"),
)

# Hop-by-hop headers belong to one connection and are not relayed onto the next.
NOT_RELAYED = ("transfer-encoding", "connection", "content-length")

# A header carrying one of these would end the header block early, so the front
# refuses the message rather than passing on something it cannot write intact.
CONTROL_CHARACTERS = ("\r", "\n", "\x00")

UPSTREAM_PORT = None


def route_for(method: str, path: str) -> str | None:
    """The upstream path for a request, or `None` if the front does not serve it.

    The value returned is one of this file's own literals, never the caller's
    request line: the target of the upstream request is fixed here and cannot be
    steered from outside.
    """
    for allowed_method, allowed_path in ROUTES:
        if method == allowed_method and path == allowed_path:
            return allowed_path
    return None


def well_formed(name: str, value: str) -> bool:
    """Whether a header can be relayed without changing the message's framing."""
    return not any(
        character in name or character in value for character in CONTROL_CHARACTERS
    )


def tls_context(certificate: str, key: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # An ingress sets its own floor rather than inheriting whatever the runtime
    # happens to allow.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, key)
    return context


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.forward("GET", None)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.forward("POST", self.rfile.read(length))

    def forward(self, method, body):
        target = route_for(method, self.path)
        if target is None:
            self.refuse(404, "no such route")
            return

        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in ("host", "connection")
        }
        if not all(well_formed(name, value) for name, value in headers.items()):
            self.refuse(400, "request header carried a control character")
            return

        upstream = http.client.HTTPConnection("127.0.0.1", UPSTREAM_PORT, timeout=10)
        try:
            upstream.request(method, target, body=body, headers=headers)
            response = upstream.getresponse()
            payload = response.read()
            status = response.status
            relayed = [
                (name, value)
                for name, value in response.getheaders()
                if name.lower() not in NOT_RELAYED
            ]
        finally:
            upstream.close()

        if not all(well_formed(name, value) for name, value in relayed):
            self.refuse(502, "upstream header carried a control character")
            return

        self.send_response(status)
        for name, value in relayed:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def refuse(self, status, reason):
        payload = json.dumps({"error": reason}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A002 - the base class names it
        pass


if __name__ == "__main__":
    listen_port, UPSTREAM_PORT, certificate, key = (
        int(sys.argv[1]),
        int(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
    )
    server = ThreadingHTTPServer(("127.0.0.1", listen_port), Handler)
    server.socket = tls_context(certificate, key).wrap_socket(
        server.socket, server_side=True
    )
    server.serve_forever()
