#!/usr/bin/env python3
"""A TLS terminator in front of Mint, for the delegation demonstration.

Deployment plumbing, not part of the security story. Mint speaks plain HTTP and
expects an operator-controlled TLS front, and Evidence refuses a non-HTTPS token
issuer, so the demonstration supplies one. In production this is your ingress.

Forwards verbatim to Mint on loopback. It adds nothing and inspects nothing.
"""

import http.client
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.forward("GET", None)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.forward("POST", self.rfile.read(length))

    def forward(self, method, body):
        upstream = http.client.HTTPConnection("127.0.0.1", UPSTREAM_PORT, timeout=10)
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in ("host", "connection")
        }
        upstream.request(method, self.path, body=body, headers=headers)
        response = upstream.getresponse()
        payload = response.read()

        self.send_response(response.status)
        for name, value in response.getheaders():
            if name.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        upstream.close()

    def log_message(self, format, *args):  # noqa: A002 - the base class names it
        pass


if __name__ == "__main__":
    listen_port, UPSTREAM_PORT, certificate, key = (
        int(sys.argv[1]),
        int(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server = ThreadingHTTPServer(("127.0.0.1", listen_port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
