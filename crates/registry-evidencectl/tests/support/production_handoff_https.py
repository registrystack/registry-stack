"""Silent local HTTPS issuer and sanitized Evidence source for acceptance tests."""

import http.client
import http.server
import json
import os
import pathlib
import ssl


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "EvidenceAcceptance/1"

    def log_message(self, _format, *_args):
        pass

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self._json(pathlib.Path(os.environ["ACCEPTANCE_JWKS"]).read_bytes())
            return
        self.send_error(404)

    def do_POST(self):
        if self.path == "/token" and os.environ.get("ACCEPTANCE_MINT_PORT"):
            self._proxy_mint_token()
            return
        if self.path != "/v1/facts":
            self.send_error(404)
            return
        expected = "Bearer " + pathlib.Path(
            os.environ["ACCEPTANCE_SOURCE_TOKEN"]
        ).read_text().strip()
        if self.headers.get("Authorization") != expected:
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        if request != {
            "lookup": {"person_id": "synthetic-person-001"},
            "fields": ["date_of_birth"],
            "limit": 2,
        }:
            self.send_error(400)
            return
        pathlib.Path(os.environ["ACCEPTANCE_SOURCE_MARKER"]).write_text("requested\n")
        self._json(b'{"total":1,"date_of_birth":"2000-01-01"}')

    def _proxy_mint_token(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length <= 0 or length > 65536:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        upstream = http.client.HTTPConnection(
            "127.0.0.1", int(os.environ["ACCEPTANCE_MINT_PORT"]), timeout=5
        )
        try:
            upstream.request(
                "POST",
                "/token",
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = upstream.getresponse()
            response_body = response.read(1048577)
            if len(response_body) > 1048576:
                self.send_error(502)
                return
            self.send_response(response.status)
            self.send_header(
                "Content-Type", response.getheader("Content-Type", "application/json")
            )
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)
        except (OSError, http.client.HTTPException):
            self.send_error(502)
        finally:
            upstream.close()

    def _json(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


address = ("127.0.0.1", int(os.environ["ACCEPTANCE_HTTPS_PORT"]))
server = http.server.ThreadingHTTPServer(address, Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# The stand-in sets its own floor rather than inheriting whatever the runtime
# happens to allow, so the handoff is proven over the transport a deployment
# would actually run.
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(
    os.environ["ACCEPTANCE_TLS_CERT"], os.environ["ACCEPTANCE_TLS_KEY"]
)
server.socket = context.wrap_socket(server.socket, server_side=True)
pathlib.Path(os.environ["ACCEPTANCE_READY"]).write_text("ready\n")
server.serve_forever()
