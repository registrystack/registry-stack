#!/usr/bin/env python3
"""Private HTTPS fixture for Casework and Evidence live qualification.

This is not an identity provider or production source. It serves one fixed JWKS
document and the bounded synthetic records used by the released Evidence
standalone example. Request paths can contain selectors, so access logging is
disabled.
"""

import argparse
import hmac
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


PRIVATE_CANARY = "PRIVATE_ADDRESS_CANARY_DO_NOT_RELEASE"


def create_server(host, port, jwks, source_token):
    class QualificationHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *values):
            return

        def reply(self, status, body):
            data = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            target = urlsplit(self.path)
            if target.query:
                self.reply(400, {"error": "source.invalid-request"})
                return
            if target.path == "/healthz":
                self.reply(200, {"status": "ready"})
                return
            if target.path == "/.well-known/jwks.json":
                self.reply(200, jwks)
                return

            supplied = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(supplied, b"Bearer " + source_token):
                self.reply(401, {"error": "source.denied"})
                return
            if len(target.path) > 256:
                self.reply(400, {"error": "source.invalid-request"})
                return

            parts = target.path.strip("/").split("/")
            if len(parts) != 2:
                self.reply(404, {"error": "source.not-found"})
                return
            resource, identifier = map(unquote, parts)
            if identifier == "missing":
                self.reply(200, {"total": 0})
                return
            if identifier == "ambiguous":
                self.reply(200, {"total": 2})
                return

            record = None
            if resource == "people" and identifier in {"adult", "minor"}:
                record = {
                    "record_id": identifier,
                    "birth_date": "1980-01-02" if identifier == "adult" else "2015-01-02",
                    "residence_region": "north",
                    "address_canary": PRIVATE_CANARY,
                }
            elif resource == "licences" and identifier in {"active", "suspended", "expired"}:
                record = {"record_id": identifier, "status": identifier}
            elif resource == "parents" and identifier == "child":
                record = {
                    "record_id": identifier,
                    "complete": True,
                    "parents": ["parent", "second-parent"],
                }
            if record is None:
                self.reply(200, {"total": 0})
                return
            self.reply(200, {"total": 1, "record": record})

    return ThreadingHTTPServer((host, port), QualificationHandler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--jwks", type=Path, required=True)
    parser.add_argument("--source-token", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args()

    jwks = json.loads(args.jwks.read_text())
    source_token = args.source_token.read_bytes().strip()
    if not 1 <= len(source_token) <= 4096:
        parser.error("source token must contain 1 through 4096 bytes")

    server = create_server(args.bind, args.port, jwks, source_token)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.certificate, args.private_key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        # Ctrl-C is the intended way to stop this development fixture. The
        # finally block closes the server.
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
