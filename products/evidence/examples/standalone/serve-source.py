#!/usr/bin/env python3
"""Bounded synthetic HTTP source used by the standalone Evidence examples."""
import argparse
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

PRIVATE_CANARY = "PRIVATE_ADDRESS_CANARY_DO_NOT_RELEASE"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--variant", choices=["primary", "alternate"], default="primary")
    parser.add_argument("--person-source-unavailable", action="store_true")
    args = parser.parse_args()
    token = args.token_file.read_bytes().strip() if args.token_file else None
    if token is not None and not 1 <= len(token) <= 4096:
        parser.error("token file must hold one bounded synthetic bearer credential")

    class Source(BaseHTTPRequestHandler):
        # Request paths contain selectors. Keep the fixture's logs value-free.
        def log_message(self, format, *values):
            pass

        def reply(self, status, body):
            data = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if token is not None:
                supplied = self.headers.get("Authorization", "").encode()
                if not hmac.compare_digest(supplied, b"Bearer " + token):
                    self.reply(401, {"error": "source.denied"})
                    return
            path = urlsplit(self.path).path
            if len(path) > 256:
                self.reply(400, {"error": "source.invalid-request"})
                return
            parts = path.strip("/").split("/")
            if len(parts) != 2:
                self.reply(404, {"error": "source.not-found"})
                return
            resource, identifier = map(unquote, parts)
            if resource == "people" and args.person_source_unavailable:
                self.reply(503, {"error": "source.unavailable"})
                return
            if identifier == "missing":
                self.reply(200, {"total": 0})
                return
            if identifier == "ambiguous":
                self.reply(200, {"total": 2})
                return
            record = None
            if resource == "people" and identifier in {"adult", "minor"}:
                record = {"record_id": identifier, "birth_date": "1980-01-02" if identifier == "adult" else "2015-01-02", "residence_region": "north", "address_canary": PRIVATE_CANARY}
            elif resource == "licences" and identifier in {"active", "suspended", "expired"}:
                record = {"record_id": identifier, "status": identifier}
            elif resource == "parents" and identifier == "child":
                record = {"record_id": identifier, "complete": True, "parents": ["parent", "second-parent"]}
            elif resource == "operators" and identifier in {"active", "inactive", "suspended"}:
                record = {"operator_id": identifier, "active": identifier != "inactive", "status": identifier, "address_canary": PRIVATE_CANARY}
            if record is None:
                self.reply(200, {"total": 0})
                return
            # Alternate implementation deliberately changes member order and
            # private source data. It satisfies the same reviewed source shape.
            if args.variant == "alternate":
                if "address_canary" in record:
                    record["address_canary"] = "ALTERNATE_PRIVATE_CANARY_DO_NOT_RELEASE"
                record = dict(reversed(list(record.items())))
            self.reply(200, {"total": 1, "record": record})

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Source)
    print("Synthetic source ready on loopback", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
