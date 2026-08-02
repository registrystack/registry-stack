#!/usr/bin/env python3
"""A stand-in registry source for the delegation demonstration.

Deployment plumbing, not part of the security story. Evidence has to call
*something* to answer a requirement; this is the smallest thing that answers.

It serves one route, `POST /v1/facts`, and answers from a fixed synthetic table.
Everything it knows is invented.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# Synthetic people, synthetic residence codes. The bundle's codelist maps
# R-101 to REGION-NORTH and R-201 to REGION-SOUTH.
RECORDS = {
    ("Amara", "Okafor", "1998-04-02"): "R-101",
    ("Kofi", "Mensah", "1971-11-30"): "R-201",
}

EXPECTED_BEARER = os.environ["DEMO_SOURCE_TOKEN"]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/v1/facts":
            return self.reply(404, {"error": "not_found"})
        if self.headers.get("Authorization") != f"Bearer {EXPECTED_BEARER}":
            return self.reply(401, {"error": "unauthorized"})

        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        lookup = body.get("lookup", {})
        key = (
            lookup.get("given_name"),
            lookup.get("family_name"),
            lookup.get("birth_date"),
        )

        # Note what the source receives: the person's identifying details, and
        # nothing about the requirement, the purpose, or the caller.
        print(f"source  <- lookup for {key[0]} {key[1]}", file=sys.stderr, flush=True)

        code = RECORDS.get(key)
        if code is None:
            return self.reply(200, {"total": 0})
        return self.reply(200, {"total": 1, "official_residence_code": code})

    def reply(self, status, payload):
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):  # noqa: A002 - the base class names it
        pass  # the one line printed in do_POST is the whole log we want


if __name__ == "__main__":
    port = int(sys.argv[1])
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
