#!/usr/bin/env python3
"""Serve the tutorial's exact local provider-publication bytes."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MEDIA_TYPE = (
    'application/ld+json;profile="https://registrystack.org/discovery/profile/v1alpha1"'
)


class PublicationHandler(BaseHTTPRequestHandler):
    descriptions: dict[str, bytes]

    def do_GET(self) -> None:  # noqa: N802
        body = self.descriptions.get(self.path)
        if body is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", MEDIA_TYPE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--descriptions", type=Path, required=True)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=38090)
    args = parser.parse_args()

    PublicationHandler.descriptions = {
        "/evidence.jsonld": (args.descriptions / "evidence.jsonld").read_bytes(),
        "/relay.jsonld": (args.descriptions / "relay.jsonld").read_bytes(),
    }
    server = ThreadingHTTPServer((args.address, args.port), PublicationHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
