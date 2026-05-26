#!/usr/bin/env python3
"""Static metadata HTTP server with standards-aware media types."""

from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

API_CATALOG_LINK = (
    '</.well-known/api-catalog>; rel="api-catalog"; '
    'type="application/linkset+json"; profile="https://www.rfc-editor.org/info/rfc9727"'
)
LINKSET_JSON = 'application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727"'


class StaticMetadataHandler(SimpleHTTPRequestHandler):
    def guess_type(self, path: str) -> str:
        request_path = self.path.split("?", 1)[0]
        if request_path == "/.well-known/api-catalog":
            return LINKSET_JSON
        if (
            request_path.endswith(".jsonld")
            or request_path.endswith("/bregdcat-ap")
            or request_path.endswith("/cpsv-ap")
        ):
            return "application/ld+json"
        return super().guess_type(path)

    def end_headers(self) -> None:
        request_path = self.path.split("?", 1)[0]
        if request_path == "/.well-known/api-catalog":
            self.send_header("Link", API_CATALOG_LINK)
        super().end_headers()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", default="/srv/static")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    directory = Path(args.directory).resolve()

    class Handler(StaticMetadataHandler):
        def __init__(self, *handler_args, **handler_kwargs):
            super().__init__(*handler_args, directory=str(directory), **handler_kwargs)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"serving static metadata from {directory} on {args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
