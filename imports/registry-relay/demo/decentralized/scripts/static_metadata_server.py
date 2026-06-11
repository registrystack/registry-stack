#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Static metadata HTTP server with browser-hardening security headers.

Drop-in replacement for `python -m http.server` that adds the baseline
security headers required by issue #88 (LAB-008). The static metadata
publisher serves JSON/YAML/JSON-LD API documents, not HTML pages, so the
Content-Security-Policy uses a restrictive `default-src 'none'` policy
appropriate for API responses.

Usage (matches the docker-compose command shape):
    python static_metadata_server.py [port] [--bind address] [--directory dir]
"""

from __future__ import annotations

import argparse
import http.server
import os
import sys


# Security headers added to every response. All static files served here
# are machine-readable API documents (JSON, JSON-LD, YAML); none are HTML.
# `default-src 'none'` is therefore the correct CSP: the files carry no
# executable content and browsers should not load sub-resources from them.
_SECURITY_HEADERS: list[tuple[str, str]] = [
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
]


class SecureStaticHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler with baseline security headers on every response."""

    def end_headers(self) -> None:
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        super().end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # Write to stderr so container log drivers capture it without
        # mixing with any structured stdout output.
        sys.stderr.write(
            "%s - - [%s] %s\n"
            % (self.address_string(), self.log_date_time_string(), format % args)
        )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Static file server with security headers",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("port", nargs="?", type=int, default=8080, help="TCP port")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument(
        "--directory",
        default="/srv/static",
        help="Root directory to serve files from",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)

    # Change into the target directory so SimpleHTTPRequestHandler resolves
    # paths relative to it, matching the behaviour of `python -m http.server
    # --directory`.
    os.chdir(args.directory)

    handler = SecureStaticHandler
    with http.server.HTTPServer((args.bind, args.port), handler) as httpd:
        sys.stderr.write(
            f"Serving {args.directory!r} on {args.bind}:{args.port} "
            f"with security headers\n"
        )
        httpd.serve_forever()


if __name__ == "__main__":
    main()
