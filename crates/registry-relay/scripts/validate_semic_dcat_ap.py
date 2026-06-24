#!/usr/bin/env python3
"""Validate a DCAT-AP catalog with the external SEMIC SHACL validator."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_ENDPOINT = "https://www.itb.ec.europa.eu/shacl/semic-shacl/api/validate"
DEFAULT_VALIDATION_TYPE = "dcatap.3_0_1_base"


def request_headers(header_args: list[str]) -> dict[str, str]:
    headers = {"Accept": "application/ld+json"}
    for header in header_args:
        if ":" not in header:
            raise SystemExit(f"Invalid --header value, expected 'Name: value': {header}")
        name, value = header.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def read_catalog(source: str, headers: dict[str, str]) -> bytes:
    if source.startswith(("http://", "https://")):
        request = Request(source, headers=headers)
        with urlopen(request, timeout=30) as response:
            return response.read()
    return Path(source).read_bytes()


def post_validation(endpoint: str, payload: dict[str, str]) -> dict[str, object]:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise SystemExit(f"SEMIC validator returned HTTP {error.code}:\n{detail}") from error
    except URLError as error:
        raise SystemExit(f"SEMIC validator request failed: {error}") from error


def error_items(report: dict[str, object], key: str) -> list[dict[str, object]]:
    reports = report.get("reports")
    if not isinstance(reports, dict):
        return []
    items = reports.get(key)
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]
    if isinstance(items, dict):
        return [items]
    return []


def print_findings(report: dict[str, object]) -> None:
    for severity in ("error", "warning", "info"):
        items = error_items(report, severity)
        if not items:
            continue
        print(f"{severity.upper()} findings:", file=sys.stderr)
        for item in items:
            description = item.get("description", "(no description)")
            location = item.get("location")
            test = item.get("test")
            print(f"- {description}", file=sys.stderr)
            if location:
                print(f"  location: {location}", file=sys.stderr)
            if test:
                print(f"  test: {test}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Submit a generated /catalog/dcat-ap.jsonld document to the European "
            "Commission SEMIC SHACL validator. Catalog content is embedded as "
            "base64 by default, so the source URL does not need to be publicly reachable."
        )
    )
    parser.add_argument(
        "--catalog",
        required=True,
        help="Path or URL for a generated /catalog/dcat-ap.jsonld document.",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"SEMIC validator REST endpoint. Default: {DEFAULT_ENDPOINT}",
    )
    parser.add_argument(
        "--validation-type",
        default=DEFAULT_VALIDATION_TYPE,
        help=f"SEMIC validation type. Default: {DEFAULT_VALIDATION_TYPE}",
    )
    parser.add_argument(
        "--content-syntax",
        default="application/ld+json",
        help="Input syntax sent to SEMIC. Default: application/ld+json.",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="HTTP header for URL catalogs, for example 'Authorization: Bearer ...'.",
    )
    parser.add_argument(
        "--save-report",
        help="Optional path to write the JSON validation report.",
    )
    return parser.parse_args()


def run() -> int:
    args = parse_args()
    catalog = read_catalog(args.catalog, request_headers(args.header))
    payload = {
        "contentToValidate": base64.b64encode(catalog).decode("ascii"),
        "contentSyntax": args.content_syntax,
        "embeddingMethod": "BASE64",
        "validationType": args.validation_type,
        "reportSyntax": "application/json",
    }

    report = post_validation(args.endpoint, payload)
    if args.save_report:
        Path(args.save_report).write_text(json.dumps(report, indent=2), encoding="utf-8")

    result = str(report.get("result", "")).upper()
    counters = report.get("counters", {})
    print(f"SEMIC {args.validation_type} result: {result}")
    if isinstance(counters, dict):
        print(
            "Counters: "
            f"errors={counters.get('nrOfErrors', 0)}, "
            f"warnings={counters.get('nrOfWarnings', 0)}, "
            f"assertions={counters.get('nrOfAssertions', 0)}"
        )

    if result != "SUCCESS":
        print_findings(report)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
