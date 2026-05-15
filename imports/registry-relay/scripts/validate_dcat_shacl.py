#!/usr/bin/env python3
"""Validate a generated data_gate DCAT-AP JSON-LD catalog with pySHACL."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SHAPES = REPO_ROOT / "tests" / "fixtures" / "shacl" / "dcat-ap-catalog-smoke.ttl"


def load_dependencies():
    try:
        from pyshacl import validate
        from pyshacl.errors import ReportableRuntimeError
        from rdflib import Graph
    except ModuleNotFoundError as error:
        missing = error.name or "pyshacl"
        raise SystemExit(
            f"Missing Python dependency: {missing}\n"
            "Run with:\n"
            "  uv run --with 'pyshacl>=0.27,<0.31' "
            "--with 'rdflib-jsonld>=0.6' "
            "python scripts/validate_dcat_shacl.py --catalog <file-or-url>\n"
            "or install pyshacl and rdflib-jsonld in your Python environment."
        ) from error
    return Graph, validate, ReportableRuntimeError


def request_headers(header_args: list[str]) -> dict[str, str]:
    headers = {"Accept": "application/ld+json"}
    for header in header_args:
        if ":" not in header:
            raise SystemExit(f"Invalid --header value, expected 'Name: value': {header}")
        name, value = header.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def read_catalog(source: str, headers: dict[str, str]) -> bytes | str:
    if source.startswith(("http://", "https://")):
        request = Request(source, headers=headers)
        with urlopen(request, timeout=30) as response:
            return response.read()
    return Path(source).read_text(encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a data_gate DCAT-AP JSON-LD catalog with a real SHACL engine. "
            "The default shape fixture is a CI-friendly DCAT-AP smoke profile; "
            "pass --shapes to use stricter external DCAT-AP shapes."
        )
    )
    parser.add_argument(
        "--catalog",
        required=True,
        help="Path or URL for a generated /catalog/dcat-ap.jsonld document.",
    )
    parser.add_argument(
        "--shapes",
        default=str(DEFAULT_SHAPES),
        help="Path to a Turtle SHACL shapes file.",
    )
    parser.add_argument(
        "--catalog-format",
        default="json-ld",
        help="RDF format for --catalog. Default: json-ld.",
    )
    parser.add_argument(
        "--shapes-format",
        default="turtle",
        help="RDF format for --shapes. Default: turtle.",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="HTTP header for URL catalogs, for example 'Authorization: Bearer ...'.",
    )
    parser.add_argument(
        "--skip-metashacl",
        action="store_true",
        help="Skip SHACL-SHACL validation of embedded entity shapes.",
    )
    return parser.parse_args()


def run_validation() -> int:
    args = parse_args()
    Graph, validate, ReportableRuntimeError = load_dependencies()

    data_graph = Graph().parse(
        data=read_catalog(args.catalog, request_headers(args.header)),
        format=args.catalog_format,
    )
    shapes_graph = Graph().parse(args.shapes, format=args.shapes_format)

    conforms, _report_graph, report_text = validate(
        data_graph,
        shacl_graph=shapes_graph,
        inference="rdfs",
        abort_on_first=False,
    )
    if not conforms:
        print(report_text, file=sys.stderr)
        return 1

    if not args.skip_metashacl:
        try:
            embedded_conforms, _embedded_report_graph, embedded_report_text = validate(
                data_graph,
                shacl_graph=data_graph,
                meta_shacl=True,
                advanced=True,
                abort_on_first=False,
            )
        except ReportableRuntimeError as error:
            print(str(error), file=sys.stderr)
            return 1
        if not embedded_conforms:
            print(embedded_report_text, file=sys.stderr)
            return 1

    print(
        "DCAT-AP catalog SHACL validation passed "
        f"({len(data_graph)} data triples, {len(shapes_graph)} shape triples)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run_validation())
