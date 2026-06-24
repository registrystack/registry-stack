#!/usr/bin/env python3
"""Validate a DCAT-AP catalog with vendored SEMIC SHACL shapes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SEMIC_ROOT = (
    REPO_ROOT.parent / "third_party" / "semic-shacl-validator" / "resources" / "semic-shacl"
)

PROFILE_SHAPES = {
    "dcatap.1_2": [
        "dcatap/v1.2/dcat-ap1.2.shapes.all.ttl",
    ],
    "dcatap.2_0_0": [
        "dcatap/v2.0/dcat-ap_2.0.0_shacl_shapes.ttl",
    ],
    "dcatap.vTest": [
        "dcatap/vTest/dcat-ap_2.0.0_shacl_shapes.ttl",
        "dcatap/vTest/dcat-ap_2.0.0_shacl_mdr-vocabularies.shape.ttl",
    ],
    "bregdcatap.2_0_0": [
        "bregdcatap/v2.00/BRegDCAT-AP_shacl_shapes_2.00.ttl",
        "bregdcatap/v2.00/BRegDCAT-AP_shacl_mdr-vocabularies_2.00.ttl",
    ],
    "bregdcatap.2_1_0": [
        "bregdcatap/v2.1.0/BRegDCAT-AP_shacl_shapes_2.1.0.ttl",
        "bregdcatap/v2.1.0/BRegDCAT-AP_shacl_mdr-vocabularies_2.1.0.ttl",
    ],
}


def load_dependencies():
    try:
        from pyshacl import validate
        from rdflib import Graph
    except ModuleNotFoundError as error:
        missing = error.name or "pyshacl"
        raise SystemExit(
            f"Missing Python dependency: {missing}\n"
            "Run with:\n"
            "  uv run --with 'pyshacl>=0.27,<0.31' "
            "--with 'rdflib-jsonld>=0.6' "
            "python scripts/validate_semic_local.py --catalog <file-or-url>\n"
            "or install pyshacl and rdflib-jsonld in your Python environment."
        ) from error
    return Graph, validate


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


def profile_shape_paths(profile: str, semic_root: Path) -> list[Path]:
    try:
        relative_paths = PROFILE_SHAPES[profile]
    except KeyError as error:
        supported = ", ".join(sorted(PROFILE_SHAPES))
        raise SystemExit(f"Unsupported local SEMIC profile: {profile}\nSupported: {supported}") from error

    paths = [semic_root / relative_path for relative_path in relative_paths]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise SystemExit(
            "Missing vendored SEMIC shape file(s):\n"
            + "\n".join(f"  {path}" for path in missing)
            + f"\nCheck --semic-root, currently: {semic_root}"
        )
    return paths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a Registry Relay DCAT-AP JSON-LD catalog with locally vendored "
            "SEMIC SHACL shapes. This is an offline compatibility/gap check, not a "
            "replacement for the European Commission SEMIC ITB validator."
        )
    )
    parser.add_argument(
        "--catalog",
        help="Path or URL for a generated /catalog/dcat-ap.jsonld document.",
    )
    parser.add_argument(
        "--profile",
        default="bregdcatap.2_1_0",
        help="Vendored SEMIC profile to run. Default: bregdcatap.2_1_0.",
    )
    parser.add_argument(
        "--semic-root",
        type=Path,
        default=DEFAULT_SEMIC_ROOT,
        help=f"Path to resources/semic-shacl. Default: {DEFAULT_SEMIC_ROOT}",
    )
    parser.add_argument(
        "--catalog-format",
        default="json-ld",
        help="RDF format for --catalog. Default: json-ld.",
    )
    parser.add_argument(
        "--shapes-format",
        default="turtle",
        help="RDF format for vendored shapes. Default: turtle.",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="HTTP header for URL catalogs, for example 'Authorization: Bearer ...'.",
    )
    parser.add_argument(
        "--save-report",
        help="Optional path to write the SHACL report graph as Turtle.",
    )
    parser.add_argument(
        "--fail-on-warnings",
        action="store_true",
        help=(
            "Treat SHACL warnings as a failing result. By default only SHACL "
            "violations fail, because several vendored SEMIC profiles use "
            "warnings for recommended vocabulary hints."
        ),
    )
    parser.add_argument(
        "--show-report",
        action="store_true",
        help="Print the full SHACL report text even when validation conforms.",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List supported local profiles and exit.",
    )
    return parser.parse_args()


def list_profiles() -> None:
    for profile in sorted(PROFILE_SHAPES):
        print(profile)


def run_validation() -> int:
    args = parse_args()
    if args.list_profiles:
        list_profiles()
        return 0
    if not args.catalog:
        raise SystemExit("--catalog is required unless --list-profiles is used")

    Graph, validate = load_dependencies()
    shapes_paths = profile_shape_paths(args.profile, args.semic_root)

    data_graph = Graph().parse(
        data=read_catalog(args.catalog, request_headers(args.header)),
        format=args.catalog_format,
    )
    shapes_graph = Graph()
    for shapes_path in shapes_paths:
        shapes_graph.parse(shapes_path, format=args.shapes_format)

    conforms, report_graph, report_text = validate(
        data_graph,
        shacl_graph=shapes_graph,
        inference="rdfs",
        abort_on_first=False,
        allow_warnings=not args.fail_on_warnings,
    )

    if args.save_report:
        Path(args.save_report).write_text(
            report_graph.serialize(format="turtle"),
            encoding="utf-8",
        )

    print(
        f"Local SEMIC {args.profile} validation "
        f"{'passed' if conforms else 'failed'} "
        f"({len(data_graph)} data triples, {len(shapes_graph)} shape triples "
        f"from {len(shapes_paths)} vendored file(s))."
    )
    if not conforms or args.show_report:
        print(report_text, file=sys.stderr)
    if not conforms:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run_validation())
