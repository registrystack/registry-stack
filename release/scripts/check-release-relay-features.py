#!/usr/bin/env python3
"""Verify that the release Relay binary keeps optional API surfaces disabled."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


DISABLED_FEATURE_MARKERS: dict[str, bytes] = {
    "attribute-release": (
        b"attribute_release_profiles require the attribute-release feature"
    ),
    "ogcapi-features": (
        b"entity declares OGC API Features spatial config but binary was built "
        b"without the ogcapi-features feature"
    ),
    "spdci-api-standards": (
        b"standards.spdci is configured but binary was built without the "
        b"spdci-api-standards feature"
    ),
}


class FeatureCheckError(ValueError):
    pass


def check_binary(path: Path) -> None:
    try:
        payload = path.read_bytes()
    except FileNotFoundError as error:
        raise FeatureCheckError(f"release Relay binary does not exist: {path}") from error
    if not payload.startswith(b"\x7fELF"):
        raise FeatureCheckError(f"release Relay binary is not an ELF executable: {path}")

    missing = [
        feature
        for feature, marker in DISABLED_FEATURE_MARKERS.items()
        if marker not in payload
    ]
    if missing:
        raise FeatureCheckError(
            "release Relay binary does not prove these optional features are "
            f"disabled: {', '.join(missing)}"
        )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        check_binary(args.binary)
    except FeatureCheckError as error:
        print(f"release Relay feature check failed: {error}", file=sys.stderr)
        return 1
    features = ", ".join(DISABLED_FEATURE_MARKERS)
    print(f"verified disabled release Relay features: {features}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
