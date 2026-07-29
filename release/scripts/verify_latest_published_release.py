#!/usr/bin/env python3
"""Verify that a dispatch targets GitHub's latest published full release."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


TAG_PATTERN = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def verify_latest_published_release(metadata: Any, expected_tag: str) -> None:
    if not TAG_PATTERN.fullmatch(expected_tag):
        raise ValueError("expected tag must be canonical v<major>.<minor>.<patch> text")
    if not isinstance(metadata, dict):
        raise ValueError("latest release metadata must be a JSON object")
    if metadata.get("draft") is not False:
        raise ValueError("latest release metadata must describe a published release")
    if metadata.get("prerelease") is not False:
        raise ValueError("latest release metadata must describe a non-prerelease")
    published_at = metadata.get("published_at")
    if not isinstance(published_at, str) or not published_at:
        raise ValueError("latest release metadata is missing published_at")
    actual_tag = metadata.get("tag_name")
    if actual_tag != expected_tag:
        raise ValueError(
            f"dispatched release {expected_tag} is stale; latest published "
            f"non-prerelease is {actual_tag!r}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--expected-tag", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
        verify_latest_published_release(metadata, args.expected_tag)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
