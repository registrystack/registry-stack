#!/usr/bin/env python3
"""Resolve Cargo's exact AWS-LC FIPS dylib directory from build messages."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


class ResolutionError(ValueError):
    """Cargo messages did not identify one usable FIPS runtime directory."""


def rendered_diagnostics(lines: list[str]) -> str:
    rendered: list[str] = []
    for line in lines:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-message":
            continue
        diagnostic = message.get("message")
        if not isinstance(diagnostic, dict):
            continue
        text = diagnostic.get("rendered")
        if isinstance(text, str):
            rendered.append(text)
    return "".join(rendered)


def resolve_aws_lc_fips_artifacts(lines: list[str]) -> Path:
    candidates: list[tuple[Path, str]] = []
    for number, line in enumerate(lines, start=1):
        try:
            message = json.loads(line)
        except json.JSONDecodeError as error:
            raise ResolutionError(f"Cargo message line {number} is not JSON: {error}") from error
        if message.get("reason") != "build-script-executed":
            continue
        if "aws-lc-fips-sys@" not in message.get("package_id", ""):
            continue
        linked = [
            value.removeprefix("dylib=")
            for value in message.get("linked_libs", [])
            if value.startswith("dylib=aws_lc_fips_") and value.endswith("_crypto")
        ]
        if len(linked) != 1:
            raise ResolutionError(
                "the AWS-LC FIPS build message must name exactly one crypto dylib"
            )
        out_dir = message.get("out_dir")
        if not isinstance(out_dir, str) or not out_dir:
            raise ResolutionError("the AWS-LC FIPS build message has no out_dir")
        candidates.append((Path(out_dir) / "build" / "artifacts", linked[0]))

    unique = sorted(set(candidates))
    if len(unique) != 1:
        raise ResolutionError(
            f"Cargo messages identified {len(unique)} AWS-LC FIPS build outputs; expected one"
        )
    artifacts, library = unique[0]
    expected = artifacts / f"lib{library}.dylib"
    if not expected.is_file():
        raise ResolutionError(f"the linked AWS-LC FIPS dylib is missing: {expected}")
    return artifacts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--render-diagnostics",
        action="store_true",
        help="replay rendered rustc diagnostics from a failed Cargo JSON stream",
    )
    parser.add_argument("messages", type=Path, help="Cargo JSON message stream")
    args = parser.parse_args()
    try:
        lines = args.messages.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        print(f"could not read Cargo messages: {error}", file=sys.stderr)
        return 1
    if args.render_diagnostics:
        sys.stdout.write(rendered_diagnostics(lines))
        return 0
    try:
        path = resolve_aws_lc_fips_artifacts(lines)
    except ResolutionError as error:
        print(f"could not resolve the AWS-LC FIPS runtime library: {error}", file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
