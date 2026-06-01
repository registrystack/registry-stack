#!/usr/bin/env python3
"""Check the container build contract that CI cannot infer from Docker alone."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_CONTENT_CACHE: dict[Path, str] = {}


def require(path: Path, needle: str, detail: str) -> list[str]:
    if path not in _CONTENT_CACHE:
        _CONTENT_CACHE[path] = path.read_text(encoding="utf-8")
    text = _CONTENT_CACHE[path]
    if needle in text:
        return []
    return [f"{path.relative_to(ROOT)}: missing {detail}: {needle!r}"]


def main() -> int:
    dockerfile = ROOT / "Dockerfile"
    build_script = ROOT / "scripts" / "build-image.sh"

    failures: list[str] = []
    failures.extend(
        require(
            dockerfile,
            'ARG REGISTRY_RELAY_FEATURES=""',
            "empty-by-default feature build arg",
        )
    )
    failures.extend(
        require(
            dockerfile,
            'cargo build --release --locked --features "$REGISTRY_RELAY_FEATURES"',
            "feature-enabled cargo build path",
        )
    )
    failures.extend(
        require(
            dockerfile,
            "cargo build --release --locked",
            "default cargo build path",
        )
    )
    failures.extend(
        require(
            build_script,
            'manifest_dir="${REGISTRY_MANIFEST_DIR:-../registry-manifest}"',
            "registry-manifest build context override",
        )
    )
    failures.extend(
        require(
            build_script,
            '--build-context "registry-manifest=$manifest_dir"',
            "registry-manifest build context",
        )
    )
    failures.extend(
        require(
            build_script,
            '--build-arg "REGISTRY_RELAY_FEATURES=$REGISTRY_RELAY_FEATURES"',
            "optional feature build arg forwarding",
        )
    )

    if failures:
        print("Docker build contract check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("Docker build contract check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
