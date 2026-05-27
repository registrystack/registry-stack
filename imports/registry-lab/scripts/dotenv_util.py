#!/usr/bin/env python3
"""Small dotenv helpers for registry-lab scripts."""

from __future__ import annotations

import os
import shlex
from pathlib import Path


def parse_dotenv_value(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    if value[0] not in ("'", '"'):
        return value
    try:
        parts = shlex.split(value, comments=False, posix=True)
    except ValueError:
        return value
    if len(parts) == 1:
        return parts[0]
    return value


def parse_dotenv_text(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        key, value = line.split("=", 1)
        values[key] = parse_dotenv_value(value)
    return values


def parse_dotenv_file(path: Path) -> dict[str, str]:
    return parse_dotenv_text(path.read_text(encoding="utf-8") if path.exists() else "")


def load_dotenv_file(path: Path, *, override: bool = False) -> None:
    for key, value in parse_dotenv_file(path).items():
        if override:
            os.environ[key] = value
        else:
            os.environ.setdefault(key, value)
