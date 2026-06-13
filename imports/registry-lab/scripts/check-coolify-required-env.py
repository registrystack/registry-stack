#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail fast when a Coolify app is missing hosted Registry Lab env vars."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def required_env_keys(compose_path: Path) -> list[str]:
    keys: list[str] = []
    in_required_env = False
    for line in compose_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "x-coolify-required-env:":
            in_required_env = True
            continue
        if not in_required_env:
            continue
        if line and not line.startswith((" ", "\t")):
            break
        if stripped.startswith("- "):
            keys.append(stripped[2:].strip())
    if not keys:
        raise SystemExit(f"{compose_path}: x-coolify-required-env must be a non-empty list")
    normalized = sorted({str(key) for key in keys})
    if any(not key or "=" in key for key in normalized):
        raise SystemExit(f"{compose_path}: x-coolify-required-env contains an invalid key")
    return normalized


def fetch_coolify_envs(api_base_url: str, app_uuid: str, token: str) -> Any:
    api_base = api_base_url.rstrip("/")
    request = urllib.request.Request(
        f"{api_base}/applications/{app_uuid}/envs",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Coolify env read failed with HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Coolify env read failed: {exc}") from exc


def collect_env_values(payload: Any) -> dict[str, str]:
    entries = list(iter_env_entries(payload))
    values: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("is_preview") is True:
            continue
        key = entry.get("key") or entry.get("name")
        if not isinstance(key, str) or not key:
            continue
        raw_value = entry.get("value")
        if raw_value is None:
            raw_value = entry.get("real_value")
        values[key] = "" if raw_value is None else str(raw_value)
    return values


def iter_env_entries(payload: Any):
    if isinstance(payload, list):
        yield from payload
        return
    if not isinstance(payload, dict):
        return
    for key in ("data", "envs", "environment_variables", "environmentVariables"):
        value = payload.get(key)
        if isinstance(value, list):
            yield from value
            return
    if all(isinstance(value, str) for value in payload.values()):
        for key, value in payload.items():
            yield {"key": key, "value": value}


def missing_required_keys(required: list[str], values: dict[str, str]) -> list[str]:
    return [key for key in required if not values.get(key)]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", type=Path, default=Path("compose.coolify.yaml"))
    parser.add_argument("--api-base-url", required=True)
    parser.add_argument("--app-uuid", required=True)
    parser.add_argument(
        "--token-env",
        default="COOLIFY_API_TOKEN",
        help="environment variable that contains the Coolify API token",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.environ.get(args.token_env)
    if not token:
        raise SystemExit(f"{args.token_env} is not configured")
    required = required_env_keys(args.compose)
    values = collect_env_values(fetch_coolify_envs(args.api_base_url, args.app_uuid, token))
    missing = missing_required_keys(required, values)
    if missing:
        print("Coolify app is missing required hosted Registry Lab env vars:", file=sys.stderr)
        for key in missing:
            print(f"- {key}", file=sys.stderr)
        return 1
    print(f"Coolify app has all {len(required)} required hosted Registry Lab env vars.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
