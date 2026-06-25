#!/usr/bin/env python3
"""Shared helpers for agriculture demo consumer scripts."""

from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv_util import load_dotenv_file


DEMO_ROOT = Path(__file__).resolve().parents[1]
PURPOSE = "https://demo.example.gov/purpose/nagdi/climate-smart-input-support"
MARKET_PURPOSE = "https://demo.example.gov/purpose/nagdi/agricultural-market-sizing"
LIVESTOCK_PURPOSE = "https://demo.example.gov/purpose/nagdi/livestock-movement-permit-review"
CLAIM_RESULT_FORMAT = "application/vnd.registry-notary.claim-result+json"
SD_JWT_FORMAT = "application/dc+sd-jwt"
DEFAULT_CORRELATION_ID = "nagdi-agri-demo-correlation-001"


class DemoError(RuntimeError):
    pass


@dataclass
class HttpResult:
    status: int
    body: Any
    headers: dict[str, str]


def load_dotenv(path: Path = DEMO_ROOT / ".env") -> None:
    load_dotenv_file(path)


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise DemoError(f"missing required environment variable: {name}")
    return value


def prepare_output_dir(path: Path) -> Path:
    if path.exists():
        for child in path.iterdir():
            if child.name == ".gitignore":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    path.mkdir(parents=True, exist_ok=True)
    return path


def parse_body(raw: bytes) -> Any:
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def request(
    method: str,
    base_url: str,
    path: str,
    token: str | None = None,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> HttpResult:
    req_headers = {
        "Accept": "*/*",
        "x-request-id": os.environ.get("DEMO_CORRELATION_ID", DEFAULT_CORRELATION_ID),
    }
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HttpResult(resp.status, parse_body(resp.read()), dict(resp.headers))
    except urllib.error.HTTPError as exc:
        return HttpResult(exc.code, parse_body(exc.read()), dict(exc.headers))
    except urllib.error.URLError as exc:
        raise DemoError(f"{method} {url} failed: {exc}") from exc


def require(result: HttpResult, expected: int, label: str) -> Any:
    if result.status != expected:
        raise DemoError(f"{label} returned HTTP {result.status}, expected {expected}: {result.body}")
    return result.body


def require_denial(result: HttpResult, label: str) -> None:
    if result.status not in {400, 403, 422}:
        raise DemoError(f"{label} expected denial HTTP 400/403/422, got {result.status}: {result.body}")


def save_json(path: Path, payload: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def first_result(evaluation: dict[str, Any]) -> dict[str, Any]:
    results = evaluation.get("results") or evaluation.get("claim_results") or []
    if not results or not isinstance(results[0], dict):
        raise DemoError(f"evaluation response has no result object: {evaluation}")
    return results[0]


def outcome(evaluation: dict[str, Any]) -> Any:
    result = first_result(evaluation)
    for key in ("value", "satisfied", "outcome", "decision", "verified", "result", "status"):
        if key in result:
            return result[key]
    return None


def first_result_id(evaluation: dict[str, Any]) -> str:
    evaluation_id = first_result(evaluation).get("evaluation_id")
    if not evaluation_id:
        raise DemoError(f"evaluation response has no evaluation_id: {evaluation}")
    return str(evaluation_id)


def evaluation_payload(
    subject: str,
    claim: str,
    disclosure: str = "predicate",
    fmt: str = CLAIM_RESULT_FORMAT,
    id_type: str = "farmer_id",
) -> dict[str, Any]:
    target_type = "Herd" if id_type == "herd_id" else "Farmer"
    return {
        "target": {
            "type": target_type,
            "identifiers": [{"scheme": id_type, "value": subject}],
        },
        "claims": [claim],
        "disclosure": disclosure,
        "format": fmt,
    }


def assert_no_secret_values(output_dir: Path) -> None:
    secret_values = [
        value
        for key, value in os.environ.items()
        if key.startswith("AGRI_")
        and key.endswith(("_RAW", "_TOKEN", "_BEARER", "_HASH"))
        and value
        and len(value) >= 16
    ]
    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for value in secret_values:
            if value in text:
                raise DemoError(f"artifact {path} contains a raw agriculture secret value")
