#!/usr/bin/env python3
"""Shared helpers for Registry Lab guided scenarios."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin


PURPOSE = "https://demo.example.gov/purpose/decentralized-evidence-demo"
AGRI_PURPOSE = "https://demo.example.gov/purpose/nagdi/climate-smart-input-support"
CLAIM_RESULT_FORMAT = "application/vnd.registry-notary.claim-result+json"


@dataclass
class StepHttpResult:
    status: int | None
    body: Any
    headers: dict[str, str]
    error: str = ""


def credential_by_id(config: dict[str, Any], credential_id: str) -> dict[str, Any]:
    for credential in config.get("credentials", []):
        if credential.get("id") == credential_id:
            return credential
    return {}


def configured_credential(config: dict[str, Any], credential_id: str) -> dict[str, Any]:
    credential = dict(credential_by_id(config, credential_id))
    credential["display_policy"] = "public"
    return credential


def runtime_bearer_credential(credential_id: str, env_name: str) -> dict[str, Any]:
    return {
        "id": credential_id,
        "env": env_name,
        "token": os.environ.get(env_name, ""),
        "auth_scheme": "bearer",
        "display_policy": "runtime-hidden",
    }


def auth_header_pair(credential: dict[str, Any]) -> tuple[str, str]:
    token = credential.get("token", "")
    if credential.get("auth_scheme") == "api_key":
        return "X-Api-Key", token
    return "Authorization", f"Bearer {token}"


def display_auth_header_pair(credential: dict[str, Any]) -> tuple[str, str]:
    name, value = auth_header_pair(credential)
    if credential.get("display_policy") == "runtime-hidden":
        if credential.get("token"):
            return name, "Bearer [runtime demo token hidden]"
        return name, "Bearer [runtime demo token missing]"
    return name, value


def service_url(config: dict[str, Any], credential_id: str, path: str) -> str:
    credential = credential_by_id(config, credential_id)
    return joined_url(str(credential.get("service_url", "")), path)


def joined_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def env_url(env_name: str, default: str, path: str) -> str:
    return joined_url(os.environ.get(env_name, default), path)


def request_source(method: str, url: str, headers: dict[str, str], body: Any | None = None, *, internal: bool = False) -> dict[str, Any]:
    source: dict[str, Any] = {"method": method, "url": url, "headers": headers}
    if body is not None:
        source["body"] = body
    if internal:
        source["internal"] = True
    return source


def simulated_request_source(operation: str, body: Any | None = None) -> dict[str, Any]:
    source: dict[str, Any] = {
        "method": "SIMULATE",
        "url": operation,
        "headers": {},
    }
    if body is not None:
        source["body"] = body
    return source


def http_json(method: str, url: str, headers: dict[str, str], body: Any | None = None, timeout: float = 8.0) -> StepHttpResult:
    data = None
    request_headers = dict(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, headers=request_headers, data=data, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return StepHttpResult(
                status=response.status,
                body=parse_body(raw),
                headers={key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as error:
        raw = error.read()
        return StepHttpResult(
            status=error.code,
            body=parse_body(raw),
            headers={key.lower(): value for key, value in error.headers.items()},
        )
    except Exception as error:  # noqa: BLE001
        return StepHttpResult(status=None, body={}, headers={}, error=error.__class__.__name__)


def parse_body(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw.decode("utf-8", errors="replace")


def source_response(result: StepHttpResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "headers": {
            key: value
            for key, value in result.headers.items()
            if key in {"content-type", "link", "www-authenticate"}
        },
        "body": result.body,
        "error": result.error,
    }


def simulated_response(body: Any) -> dict[str, Any]:
    return {
        "status": "simulated",
        "headers": {},
        "body": body,
        "error": "",
    }


def ok_status(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def result_item(body: Any, claim_id: str | None = None) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    results = body.get("results") or body.get("claim_results") or []
    if not isinstance(results, list):
        return {}
    for item in results:
        if not isinstance(item, dict):
            continue
        if claim_id is None or item.get("claim_id") == claim_id or item.get("claim") == claim_id:
            return item
    return results[0] if results and isinstance(results[0], dict) else {}


def observed_answer(item: dict[str, Any]) -> Any:
    if "satisfied" in item:
        return item.get("satisfied")
    return item.get("value")


def attestation_response(
    public_attestation: dict[str, Any],
    *,
    subject_type: str,
    subject_id: str,
    lookup_profile: str,
    claim_id: str,
    claim_value: Any,
    match_method: str = "identifier_exact",
    valid_until: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    claims: list[dict[str, Any]] = [{"id": claim_id}]
    if isinstance(claim_value, bool):
        claims[0]["satisfied"] = claim_value
    elif claim_value is not None:
        claims[0]["value"] = claim_value
    envelope = {
        "attestation_id": public_attestation["offering_id"],
        "display_name": public_attestation["display_name"],
        "source_authority": public_attestation["source_authority"],
        "jurisdiction": public_attestation["jurisdiction"],
        "publicschema_anchor": public_attestation["publicschema_anchor"],
        "subject": {"type": subject_type, "identifier": subject_id},
        "match_method": match_method,
        "matched_record_ref": "available in minimized Notary response or source provenance",
        "as_of": now,
        "source_observed_at": now,
        "disclosure_profile": public_attestation["disclosure_profile"],
        "claims": claims,
        "proof": {
            "type": "registry-notary-evaluation-response",
            "status": "linked_raw_response",
            "source": "response_source.http.body",
        },
    }
    if valid_until:
        envelope["valid_until"] = valid_until
    return envelope


def evaluation_body(subject: str, claim_id: str, id_scheme: str = "national_id", disclosure: str = "predicate") -> dict[str, Any]:
    return {
        "target": {"type": "Person", "identifiers": [{"scheme": id_scheme, "value": subject}]},
        "claims": [claim_id],
        "disclosure": disclosure,
        "format": CLAIM_RESULT_FORMAT,
    }


def friendly_unavailable(service_name: str, env_name: str, url: str) -> dict[str, Any]:
    return {
        "title": f"{service_name} is local-only in this lab.",
        "message": (
            f"This scenario can run when the local service is started and {env_name} is set. "
            "The UI keeps the story visible so users understand the flow before they start the local profile."
        ),
        "status": "needs_attention",
        "facts": [
            {"label": "Endpoint", "value": url},
            {"label": "Required token env", "value": env_name},
            {"label": "Availability", "value": "Local-only"},
        ],
    }


def standard_error_result(step_id: str) -> dict[str, Any]:
    return {
        "step_id": step_id,
        "friendly": {
            "title": "Unknown step.",
            "message": "This scenario step is not configured.",
            "status": "needs_attention",
            "facts": [],
        },
        "request_source": {},
        "response_source": {},
    }
