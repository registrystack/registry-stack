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


def request_source(
    method: str,
    url: str,
    headers: dict[str, str],
    body: Any | None = None,
    *,
    internal: bool = False,
    target_input_selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source: dict[str, Any] = {"method": method, "url": url, "headers": headers}
    if body is not None:
        source["body"] = body
    if internal:
        source["internal"] = True
    if target_input_selection is not None:
        source["target_input_selection"] = target_input_selection
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


def claim_catalog_items(body: Any) -> list[Any]:
    if not isinstance(body, dict):
        return []
    claims = body.get("claims")
    if isinstance(claims, list):
        return claims
    data = body.get("data")
    if isinstance(data, list):
        return data
    claim_service = body.get("claim_service")
    if isinstance(claim_service, dict) and isinstance(claim_service.get("claims"), list):
        return claim_service["claims"]
    service = body.get("service")
    if isinstance(service, dict) and isinstance(service.get("claims"), list):
        return service["claims"]
    return []


def claims_catalog(body: Any) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for item in claim_catalog_items(body):
        if isinstance(item, dict):
            claims.append(item)
        elif isinstance(item, str):
            claims.append({"id": item})
    return claims


def target_input_facts(body: Any, claim_ids: list[str] | tuple[str, ...] = ()) -> list[dict[str, Any]]:
    methods = _target_input_methods(claims_catalog(body), list(claim_ids))
    if not methods:
        return [{"label": "Target inputs", "value": "Legacy identifier fallback"}]
    return [
        {"label": "Target inputs", "value": _target_input_options_label(methods)},
        {"label": "Input metadata", "value": "Published by Notary claim discovery"},
    ]


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


def person_profile(
    identifier: str,
    *,
    id_scheme: str = "national_id",
    attributes: dict[str, Any] | None = None,
    target_type: str = "Person",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "target_type": target_type,
        "identifiers": {id_scheme: identifier} if identifier else {},
        "attributes": attributes or {},
    }


def evaluation_body_from_claim_metadata(
    claims_body: Any,
    profile: dict[str, Any],
    claim_ids: list[str] | tuple[str, ...],
    *,
    disclosure: str = "predicate",
    fmt: str = CLAIM_RESULT_FORMAT,
) -> tuple[dict[str, Any], dict[str, Any]]:
    claim_id_list = list(claim_ids)
    target, selection = target_from_claim_metadata(claims_body, profile, claim_id_list)
    return {
        "target": target,
        "claims": claim_id_list,
        "disclosure": disclosure,
        "format": fmt,
    }, selection


def target_from_claim_metadata(
    claims_body: Any,
    profile: dict[str, Any],
    claim_ids: list[str] | tuple[str, ...],
) -> tuple[dict[str, Any], dict[str, Any]]:
    methods = _target_input_methods(claims_catalog(claims_body), list(claim_ids))
    for method in methods:
        for group in method.get("groups", []):
            target = _target_from_input_group(group, profile, method.get("target_type"))
            if target is not None:
                return target, {
                    "source": "target_inputs",
                    "method": method.get("method", ""),
                    "target_type": method.get("target_type") or profile.get("target_type") or "Person",
                    "claim_ids": list(claim_ids),
                    "group": _input_group_label(group),
                    "inputs": group.get("inputs", []),
                }
    target = _identifier_fallback_target(profile)
    return target, {
        "source": "identifier_fallback",
        "target_type": target.get("type", "Person"),
        "claim_ids": list(claim_ids),
        "group": _identifier_fallback_label(target),
        "inputs": [],
    }


def _target_input_methods(claims: list[dict[str, Any]], claim_ids: list[str]) -> list[dict[str, Any]]:
    selected_ids = set(claim_ids)
    methods: list[dict[str, Any]] = []
    for claim in claims:
        if selected_ids and claim.get("id") not in selected_ids:
            continue
        target_inputs = claim.get("target_inputs", [])
        if isinstance(target_inputs, list):
            methods.extend(item for item in target_inputs if isinstance(item, dict))
    return methods


def _target_from_input_group(group: dict[str, Any], profile: dict[str, Any], target_type: Any) -> dict[str, Any] | None:
    inputs = group.get("inputs", [])
    if not isinstance(inputs, list) or not inputs:
        return None
    target: dict[str, Any] = {"type": str(target_type or profile.get("target_type") or "Person")}
    identifiers: list[dict[str, Any]] = []
    attributes: dict[str, Any] = {}
    for input_meta in inputs:
        if not isinstance(input_meta, dict):
            return None
        value = _profile_value_for_input(profile, input_meta)
        if value in (None, ""):
            return None
        kind = input_meta.get("kind")
        name = str(input_meta.get("name") or "")
        if kind == "id":
            target["id"] = value
        elif kind == "identifier" and name:
            identifiers.append({"scheme": name, "value": value})
        elif kind == "attribute" and name:
            attributes[name] = value
        else:
            return None
    if identifiers:
        target["identifiers"] = identifiers
    if attributes:
        target["attributes"] = attributes
    return target


def _profile_value_for_input(profile: dict[str, Any], input_meta: dict[str, Any]) -> Any:
    kind = input_meta.get("kind")
    name = str(input_meta.get("name") or "")
    if kind == "id":
        return profile.get("id")
    if kind == "identifier":
        identifiers = profile.get("identifiers", {})
        return identifiers.get(name) if isinstance(identifiers, dict) else None
    if kind == "attribute":
        attributes = profile.get("attributes", {})
        return attributes.get(name) if isinstance(attributes, dict) else None
    return None


def _identifier_fallback_target(profile: dict[str, Any]) -> dict[str, Any]:
    identifiers = profile.get("identifiers", {})
    if isinstance(identifiers, dict) and identifiers:
        scheme, value = next(iter(identifiers.items()))
        return {
            "type": str(profile.get("target_type") or "Person"),
            "identifiers": [{"scheme": scheme, "value": value}],
        }
    return {"type": str(profile.get("target_type") or "Person"), "id": profile.get("id", "")}


def _identifier_fallback_label(target: dict[str, Any]) -> str:
    identifiers = target.get("identifiers", [])
    if identifiers and isinstance(identifiers, list) and isinstance(identifiers[0], dict):
        return _label_from_name(str(identifiers[0].get("scheme") or "identifier"))
    return "ID"


def _target_input_options_label(methods: list[dict[str, Any]]) -> str:
    labels: list[str] = []
    for method in methods:
        groups = method.get("groups", [])
        if not isinstance(groups, list):
            continue
        for group in groups:
            if isinstance(group, dict):
                label = _input_group_label(group)
                if label and label not in labels:
                    labels.append(label)
    return " OR ".join(labels) if labels else "Legacy identifier fallback"


def _input_group_label(group: dict[str, Any]) -> str:
    inputs = group.get("inputs", [])
    if not isinstance(inputs, list):
        return ""
    labels = []
    for input_meta in inputs:
        if not isinstance(input_meta, dict):
            continue
        labels.append(str(input_meta.get("label") or _label_from_name(str(input_meta.get("name") or ""))))
    return " + ".join(label for label in labels if label)


def _label_from_name(name: str) -> str:
    parts = [part for part in name.split("_") if part]
    if not parts:
        return name
    return " ".join([parts[0].capitalize(), *parts[1:]])


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
