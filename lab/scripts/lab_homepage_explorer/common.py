#!/usr/bin/env python3
"""Shared helpers for the Registry Lab explorer APIs."""

from __future__ import annotations

import ipaddress
import json
import os
import shlex
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin


PURPOSE = "https://demo.example.gov/purpose/decentralized-evidence-demo"
CLAIM_RESULT_FORMAT = "application/vnd.registry-notary.claim-result+json"
EXPLORER_MAX_LIMIT = 10
RUNTIME_TOKEN_HIDDEN = "[runtime demo token hidden]"
RUNTIME_TOKEN_MISSING = "[runtime demo token missing]"
EXPLORER_ALLOWED_HOST_SUFFIXES = (".lab.registrystack.org", ".example")
EXPLORER_ALLOWED_HOSTS = {"lab.registrystack.org", "example"}
EXPLORER_INTERNAL_RUNTIME_HOSTS = {
    "localhost",
    "host.docker.internal",
    "civil-notary",
    "shared-eligibility-notary",
    "nagdi-agriculture-notary",
    "agriculture-notary",
}


@dataclass(frozen=True)
class ExplorerHttpResult:
    status: int | None
    body: Any
    headers: dict[str, str]
    error: str = ""


class ExplorerInputError(ValueError):
    """Controlled validation error safe to return as JSON."""

    def __init__(self, code: str, message: str, *, field: str = "", allowed: list[Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field
        self.allowed = allowed or []

    def payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": False,
            "error": {
                "code": self.code,
                "message": self.message,
            },
        }
        if self.field:
            payload["error"]["field"] = self.field
        if self.allowed:
            payload["error"]["allowed"] = self.allowed
        return payload


def error_payload(code: str, message: str, *, field: str = "", allowed: list[Any] | None = None) -> dict[str, Any]:
    return ExplorerInputError(code, message, field=field, allowed=allowed).payload()


def unknown_id_error(kind: str, requested_id: str, allowed_ids: list[str]) -> dict[str, Any]:
    safe_requested = requested_id if requested_id in allowed_ids else ""
    message = f"Unknown {kind} id."
    if safe_requested:
        message = f"Unknown {kind} id: {safe_requested}."
    return error_payload(f"explorer.unknown_{kind}", message, field=f"{kind}_id", allowed=allowed_ids)


def credential_by_id(config: dict[str, Any], credential_id: str) -> dict[str, Any]:
    for credential in config.get("credentials", []):
        if credential.get("id") == credential_id:
            return credential
    return {}


def public_credential_ids(config: dict[str, Any]) -> set[str]:
    return {credential.get("id", "") for credential in config.get("credentials", []) if credential.get("id")}


def auth_header_pair(credential: dict[str, Any], token: str | None = None) -> tuple[str, str]:
    value = credential.get("token", "") if token is None else token
    if credential.get("auth_scheme") == "api_key":
        return "X-Api-Key", value
    return "Authorization", f"Bearer {value}"


def runtime_bearer_credential(credential_id: str, env_name: str) -> dict[str, Any]:
    return {
        "id": credential_id,
        "token": os.environ.get(env_name, ""),
        "auth_scheme": "bearer",
        "display_policy": "runtime-hidden",
    }


def credential_display(config: dict[str, Any], credential_id: str, *, runtime_env: str = "") -> dict[str, Any]:
    """Return a credential summary safe for public explorer payloads."""
    credential = dict(credential_by_id(config, credential_id))
    if credential:
        token = str(credential.get("token", ""))
        display_policy = "public"
    elif runtime_env:
        credential = runtime_bearer_credential(credential_id, runtime_env)
        token = str(credential.get("token", ""))
        display_policy = "runtime-hidden"
    else:
        token = ""
        display_policy = "missing"

    if display_policy == "runtime-hidden":
        display_value = RUNTIME_TOKEN_HIDDEN if token else RUNTIME_TOKEN_MISSING
    else:
        display_value = token

    header_name, header_value = auth_header_pair(credential, display_value)
    return {
        "id": credential_id,
        "label": credential.get("label", credential_id),
        "configured": bool(token),
        "display_policy": display_policy,
        "auth_header": {"name": header_name, "value": header_value},
        "scopes": list(credential.get("scopes", [])),
    }


def credential_for_execution(config: dict[str, Any], credential_id: str, *, runtime_env: str = "") -> dict[str, Any]:
    credential = dict(credential_by_id(config, credential_id))
    if credential:
        credential["display_policy"] = "public"
        return credential
    if runtime_env:
        return runtime_bearer_credential(credential_id, runtime_env)
    return {"id": credential_id, "token": "", "auth_scheme": "bearer", "display_policy": "missing"}


def display_auth_header_pair(credential: dict[str, Any]) -> tuple[str, str]:
    token = str(credential.get("token", ""))
    if credential.get("display_policy") == "runtime-hidden":
        display_token = RUNTIME_TOKEN_HIDDEN if token else RUNTIME_TOKEN_MISSING
    else:
        display_token = token
    return auth_header_pair(credential, display_token)


def joined_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def service_url(config: dict[str, Any], credential_id: str, path: str, *, fallback_base_url: str = "") -> str:
    credential = credential_by_id(config, credential_id)
    base_url = str(credential.get("service_url", fallback_base_url))
    return joined_url(base_url, path)


def env_url(env_name: str, default: str, path: str) -> str:
    return joined_url(os.environ.get(env_name, default), path)


def request_source(method: str, url: str, headers: dict[str, str], body: Any | None = None) -> dict[str, Any]:
    source: dict[str, Any] = {"method": method, "url": url, "headers": headers}
    if body is not None:
        source["body"] = body
    return source


def source_response(result: ExplorerHttpResult) -> dict[str, Any]:
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


def _is_explorer_allowlisted_host(host: str) -> bool:
    return host in EXPLORER_ALLOWED_HOSTS or any(host.endswith(suffix) for suffix in EXPLORER_ALLOWED_HOST_SUFFIXES)


def validate_explorer_outbound_url(url: str, *, allow_internal_runtime: bool = False) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.username or parsed.password:
        raise ExplorerInputError("explorer.blocked_url", "Explorer request URLs must not include credentials.", field="url")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ExplorerInputError("explorer.blocked_url", "Explorer request URLs must include a host.", field="url")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    explorer_host_allowed = address is None and _is_explorer_allowlisted_host(host)
    internal_runtime_allowed = allow_internal_runtime and (
        (address is not None and address.is_loopback) or host in EXPLORER_INTERNAL_RUNTIME_HOSTS
    )
    if parsed.scheme == "https":
        if explorer_host_allowed or internal_runtime_allowed:
            return
    elif parsed.scheme == "http":
        if internal_runtime_allowed:
            return
        if allow_internal_runtime:
            raise ExplorerInputError(
                "explorer.blocked_url",
                "Explorer HTTP runtime URLs must target an allowed internal runtime host.",
                field="url",
            )
        raise ExplorerInputError("explorer.blocked_url", "Explorer requests must use HTTPS.", field="url")
    else:
        message = "Explorer requests must use HTTPS."
        if allow_internal_runtime:
            message = "Explorer request URLs must use HTTPS or an allowed internal runtime HTTP URL."
        raise ExplorerInputError("explorer.blocked_url", message, field="url")

    if address is not None:
        raise ExplorerInputError("explorer.blocked_url", "Explorer request URLs must use allowlisted hostnames.", field="url")
    raise ExplorerInputError("explorer.blocked_url", "Explorer request URLs must target an allowlisted host.", field="url")


def safe_curl(method: str, url: str, headers: dict[str, str], body: Any | None = None) -> str:
    pieces = ["curl", "-fsS", "-X", method.upper(), shlex.quote(url)]
    for name, value in headers.items():
        pieces.extend(["-H", shlex.quote(f"{name}: {value}")])
    if body is not None:
        pieces.extend(["--data", shlex.quote(json.dumps(body, separators=(",", ":"), sort_keys=True))])
    return " ".join(pieces)


def http_json(
    method: str,
    url: str,
    headers: dict[str, str],
    body: Any | None = None,
    timeout: float = 8.0,
    *,
    allow_internal_runtime: bool = False,
) -> ExplorerHttpResult:
    data = None
    request_headers = dict(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    try:
        validate_explorer_outbound_url(url, allow_internal_runtime=allow_internal_runtime)
        # URL is constrained to an allowlisted HTTPS host or explicit internal runtime target above.
        # codeql[py/full-ssrf]
        request = urllib.request.Request(url, headers=request_headers, data=data, method=method)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return ExplorerHttpResult(
                status=response.status,
                body=parse_body(response.read()),
                headers={key.lower(): value for key, value in response.headers.items()},
            )
    except ExplorerInputError as error:
        return ExplorerHttpResult(status=None, body={}, headers={}, error=error.code)
    except urllib.error.HTTPError as error:
        return ExplorerHttpResult(
            status=error.code,
            body=parse_body(error.read()),
            headers={key.lower(): value for key, value in error.headers.items()},
        )
    except Exception as error:  # noqa: BLE001
        return ExplorerHttpResult(status=None, body={}, headers={}, error=error.__class__.__name__)


def parse_body(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw.decode("utf-8", errors="replace")


def validate_limit(raw_limit: Any, *, default: int = 1, max_limit: int = EXPLORER_MAX_LIMIT) -> int:
    if raw_limit in (None, ""):
        return default
    try:
        limit = int(str(raw_limit), 10)
    except (TypeError, ValueError) as error:
        raise ExplorerInputError("explorer.invalid_limit", "Limit must be an integer.", field="limit") from error
    if limit < 0:
        raise ExplorerInputError("explorer.invalid_limit", "Limit must not be negative.", field="limit")
    if limit > max_limit:
        raise ExplorerInputError(
            "explorer.invalid_limit",
            f"Limit must be less than or equal to {max_limit}.",
            field="limit",
        )
    return limit


def parse_filter_params(params: dict[str, list[str]]) -> list[dict[str, str]]:
    filters: list[dict[str, str]] = []
    for key, values in params.items():
        if not key.startswith("filter."):
            continue
        field = key.removeprefix("filter.")
        if not field:
            raise ExplorerInputError("explorer.invalid_filter", "Filter field is required.", field="filter")
        op = "eq"
        if "." in field:
            field, op = field.rsplit(".", 1)
        value = values[0] if values else ""
        filters.append({"field": field, "op": op, "value": value})
    return filters


def validate_filters(filters: list[dict[str, str]], allowed_filters: dict[str, list[str]]) -> list[dict[str, str]]:
    validated = []
    for item in filters:
        field = item.get("field", "")
        op = item.get("op", "eq")
        if field not in allowed_filters:
            raise ExplorerInputError(
                "explorer.unsupported_filter_field",
                "This filter field is not supported for the selected entity.",
                field="filter",
                allowed=sorted(allowed_filters),
            )
        if op not in allowed_filters[field]:
            raise ExplorerInputError(
                "explorer.unsupported_filter_operator",
                "This filter operator is not supported for the selected field.",
                field=f"filter.{field}",
                allowed=allowed_filters[field],
            )
        validated.append({"field": field, "op": op, "value": str(item.get("value", ""))})
    return validated


def filters_to_query(filters: list[dict[str, str]]) -> str:
    pairs = []
    for item in filters:
        suffix = "" if item["op"] == "eq" else f".{item['op']}"
        pairs.append((f"filter.{item['field']}{suffix}", item["value"]))
    return urllib.parse.urlencode(pairs)


def require_keys(body: dict[str, Any], allowed_keys: set[str]) -> None:
    unexpected = sorted(set(body) - allowed_keys)
    if unexpected:
        raise ExplorerInputError(
            "explorer.unexpected_request_key",
            "Request contains unsupported keys.",
            field=unexpected[0],
            allowed=sorted(allowed_keys),
        )
