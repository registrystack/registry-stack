#!/usr/bin/env python3
"""Server-side discovery for Registry Lab explorer catalogs."""

from __future__ import annotations

from copy import deepcopy
import json
import time
from typing import Any, Callable
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .common import (
    ExplorerHttpResult,
    ExplorerInputError,
    auth_header_pair,
    credential_for_execution,
    joined_url,
    validate_explorer_outbound_url,
)


DISCOVERY_TTL_SECONDS = 60.0
DISCOVERY_MAX_BYTES = 1_000_000
HTTP_JSON: Callable[..., ExplorerHttpResult]
_CACHE: dict[tuple[Any, ...], tuple[float, Any]] = {}


class DiscoveryUnavailable(RuntimeError):
    """Discovery failed in a way safe to collapse back to the lab overlay."""

    def __init__(self, message: str, *, code: str = "unavailable", status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def clear_discovery_cache() -> None:
    _CACHE.clear()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        return None


def discovery_http_json(method: str, url: str, headers: dict[str, str], body: Any | None = None, timeout: float = 6.0) -> ExplorerHttpResult:
    if body is not None:
        return ExplorerHttpResult(status=None, body={}, headers={}, error="DiscoveryBodyNotSupported")
    try:
        validate_explorer_outbound_url(url)
        request = urllib.request.Request(url, headers=dict(headers), method=method)
        opener = urllib.request.build_opener(_NoRedirectHandler)
        with opener.open(request, timeout=timeout) as response:
            raw = _read_bounded(response)
            if raw is None:
                return ExplorerHttpResult(status=None, body={}, headers={}, error="DiscoveryResponseTooLarge")
            return ExplorerHttpResult(
                status=response.status,
                body=_parse_body(raw),
                headers={key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as error:
        raw = _read_bounded(error)
        return ExplorerHttpResult(
            status=error.code,
            body=_parse_body(raw or b""),
            headers={key.lower(): value for key, value in error.headers.items()},
        )
    except ExplorerInputError as error:
        return ExplorerHttpResult(status=None, body={}, headers={}, error=error.code)
    except Exception as error:  # noqa: BLE001
        return ExplorerHttpResult(status=None, body={}, headers={}, error=error.__class__.__name__)


HTTP_JSON = discovery_http_json


def discover_relay_registries(
    config: dict[str, Any],
    overlays: dict[str, dict[str, Any]],
    order: list[str],
    *,
    ttl_seconds: float = DISCOVERY_TTL_SECONDS,
) -> dict[str, dict[str, Any]]:
    cache_key = _cache_key("relay", config, [overlays[item] for item in order if item in overlays])
    cached = _cached(cache_key, ttl_seconds)
    if cached is not None:
        return deepcopy(cached)
    registries = {
        registry_id: _discover_relay_registry(config, overlays[registry_id])
        for registry_id in order
        if registry_id in overlays
    }
    _CACHE[cache_key] = (time.monotonic(), deepcopy(registries))
    return registries


def discover_claim_services(
    config: dict[str, Any],
    overlays: dict[str, dict[str, Any]],
    order: list[str],
    *,
    ttl_seconds: float = DISCOVERY_TTL_SECONDS,
) -> dict[str, dict[str, Any]]:
    cache_key = _cache_key("claims", config, [overlays[item] for item in order if item in overlays])
    cached = _cached(cache_key, ttl_seconds)
    if cached is not None:
        return deepcopy(cached)
    services = {
        service_id: _discover_claim_service(config, overlays[service_id])
        for service_id in order
        if service_id in overlays
    }
    _CACHE[cache_key] = (time.monotonic(), deepcopy(services))
    return services


def _cached(cache_key: tuple[Any, ...], ttl_seconds: float) -> Any | None:
    cached = _CACHE.get(cache_key)
    if not cached:
        return None
    created_at, value = cached
    if time.monotonic() - created_at > ttl_seconds:
        _CACHE.pop(cache_key, None)
        return None
    return deepcopy(value)


def _cache_key(kind: str, config: dict[str, Any], overlays: list[dict[str, Any]]) -> tuple[Any, ...]:
    credentials = {
        credential.get("id", ""): credential
        for credential in config.get("credentials", [])
        if isinstance(credential, dict) and credential.get("id")
    }
    items = []
    for overlay in overlays:
        credential_id = overlay.get("metadata_credential_id") or overlay.get("client_credential_id") or ""
        credential = credentials.get(credential_id, {})
        items.append(
            (
                overlay.get("id", ""),
                overlay.get("base_url", ""),
                credential.get("service_url", ""),
                bool(credential.get("token")),
            )
        )
    return (kind, tuple(items))


def _discover_relay_registry(config: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    registry = deepcopy(overlay)
    try:
        credential_id = str(registry.get("metadata_credential_id", ""))
        datasets_body = _discovery_get(config, credential_id, registry.get("base_url", ""), "/v1/datasets")
        discovered_datasets = _relay_datasets(datasets_body)
        if not discovered_datasets:
            raise DiscoveryUnavailable("Relay did not return datasets.", code="empty_catalog")
        registry["datasets"] = _merge_relay_datasets(config, registry, discovered_datasets)
        _normalize_registry_defaults(registry)
        registry["discovery"] = {"status": "live", "source": "relay"}
    except DiscoveryUnavailable as error:
        registry["discovery"] = _unavailable_discovery("Relay discovery unavailable.", error)
    return registry


def _merge_relay_datasets(
    config: dict[str, Any],
    registry: dict[str, Any],
    discovered_datasets: list[dict[str, Any]],
) -> dict[str, Any]:
    credential_id = str(registry.get("metadata_credential_id", ""))
    fallback_datasets = registry.get("datasets", {})
    merged: dict[str, Any] = {}
    for dataset_summary in discovered_datasets:
        dataset_id = str(dataset_summary.get("id", "")).strip()
        if not dataset_id:
            continue
        fallback_dataset = fallback_datasets.get(dataset_id, {})
        dataset = {
            "id": dataset_id,
            "title": str(dataset_summary.get("title") or dataset_summary.get("label") or fallback_dataset.get("title") or _titleize(dataset_id)),
            "entities": {},
            "aggregates": {},
        }
        entity_summaries = _relay_entities(dataset_summary) or _entity_summaries_from_fallback(fallback_dataset)
        for entity_summary in entity_summaries:
            entity_id = str(entity_summary.get("id", "")).strip()
            if not entity_id:
                continue
            fallback_entity = fallback_dataset.get("entities", {}).get(entity_id, {})
            discovered_entity = {
                "id": entity_id,
                "title": str(entity_summary.get("title") or entity_summary.get("label") or fallback_entity.get("title") or _titleize(entity_id)),
                "fields": _discover_relay_fields(config, credential_id, registry.get("base_url", ""), dataset_id, entity_id, fallback_entity),
            }
            dataset["entities"][entity_id] = discovered_entity
        dataset["aggregates"] = _discover_relay_aggregates(config, credential_id, registry.get("base_url", ""), dataset_id, fallback_dataset)
        merged[dataset_id] = dataset
    return merged or deepcopy(fallback_datasets)


def _discover_relay_fields(
    config: dict[str, Any],
    credential_id: str,
    base_url: str,
    dataset_id: str,
    entity_id: str,
    fallback_entity: dict[str, Any],
) -> list[dict[str, Any]]:
    try:
        body = _discovery_get(config, credential_id, base_url, f"/v1/datasets/{dataset_id}/entities/{entity_id}/schema")
        fields = _relay_fields(body)
    except DiscoveryUnavailable:
        fields = []
    if not fields:
        return deepcopy(fallback_entity.get("fields", []))
    fallback_fields = {
        field.get("name", ""): field
        for field in fallback_entity.get("fields", [])
        if isinstance(field, dict) and field.get("name")
    }
    merged = []
    for field in fields:
        name = str(field.get("name", "")).strip()
        if not name:
            continue
        fallback = fallback_fields.get(name, {})
        item = {
            "name": name,
            "type": str(field.get("type") or fallback.get("type") or "string"),
            "filter_ops": list(fallback.get("filter_ops", [])),
            "sensitive": bool(fallback.get("sensitive", False)),
        }
        merged.append(item)
    return merged


def _discover_relay_aggregates(
    config: dict[str, Any],
    credential_id: str,
    base_url: str,
    dataset_id: str,
    fallback_dataset: dict[str, Any],
) -> dict[str, Any]:
    try:
        body = _discovery_get(config, credential_id, base_url, f"/v1/datasets/{dataset_id}/aggregates")
        aggregates = _relay_aggregates(body)
    except DiscoveryUnavailable:
        aggregates = []
    fallback_aggregates = fallback_dataset.get("aggregates", {})
    if not aggregates:
        return deepcopy(fallback_aggregates)
    merged = {}
    for aggregate in aggregates:
        aggregate_id = str(aggregate.get("id", "")).strip()
        if not aggregate_id:
            continue
        fallback = fallback_aggregates.get(aggregate_id, {})
        item = {
            **deepcopy(fallback),
            "id": aggregate_id,
            "title": str(aggregate.get("title") or aggregate.get("label") or fallback.get("title") or _titleize(aggregate_id)),
        }
        for key in ("dimensions", "measures", "fields", "description"):
            if key in aggregate:
                item[key] = deepcopy(aggregate[key])
        merged[aggregate_id] = item
    return merged


def _discover_claim_service(config: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    service = deepcopy(overlay)
    try:
        credential_id = str(service.get("client_credential_id", ""))
        runtime_env = str(service.get("runtime_token_env", ""))
        _discovery_get(config, credential_id, service.get("base_url", ""), "/.well-known/evidence-service", runtime_env=runtime_env)
        claims_body = _discovery_get(config, credential_id, service.get("base_url", ""), "/v1/claims", runtime_env=runtime_env)
        discovered_claims = _notary_claims(claims_body)
        if not discovered_claims:
            raise DiscoveryUnavailable("Notary did not return claims.", code="empty_catalog")
        service["claims"] = _merge_notary_claims(service, discovered_claims)
        _normalize_claim_defaults(service)
        service["discovery"] = {"status": "live", "source": "notary"}
    except DiscoveryUnavailable as error:
        service["discovery"] = _unavailable_discovery("Notary discovery unavailable.", error)
    return service


def _merge_notary_claims(service: dict[str, Any], discovered_claims: list[dict[str, Any]]) -> dict[str, Any]:
    fallback_claims = service.get("claims", {})
    merged: dict[str, Any] = {}
    for claim in discovered_claims:
        claim_id = str(claim.get("id", "")).strip()
        if not claim_id:
            continue
        fallback = fallback_claims.get(claim_id, {})
        disclosures = _notary_disclosures(claim, fallback)
        default_disclosure = _notary_default_disclosure(claim, disclosures, fallback)
        item = {
            **deepcopy(fallback),
            "id": claim_id,
            "title": str(claim.get("title") or claim.get("name") or fallback.get("title") or _titleize(claim_id)),
            "value_type": _notary_value_type(claim, fallback),
            "default_disclosure": default_disclosure,
            "allowed_disclosures": disclosures,
            "formats": _notary_formats(claim, fallback),
            "relay_fields_used": list(fallback.get("relay_fields_used", [])),
            "source": deepcopy(fallback.get("source", {})),
        }
        if claim.get("target_inputs"):
            item["target_inputs"] = deepcopy(claim["target_inputs"])
        elif fallback.get("target_inputs"):
            item["target_inputs"] = deepcopy(fallback["target_inputs"])
        for key in ("default_subject", "default_identifier_scheme", "default_purpose"):
            if fallback.get(key):
                item[key] = fallback[key]
        merged[claim_id] = item
    return merged or deepcopy(fallback_claims)


def _normalize_registry_defaults(registry: dict[str, Any]) -> None:
    datasets = registry.get("datasets", {})
    if not datasets:
        return
    default_dataset = registry.get("default_dataset")
    if default_dataset not in datasets:
        default_dataset = next(iter(datasets))
        registry["default_dataset"] = default_dataset
    dataset = datasets.get(default_dataset, {})
    entities = dataset.get("entities", {})
    if entities and registry.get("default_entity") not in entities:
        registry["default_entity"] = next(iter(entities))
    aggregates = dataset.get("aggregates", {})
    if registry.get("default_aggregate") and registry["default_aggregate"] not in aggregates:
        registry["default_aggregate"] = next(iter(aggregates), "")


def _normalize_claim_defaults(service: dict[str, Any]) -> None:
    claims = service.get("claims", {})
    if claims and service.get("default_claim") not in claims:
        service["default_claim"] = next(iter(claims))


def _unavailable_discovery(message: str, error: DiscoveryUnavailable) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "overlay",
        "source": "overlay",
        "message": message,
        "error": {"code": error.code},
    }
    if error.status is not None:
        payload["error"]["status"] = error.status
    return payload


def _discovery_get(config: dict[str, Any], credential_id: str, base_url: str, path: str, *, runtime_env: str = "") -> Any:
    if _is_http_url(path):
        raise DiscoveryUnavailable("Discovery path must be relative to the configured service.", code="absolute_path")
    credential = credential_for_execution(config, credential_id, runtime_env=runtime_env)
    token = str(credential.get("token", ""))
    if not token:
        raise DiscoveryUnavailable("Discovery credential is not configured.", code="credential_missing")
    header_name, header_value = auth_header_pair(credential, token)
    url = joined_url(str(credential.get("service_url") or base_url), path)
    result = HTTP_JSON("GET", url, {header_name: header_value}, timeout=6.0)
    if result.status is None or result.status >= 400:
        raise DiscoveryUnavailable("Discovery request failed.", code=_discovery_error_code(result), status=result.status)
    if result.status >= 300:
        raise DiscoveryUnavailable("Discovery redirects are not followed.", code="redirect", status=result.status)
    return result.body


def _discovery_error_code(result: ExplorerHttpResult) -> str:
    if result.status is not None:
        return "http_error"
    if result.error == "DiscoveryResponseTooLarge":
        return "response_too_large"
    if result.error:
        return "transport_error"
    return "request_failed"


def _relay_datasets(body: Any) -> list[dict[str, Any]]:
    return _collection(body, "datasets")


def _relay_entities(dataset: dict[str, Any]) -> list[dict[str, Any]]:
    return _collection(dataset.get("entities") or dataset.get("entity_schemas") or dataset.get("tables"), "entities")


def _entity_summaries_from_fallback(dataset: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"id": entity_id, "title": entity.get("title", _titleize(entity_id))}
        for entity_id, entity in dataset.get("entities", {}).items()
    ]


def _relay_fields(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict):
        raw = body.get("fields") or body.get("columns")
        if raw is None and isinstance(body.get("properties"), dict):
            raw = [
                {"name": name, **schema}
                for name, schema in body["properties"].items()
                if isinstance(schema, dict)
            ]
        if raw is None and isinstance(body.get("schema"), dict):
            return _relay_fields(body["schema"])
    else:
        raw = body
    fields = []
    for item in _collection(raw, "fields"):
        name = str(item.get("name") or item.get("id") or "").strip()
        if not name:
            continue
        fields.append({"name": name, "type": _field_type(item)})
    return fields


def _relay_aggregates(body: Any) -> list[dict[str, Any]]:
    return _collection(body, "aggregates")


def _notary_claims(body: Any) -> list[dict[str, Any]]:
    return _collection(body, "claims")


def _notary_disclosures(claim: dict[str, Any], fallback: dict[str, Any]) -> list[str]:
    disclosure = claim.get("disclosure")
    raw: Any = None
    if isinstance(disclosure, dict):
        raw = disclosure.get("allowed")
    raw = raw or claim.get("allowed_disclosures") or claim.get("disclosures") or fallback.get("allowed_disclosures")
    items = [str(item) for item in raw] if isinstance(raw, list) else []
    return items or ["predicate"]


def _notary_default_disclosure(claim: dict[str, Any], disclosures: list[str], fallback: dict[str, Any]) -> str:
    disclosure = claim.get("disclosure")
    if isinstance(disclosure, dict) and disclosure.get("default") in disclosures:
        return str(disclosure["default"])
    if claim.get("default_disclosure") in disclosures:
        return str(claim["default_disclosure"])
    if fallback.get("default_disclosure") in disclosures:
        return str(fallback["default_disclosure"])
    return "predicate" if "predicate" in disclosures else disclosures[0]


def _notary_formats(claim: dict[str, Any], fallback: dict[str, Any]) -> list[str]:
    raw = claim.get("formats") or claim.get("allowed_formats") or fallback.get("formats")
    if isinstance(raw, list) and raw:
        return [str(item) for item in raw]
    return list(fallback.get("formats", [])) or ["application/vnd.registry-notary.claim-result+json"]


def _notary_value_type(claim: dict[str, Any], fallback: dict[str, Any]) -> str:
    value = claim.get("value")
    if isinstance(value, dict) and value.get("type"):
        return str(value["type"])
    if claim.get("value_type"):
        return str(claim["value_type"])
    return str(fallback.get("value_type") or "boolean")


def _collection(value: Any, preferred_key: str) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        raw = value.get(preferred_key) or value.get("items") or value.get("data") or value.get("results")
        if raw is None:
            raw = value
    else:
        raw = value
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        return [
            {"id": key, **item} if isinstance(item, dict) else {"id": key, "value": item}
            for key, item in raw.items()
        ]
    return []


def _read_bounded(response: Any, max_bytes: int = DISCOVERY_MAX_BYTES) -> bytes | None:
    raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        return None
    return raw


def _parse_body(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw.decode("utf-8", errors="replace")


def _field_type(field: dict[str, Any]) -> str:
    raw = field.get("type") or field.get("json_type") or field.get("data_type") or "string"
    if isinstance(raw, list):
        raw = next((item for item in raw if item != "null"), "string")
    return str(raw)


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _titleize(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").title()
