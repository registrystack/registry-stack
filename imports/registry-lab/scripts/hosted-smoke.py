#!/usr/bin/env python3
"""Public hosted smoke checks for Registry Lab."""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse, urlunparse


DEFAULT_BASE_URL = "https://lab.registrystack.org"
DEFAULT_CITIZEN_PORTAL_URL = "https://portal.lab.registrystack.org"
DEFAULT_CITIZEN_ISSUER = "https://citizen-notary.lab.registrystack.org"
DEFAULT_DHIS2_NOTARY = "https://dhis2-notary.lab.registrystack.org"
DEFAULT_DHIS2_SERVICE_ID = "dhis2-health-notary"
PERSON_ALIVE_CONFIGURATION = "person_is_alive_sd_jwt"
DHIS2_CREDENTIAL_PROFILE = "dhis2_programme_participation_sd_jwt"
DHIS2_FORMAT = "application/dc+sd-jwt"
CLAIM_RESULT_FORMAT = "application/vnd.registry-notary.claim-result+json"
DHIS2_PURPOSE = "https://demo.example.gov/purpose/dhis2-openfn-health-evidence"
DHIS2_SUBJECT_ID = "PQfMcpmXeFE"
DHIS2_RECONCILIATION_REF = f"dhis2:tracked-entity:{DHIS2_SUBJECT_ID}"
DHIS2_EXPECTED_ISSUER = "did:web:dhis2-notary.lab.registrystack.org"
DHIS2_EXPECTED_VCT = "https://dhis2-notary.lab.registrystack.org/credentials/dhis2/programme-participation/v1"
DHIS2_PROGRAMME_CLAIMS = [
    "dhis2-tracked-entity-first-name",
    "dhis2-tracked-entity-last-name",
    "dhis2-child-age-band",
    "dhis2-programme-code",
    "dhis2-child-program-active",
    "dhis2-reconciliation-ref",
]

EXPECTED_STEPS = {
    "alive-proof": ["discover", "prepare-evidence", "deny-row"],
    "civil-birth-demographics": ["discover", "lookup"],
    "civil-birth-evidence": ["discover", "evaluate"],
    "civil-birth-evidence-demographics": ["discover", "evaluate"],
    "civil-marriage-evidence": ["discover", "evaluate"],
    "wallet-credential": ["issuer-metadata", "credential-offer", "holder-key", "nonce", "credential-preview"],
    "dhis2-programme-vc": [
        "discover",
        "evaluate-programme",
        "preview-vc",
        "reconcile",
        "negative-control",
        "render-cccev",
    ],
    "social-aggregate": ["discover", "read-aggregate", "deny-row-with-aggregate", "read-row-with-row-token"],
    "combined-support": [
        "discover",
        "civil-subclaim",
        "social-subclaim",
        "health-subclaim",
        "final-positive",
        "negative-control",
    ],
    "agriculture-voucher": [
        "discover",
        "positive-voucher",
        "inactive-parcel-control",
        "redeemed-control",
        "reason-code",
    ],
}
EXPECTED_STEP_STATUSES = {
    "alive-proof": {
        "discover": "done",
        "prepare-evidence": "done",
        "deny-row": "denied_as_expected",
    },
    "civil-birth-demographics": {
        "discover": "done",
        "lookup": "done",
    },
    "civil-birth-evidence": {
        "discover": "done",
        "evaluate": "done",
    },
    "civil-birth-evidence-demographics": {
        "discover": "done",
        "evaluate": "done",
    },
    "civil-marriage-evidence": {
        "discover": "done",
        "evaluate": "done",
    },
    "wallet-credential": {
        "issuer-metadata": "done",
        "credential-offer": "done",
        "holder-key": "done",
        "nonce": "done",
        "credential-preview": "done",
    },
    "dhis2-programme-vc": {
        "discover": "done",
        "evaluate-programme": "done",
        "preview-vc": "done",
        "reconcile": "done",
        "negative-control": "done",
        "render-cccev": "done",
    },
    "social-aggregate": {
        "discover": "done",
        "read-aggregate": "done",
        "deny-row-with-aggregate": "denied_as_expected",
        "read-row-with-row-token": "done",
    },
    "combined-support": {
        "discover": "done",
        "civil-subclaim": "done",
        "social-subclaim": "done",
        "health-subclaim": "done",
        "final-positive": "done",
        "negative-control": "done",
    },
    "agriculture-voucher": {
        "discover": "done",
        "positive-voucher": "done",
        "inactive-parcel-control": "done",
        "redeemed-control": "done",
        "reason-code": "done",
    },
}

CITIZEN_PORTAL_EXPECTED_STEPS = {
    "citizen-portal": [
        "landing",
        "solmaraid-sign-in",
        "mock-login",
        "evaluate-field",
        "sse-redacted-trace",
    ],
}

DEFAULT_EVALUATED_CLAIM_SERVICES = {
    "civil-notary",
    "social-protection-notary",
    "shared-eligibility-notary",
    "dhis2-notary",
    "agriculture-notary",
}
DISCOVERY_REQUIRED_AGRICULTURE_CLAIM = "active-smallholder-farmer"

SENSITIVE_KEYS = {
    "authorization",
    "auth_header",
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "credential",
    "raw_credential",
    "compact_credential",
    "issuer_signed_jwt",
    "disclosure",
    "disclosures",
    "holder",
    "holder_proof",
    "proof",
    "secret",
}
SENSITIVE_KEY_SUFFIXES = (
    "token",
    "bearer",
    "secret",
)
AUTH_HEADER_RE = re.compile(r"(?i)\b(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9._~+/=-]{8,}")
API_KEY_RE = re.compile(r"(?i)\b(x-api-key\s*[:=]\s*)[A-Za-z0-9._~+/=-]{8,}")
JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}(?:~[A-Za-z0-9_-]+)*\b")
DID_JWK_RE = re.compile(r"\bdid:jwk:[A-Za-z0-9_-]{24,}\b")
JSON_SECRET_RE = re.compile(
    r'(?i)("?(?:authorization|auth_header|token|credential|disclosures?|holder|proof|secret)"?\s*[:=]\s*)("[^"]+"|[^,\s}]+)'
)
PORTAL_RAW_IDENTIFIER_RE = re.compile(r"\b(?:NID|CP)-[A-Za-z0-9-]+\b")
PORTAL_RAW_BEARER_RE = re.compile(r"(?i)\b(?:authorization\s*[:=]\s*)?bearer\s+[A-Za-z0-9._~+/=-]{8,}")


@dataclass(frozen=True)
class SmokeConfig:
    base_url: str = DEFAULT_BASE_URL
    citizen_portal_smoke: bool = True
    credential_smoke: bool = False
    portal_url: str | None = None
    timeout: float = 12.0


@dataclass(frozen=True)
class HttpJsonResponse:
    status: int | None
    body: Any
    headers: dict[str, str]
    url: str
    method: str
    error: str = ""


class SmokeFailure(Exception):
    def __init__(self, code: str, detail: Any = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(self.__str__())

    def __str__(self) -> str:
        if self.detail == "":
            return self.code
        return f"{self.code}: {format_failure_detail(self.detail)}"


class JsonClient:
    def __init__(self, timeout: float, opener: urllib.request.OpenerDirector | None = None) -> None:
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener()

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpJsonResponse:
        return self.request("GET", url, headers=headers)

    def post(self, url: str, body: Any, headers: dict[str, str] | None = None) -> HttpJsonResponse:
        return self.request("POST", url, headers=headers, body=body)

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: Any | None = None,
    ) -> HttpJsonResponse:
        request = self.build_request(method, url, headers=headers, body=body)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                return HttpJsonResponse(
                    status=response.status,
                    body=parse_json_body(raw),
                    headers={key.lower(): value for key, value in response.headers.items()},
                    url=response.geturl(),
                    method=method,
                )
        except urllib.error.HTTPError as error:
            raw = error.read()
            return HttpJsonResponse(
                status=error.code,
                body=parse_json_body(raw),
                headers={key.lower(): value for key, value in error.headers.items()},
                url=error.geturl(),
                method=method,
            )
        except Exception as error:  # noqa: BLE001
            return HttpJsonResponse(
                status=None,
                body={},
                headers={},
                url=url,
                method=method,
                error=error.__class__.__name__,
            )

    def open_response(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: Any | None = None,
    ) -> Any:
        return self.opener.open(self.build_request(method, url, headers=headers, body=body), timeout=self.timeout)

    def build_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: Any | None = None,
    ) -> urllib.request.Request:
        request_headers = {"User-Agent": "registry-lab-hosted-smoke/1.0", **(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        return urllib.request.Request(url, headers=request_headers, data=data, method=method)


def joined_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def parse_json_body(raw: bytes) -> Any:
    if not raw:
        return {}
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def is_ok(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def require(condition: bool, code: str, detail: Any = "") -> None:
    if not condition:
        raise SmokeFailure(code, detail)


def require_ok(response: HttpJsonResponse, code: str) -> None:
    require(
        is_ok(response.status),
        code,
        {
            "method": response.method,
            "url": response.url,
            "status": response.status,
            "body": response.body,
            "error": response.error,
        },
    )


def sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if is_sensitive_key(str(key)):
                result[key] = "[redacted]"
            else:
                result[key] = sanitize_value(item)
        return result
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return lowered in SENSITIVE_KEYS or "holder_proof" in lowered or lowered.endswith(SENSITIVE_KEY_SUFFIXES)


def sanitize_text(text: str) -> str:
    redacted = AUTH_HEADER_RE.sub(r"\1[redacted]", text)
    redacted = API_KEY_RE.sub(r"\1[redacted]", redacted)
    redacted = JSON_SECRET_RE.sub(r"\1[redacted]", redacted)
    redacted = JWT_RE.sub("[compact-redacted]", redacted)
    redacted = DID_JWK_RE.sub("[holder-did-redacted]", redacted)
    return redacted


def format_failure_detail(detail: Any) -> str:
    safe = sanitize_value(detail)
    if isinstance(safe, str):
        text = safe
    else:
        text = json.dumps(safe, sort_keys=True, separators=(",", ":"))
    text = sanitize_text(text)
    return text if len(text) <= 1200 else text[:1197] + "..."


def credential_configurations(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    configurations = metadata.get("credential_configurations_supported")
    return configurations if isinstance(configurations, dict) else {}


def scenario_step_ids(story_payload: Any) -> list[str]:
    if not isinstance(story_payload, dict):
        return []
    story = story_payload.get("story")
    if not isinstance(story, dict):
        return []
    steps = story.get("steps")
    if not isinstance(steps, list):
        return []
    return [step.get("id") for step in steps if isinstance(step, dict)]


def items_from(body: Any, key: str) -> list[Any]:
    if not isinstance(body, dict):
        return []
    items = body.get(key)
    return items if isinstance(items, list) else []


def friendly_status(step_payload: Any) -> str:
    if not isinstance(step_payload, dict):
        return ""
    friendly = step_payload.get("friendly")
    if not isinstance(friendly, dict):
        return ""
    status = friendly.get("status")
    return status if isinstance(status, str) else ""


def health_body_ok(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    if body.get("ok") is True:
        return True
    return body.get("status") == "ok"


def query_path(path: str, params: dict[str, Any]) -> str:
    query = urlencode({key: value for key, value in params.items() if value not in (None, "")})
    return f"{path}?{query}" if query else path


def require_no_error_payload(body: Any, code: str, context: dict[str, Any]) -> None:
    require(not (isinstance(body, dict) and body.get("ok") is False and "error" in body), code, {**context, "body": body})


def claim_answer_available(answer: Any) -> bool:
    if not isinstance(answer, dict):
        return False
    if answer.get("satisfied") is not None or answer.get("value") is not None:
        return True
    return answer.get("preview") is True and answer.get("subject_found") is True


def resolve_citizen_portal_url(config: SmokeConfig, base_url: str) -> str:
    configured = (
        config.portal_url
        or os.environ.get("REGISTRY_LAB_CITIZEN_PORTAL_URL")
        or os.environ.get("CITIZEN_PORTAL_URL")
        or ""
    ).strip()
    if configured:
        return configured.rstrip("/")
    if base_url.rstrip("/") == DEFAULT_BASE_URL:
        return DEFAULT_CITIZEN_PORTAL_URL

    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    if host.startswith("lab."):
        netloc = "portal." + host
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunparse((parsed.scheme, netloc, "", "", "", "")).rstrip("/")
    return ""


def cookie_client(timeout: float) -> JsonClient:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    return JsonClient(timeout, opener)


def run_citizen_portal_smoke(config: SmokeConfig, base_url: str) -> dict[str, Any]:
    expected_steps = CITIZEN_PORTAL_EXPECTED_STEPS["citizen-portal"]
    if not config.citizen_portal_smoke:
        return {"status": "skipped", "reason": "disabled", "checks": 0, "steps": expected_steps}

    portal_url = resolve_citizen_portal_url(config, base_url)
    if not portal_url:
        return {
            "status": "skipped",
            "reason": "portal_url_not_configured",
            "checks": 0,
            "steps": expected_steps,
        }

    client = cookie_client(config.timeout)
    landing = client.get(joined_url(portal_url, "/"))
    require_ok(landing, "citizen-portal-landing-unavailable")
    require(
        isinstance(landing.body, str) and "Sign in with SolmaraID" in landing.body,
        "citizen-portal-sign-in-missing",
        {"url": landing.url, "status": landing.status, "body": landing.body},
    )

    login = client.get(joined_url(portal_url, "/auth/login"))
    require_ok(login, "citizen-portal-login-unavailable")
    require(
        urlparse(login.url).path.rstrip("/") == "/services",
        "citizen-portal-login-redirect-mismatch",
        {"url": login.url, "status": login.status},
    )

    trace, trace_text = run_citizen_portal_evaluation_round_trip(client, portal_url, config.timeout)
    assert_no_portal_sensitive_material(trace_text, "citizen-portal-sse-sensitive-material")

    return {
        "status": "done",
        "url": portal_url,
        "checks": len(expected_steps),
        "steps": expected_steps,
        "evaluation": {
            "field_id": trace.get("fieldId"),
            "status": trace.get("status"),
            "trace_id": trace.get("id"),
        },
    }


def run_citizen_portal_evaluation_round_trip(
    client: JsonClient,
    portal_url: str,
    timeout: float,
) -> tuple[dict[str, Any], str]:
    stream_url = joined_url(portal_url, "/proof/stream")
    try:
        stream = client.open_response("GET", stream_url, headers={"Accept": "text/event-stream"})
    except Exception as error:  # noqa: BLE001
        raise SmokeFailure("citizen-portal-sse-unavailable", {"url": stream_url, "error": error.__class__.__name__}) from error

    try:
        require(stream.status == 200, "citizen-portal-sse-unavailable", {"url": stream_url, "status": stream.status})
        content_type = stream.headers.get("content-type", "")
        require(
            "text/event-stream" in content_type,
            "citizen-portal-sse-content-type-mismatch",
            {"url": stream_url, "content_type": content_type},
        )

        evaluation_body = {"slug": "agri-subsidy", "fieldId": "registered-farmer"}
        evaluation = client.post(joined_url(portal_url, "/api/evaluate"), evaluation_body)
        require_ok(evaluation, "citizen-portal-evaluation-unavailable")
        require(
            isinstance(evaluation.body, dict) and evaluation.body.get("state") == "verified",
            "citizen-portal-evaluation-unexpected",
            {"status": evaluation.status, "body": evaluation.body},
        )
        trace_id = evaluation.body.get("traceId") if isinstance(evaluation.body, dict) else None
        require(
            isinstance(trace_id, str) and trace_id,
            "citizen-portal-evaluation-trace-id-missing",
            {"status": evaluation.status, "body": evaluation.body},
        )

        trace, trace_text = read_sse_trace(stream, timeout, "registered-farmer", trace_id)
        require(
            trace.get("fieldId") == "registered-farmer",
            "citizen-portal-sse-trace-field-mismatch",
            trace,
        )
        require(
            trace.get("status") in {"ok", "false", "denied"},
            "citizen-portal-sse-trace-status-mismatch",
            trace,
        )
        return trace, trace_text
    finally:
        stream.close()


def read_sse_trace(stream: Any, timeout: float, field_id: str, trace_id: str) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + timeout
    event_name = ""
    data_lines: list[str] = []
    seen_events: list[str] = []

    while time.monotonic() < deadline:
        try:
            raw = stream.readline()
        except socket.timeout as error:
            raise SmokeFailure("citizen-portal-sse-trace-timeout", {"seen_events": seen_events}) from error
        if raw == b"":
            break
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if line == "":
            if event_name:
                seen_events.append(event_name)
            if event_name == "trace":
                data_text = "\n".join(data_lines)
                assert_no_portal_sensitive_material(data_text, "citizen-portal-sse-sensitive-material")
                try:
                    payload = json.loads(data_text)
                except json.JSONDecodeError as error:
                    raise SmokeFailure("citizen-portal-sse-trace-invalid-json", data_text) from error
                require(isinstance(payload, dict), "citizen-portal-sse-trace-shape-mismatch", payload)
                if payload.get("fieldId") == field_id and payload.get("id") == trace_id:
                    return payload, data_text
            event_name = ""
            data_lines = []
            continue
        if line.startswith("event:"):
            event_name = line.split(":", 1)[1].strip()
        elif line.startswith("data:"):
            data_lines.append(line.split(":", 1)[1].lstrip())

    raise SmokeFailure("citizen-portal-sse-trace-timeout", {"seen_events": seen_events})


def assert_no_portal_sensitive_material(text: str, code: str) -> None:
    identifier = PORTAL_RAW_IDENTIFIER_RE.search(text)
    bearer = PORTAL_RAW_BEARER_RE.search(text)
    require(
        identifier is None and bearer is None,
        code,
        {
            "identifier": identifier.group(0) if identifier else "",
            "bearer": bearer.group(0) if bearer else "",
        },
    )


def run_smoke(config: SmokeConfig) -> dict[str, Any]:
    base_url = config.base_url.rstrip("/")
    client = JsonClient(config.timeout)

    health = client.get(joined_url(base_url, "/healthz"))
    require_ok(health, "healthz-unavailable")
    require(health_body_ok(health.body), "healthz-unexpected", health.body)

    catalogue = client.get(joined_url(base_url, "/api/scenarios.json"))
    require_ok(catalogue, "scenario-catalogue-unavailable")
    catalogue_ids = scenario_catalogue_ids(catalogue.body)
    expected_catalogue_ids = list(EXPECTED_STEPS)
    require(
        sorted(catalogue_ids) == sorted(expected_catalogue_ids),
        "scenario-catalogue-mismatch",
        {"expected": sorted(expected_catalogue_ids), "actual": sorted(catalogue_ids)},
    )

    lab = client.get(joined_url(base_url, "/api/lab.json"))
    require_ok(lab, "lab-metadata-unavailable")
    wallet = lab.body.get("wallet") if isinstance(lab.body, dict) else None
    require(isinstance(wallet, dict), "wallet-metadata-missing", lab.body)
    require(
        wallet.get("credential_configuration_id") == PERSON_ALIVE_CONFIGURATION,
        "wallet-credential-configuration-mismatch",
        wallet,
    )

    citizen_issuer = DEFAULT_CITIZEN_ISSUER if base_url == DEFAULT_BASE_URL else str(wallet.get("issuer") or DEFAULT_CITIZEN_ISSUER)
    citizen_metadata = client.get(joined_url(citizen_issuer, "/.well-known/openid-credential-issuer"))
    require_ok(citizen_metadata, "citizen-issuer-metadata-unavailable")
    configurations = credential_configurations(citizen_metadata.body)
    require(
        PERSON_ALIVE_CONFIGURATION in configurations,
        "citizen-issuer-configuration-missing",
        {"expected": PERSON_ALIVE_CONFIGURATION, "seen": sorted(configurations)},
    )

    story_summaries: dict[str, list[str]] = {}
    for scenario_id, expected_ids in EXPECTED_STEPS.items():
        story_response = client.get(joined_url(base_url, f"/api/scenarios/{scenario_id}.json"))
        require_ok(story_response, "scenario-story-unavailable")
        actual_ids = scenario_step_ids(story_response.body)
        require(
            actual_ids == expected_ids,
            "scenario-story-step-mismatch",
            {"scenario": scenario_id, "expected": expected_ids, "actual": actual_ids},
        )
        story_summaries[scenario_id] = actual_ids

    step_summaries: dict[str, dict[str, str]] = {}
    for scenario_id, expected_by_step in EXPECTED_STEP_STATUSES.items():
        step_summaries[scenario_id] = {}
        for step_id, expected_status in expected_by_step.items():
            step_response = client.post(joined_url(base_url, f"/api/scenarios/{scenario_id}/{step_id}"), {})
            require_ok(step_response, "scenario-step-unavailable")
            actual_status = friendly_status(step_response.body)
            require(
                actual_status == expected_status,
                "scenario-step-status-mismatch",
                {
                    "scenario": scenario_id,
                    "step": step_id,
                    "expected": expected_status,
                    "actual": actual_status,
                    "body": step_response.body,
                },
            )
            step_summaries[scenario_id][step_id] = actual_status

    explorer_summary = run_explorer_smoke(client, base_url)
    citizen_portal_summary = run_citizen_portal_smoke(config, base_url)

    summary: dict[str, Any] = {
        "base_url": base_url,
        "checks": (
            1
            + 1
            + 1
            + 1
            + sum(len(steps) for steps in EXPECTED_STEP_STATUSES.values())
            + len(EXPECTED_STEPS)
            + explorer_summary["checks"]
            + citizen_portal_summary["checks"]
        ),
        "citizen_portal": citizen_portal_summary,
        "credential_smoke": "skipped",
        "explorers": explorer_summary,
        "scenarios": step_summaries,
        "stories": {key: len(value) for key, value in story_summaries.items()},
        "wallet_configuration": PERSON_ALIVE_CONFIGURATION,
    }
    if config.credential_smoke:
        summary["credential_smoke"] = run_credential_smoke(client, lab.body)
    return summary


def run_explorer_smoke(client: JsonClient, base_url: str) -> dict[str, Any]:
    registry_catalog = client.get(joined_url(base_url, "/api/explorer/registries.json"))
    require_ok(registry_catalog, "registry-explorer-catalogue-unavailable")
    registries = items_from(registry_catalog.body, "registries")
    require(bool(registries), "registry-explorer-catalogue-empty", registry_catalog.body)

    registry_summary: dict[str, Any] = {}
    checks = 1
    live_registry_discovery = 0
    for registry in registries:
        if not isinstance(registry, dict):
            continue
        registry_id = str(registry.get("id") or "")
        dataset_id = str(registry.get("default_dataset") or "")
        entity_id = str(registry.get("default_entity") or "")
        default_limit = registry.get("default_limit", 1)
        require(registry_id and dataset_id and entity_id, "registry-explorer-defaults-missing", registry)
        discovery = registry.get("discovery") if isinstance(registry.get("discovery"), dict) else {}
        if discovery.get("status") == "live":
            live_registry_discovery += 1

        metadata = client.get(joined_url(base_url, f"/api/explorer/registries/{registry_id}/metadata.json"))
        require_ok(metadata, "registry-explorer-metadata-unavailable")
        require_no_error_payload(metadata.body, "registry-explorer-metadata-error", {"registry": registry_id})

        schema_path = query_path(
            f"/api/explorer/registries/{registry_id}/entity-schema.json",
            {"dataset": dataset_id, "entity": entity_id},
        )
        schema = client.get(joined_url(base_url, schema_path))
        require_ok(schema, "registry-explorer-schema-unavailable")
        require_no_error_payload(schema.body, "registry-explorer-schema-error", {"registry": registry_id})
        fields = items_from(schema.body, "fields")
        require(bool(fields), "registry-explorer-schema-empty", {"registry": registry_id, "body": schema.body})

        records_path = query_path(
            f"/api/explorer/registries/{registry_id}/records.json",
            {"dataset": dataset_id, "entity": entity_id, "limit": default_limit},
        )
        records = client.get(joined_url(base_url, records_path))
        require_ok(records, "registry-explorer-records-unavailable")
        require_no_error_payload(records.body, "registry-explorer-records-error", {"registry": registry_id})
        rows = items_from(records.body, "records")
        require(bool(rows), "registry-explorer-records-empty", {"registry": registry_id, "body": records.body})
        checks += 3

        aggregate_count = 0
        aggregate_id = str(registry.get("default_aggregate") or "")
        if aggregate_id:
            aggregates_path = query_path(
                f"/api/explorer/registries/{registry_id}/aggregates.json",
                {"dataset": dataset_id},
            )
            aggregates = client.get(joined_url(base_url, aggregates_path))
            require_ok(aggregates, "registry-explorer-aggregates-unavailable")
            require_no_error_payload(aggregates.body, "registry-explorer-aggregates-error", {"registry": registry_id})
            require(bool(items_from(aggregates.body, "aggregates")), "registry-explorer-aggregates-empty", {"registry": registry_id})

            aggregate_path_value = query_path(
                f"/api/explorer/registries/{registry_id}/aggregate.json",
                {"dataset": dataset_id, "aggregate": aggregate_id},
            )
            aggregate = client.get(joined_url(base_url, aggregate_path_value))
            require_ok(aggregate, "registry-explorer-aggregate-unavailable")
            require_no_error_payload(aggregate.body, "registry-explorer-aggregate-error", {"registry": registry_id})
            aggregate_rows = items_from(aggregate.body, "records") or items_from(aggregate.body, "observations")
            require(bool(aggregate_rows), "registry-explorer-aggregate-empty", {"registry": registry_id, "aggregate": aggregate_id})
            aggregate_count = len(aggregate_rows)
            checks += 2

        registry_summary[registry_id] = {
            "records": len(rows),
            "aggregate_records": aggregate_count,
            "discovery": discovery.get("status", "unknown"),
        }

    require(
        live_registry_discovery > 0,
        "registry-explorer-discovery-not-live",
        {"registries": registry_summary},
    )

    claims_catalog = client.get(joined_url(base_url, "/api/explorer/claims.json"))
    require_ok(claims_catalog, "claims-explorer-catalogue-unavailable")
    services = items_from(claims_catalog.body, "claim_services")
    require(bool(services), "claims-explorer-catalogue-empty", claims_catalog.body)
    default_format = claims_catalog.body.get("default_format") if isinstance(claims_catalog.body, dict) else CLAIM_RESULT_FORMAT
    checks += 1

    claim_summary: dict[str, Any] = {}
    for service in services:
        if not isinstance(service, dict):
            continue
        service_id = str(service.get("id") or "")
        require(service_id, "claims-explorer-service-id-missing", service)
        metadata = client.get(joined_url(base_url, f"/api/explorer/claims/{service_id}/metadata.json"))
        require_ok(metadata, "claims-explorer-metadata-unavailable")
        require_no_error_payload(metadata.body, "claims-explorer-metadata-error", {"service": service_id})
        claim_service = metadata.body.get("claim_service") if isinstance(metadata.body, dict) else None
        require(isinstance(claim_service, dict), "claims-explorer-metadata-shape", {"service": service_id, "body": metadata.body})
        claims = items_from(claim_service, "claims")
        require(bool(claims), "claims-explorer-claims-empty", {"service": service_id})
        checks += 1
        discovery = claim_service.get("discovery") if isinstance(claim_service.get("discovery"), dict) else {}
        claim_ids = {str(claim.get("id")) for claim in claims if isinstance(claim, dict)}
        if service_id == "agriculture-notary":
            require(
                discovery.get("status") == "live",
                "claims-explorer-agriculture-discovery-not-live",
                {"service": service_id, "discovery": discovery},
            )
            require(
                DISCOVERY_REQUIRED_AGRICULTURE_CLAIM in claim_ids,
                "claims-explorer-agriculture-discovery-claim-missing",
                {"claim_id": DISCOVERY_REQUIRED_AGRICULTURE_CLAIM, "claims": sorted(claim_ids)},
            )

        mode = "metadata"
        if service_id in DEFAULT_EVALUATED_CLAIM_SERVICES:
            default_claim = str(claim_service.get("default_claim") or "")
            selected_claim = next((claim for claim in claims if isinstance(claim, dict) and claim.get("id") == default_claim), {})
            require(bool(selected_claim), "claims-explorer-default-claim-missing", {"service": service_id, "default_claim": default_claim})
            evaluation_body = {
                "claim_id": default_claim,
                "subject": claim_service.get("default_subject"),
                "identifier_scheme": claim_service.get("default_identifier_scheme"),
                "disclosure": selected_claim.get("default_disclosure"),
                "format": default_format,
                "purpose": claim_service.get("default_purpose"),
            }
            evaluation = client.post(
                joined_url(base_url, f"/api/explorer/claims/{service_id}/evaluate.json"),
                evaluation_body,
            )
            require_ok(evaluation, "claims-explorer-evaluation-unavailable")
            require_no_error_payload(evaluation.body, "claims-explorer-evaluation-error", {"service": service_id})
            answer = evaluation.body.get("answer") if isinstance(evaluation.body, dict) else {}
            require(
                claim_answer_available(answer),
                "claims-explorer-evaluation-empty",
                {"service": service_id, "body": evaluation.body},
            )
            mode = str(evaluation.body.get("mode", "unknown")) if isinstance(evaluation.body, dict) else "unknown"
            checks += 1
        claim_summary[service_id] = {
            "claims": len(claims),
            "default_evaluation": mode,
            "discovery": discovery.get("status", "unknown"),
        }

    return {"checks": checks, "registries": registry_summary, "claims": claim_summary}


def scenario_catalogue_ids(body: Any) -> list[str]:
    if not isinstance(body, dict) or not isinstance(body.get("scenarios"), list):
        return []
    return [item.get("id") for item in body["scenarios"] if isinstance(item, dict) and isinstance(item.get("id"), str)]


def find_credential(lab: Any, credential_id: str) -> dict[str, Any]:
    if not isinstance(lab, dict):
        return {}
    credentials = lab.get("credentials")
    if not isinstance(credentials, list):
        return {}
    for credential in credentials:
        if isinstance(credential, dict) and credential.get("id") == credential_id:
            return credential
    return {}


def bearer_from_env_or_lab(credential: dict[str, Any]) -> str:
    env_name = str(credential.get("env") or "DHIS2_EVIDENCE_CLIENT_BEARER")
    return (
        os.environ.get(env_name, "")
        or os.environ.get("DHIS2_EVIDENCE_CLIENT_BEARER", "")
        or str(credential.get("token") or "")
    )


def auth_headers(token: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", **(extra or {})}


def run_credential_smoke(client: JsonClient, lab: Any) -> dict[str, Any]:
    credential = find_credential(lab, "dhis2-bearer")
    token = bearer_from_env_or_lab(credential)
    require(bool(token), "dhis2-bearer-missing", {"credential_id": "dhis2-bearer", "env": credential.get("env")})
    notary_url = (
        os.environ.get("DHIS2_NOTARY_URL")
        or str(credential.get("service_url") or "")
        or DEFAULT_DHIS2_NOTARY
    ).rstrip("/")
    service_id = (
        os.environ.get("DHIS2_NOTARY_SERVICE_ID")
        or str(credential.get("service_id") or "")
        or DEFAULT_DHIS2_SERVICE_ID
    )

    evaluate_body = {
        "target": {
            "type": "TrackedEntity",
            "identifiers": [{"scheme": "dhis2_tracked_entity", "value": DHIS2_SUBJECT_ID}],
        },
        "claims": DHIS2_PROGRAMME_CLAIMS,
        "disclosure": "value",
        "format": DHIS2_FORMAT,
    }
    evaluation = client.post(
        joined_url(notary_url, "/v1/evaluations"),
        evaluate_body,
        auth_headers(token, {"Content-Type": "application/json", "Data-Purpose": DHIS2_PURPOSE}),
    )
    require_ok(evaluation, "dhis2-evaluation-unavailable")
    evaluation_id = first_evaluation_id(evaluation.body)
    require(bool(evaluation_id), "dhis2-evaluation-id-missing", evaluation.body)
    facts = dhis2_facts(evaluation.body)
    require(facts["active"] is True, "dhis2-programme-active-mismatch", facts)
    require(
        facts["reconciliation_ref"] == DHIS2_RECONCILIATION_REF,
        "dhis2-reconciliation-ref-mismatch",
        facts,
    )
    require(facts["claim_count"] >= len(DHIS2_PROGRAMME_CLAIMS), "dhis2-claim-count-mismatch", facts)

    holder = generate_holder_proof(service_id, evaluation_id)
    credential_request = {
        "evaluation_id": evaluation_id,
        "credential_profile": DHIS2_CREDENTIAL_PROFILE,
        "format": DHIS2_FORMAT,
        "claims": DHIS2_PROGRAMME_CLAIMS,
        "disclosure": "value",
        "holder": holder["holder"],
    }
    credential_response = client.post(
        joined_url(notary_url, "/v1/credentials"),
        credential_request,
        auth_headers(token, {"Content-Type": "application/json", "Data-Purpose": DHIS2_PURPOSE}),
    )
    require_ok(credential_response, "dhis2-credential-unavailable")
    credential_summary = validate_credential_response(credential_response.body)
    return {
        "status": "done",
        "claim_count": facts["claim_count"],
        "credential_profile": credential_summary["credential_profile"],
        "format": credential_summary["format"],
        "reconciliation": "matched",
        "validity": credential_summary["validity"],
    }


def first_evaluation_id(body: Any) -> str:
    results = body.get("results") if isinstance(body, dict) else None
    if not isinstance(results, list):
        return ""
    for item in results:
        if isinstance(item, dict) and isinstance(item.get("evaluation_id"), str):
            return item["evaluation_id"]
    return ""


def dhis2_facts(body: Any) -> dict[str, Any]:
    results = body.get("results") if isinstance(body, dict) else None
    by_claim = {item.get("claim_id"): item for item in results if isinstance(item, dict)} if isinstance(results, list) else {}
    active = observed_answer(by_claim.get("dhis2-child-program-active", {}))
    reconciliation_ref = observed_answer(by_claim.get("dhis2-reconciliation-ref", {}))
    return {
        "active": active,
        "claim_count": len(results) if isinstance(results, list) else 0,
        "reconciliation_ref": reconciliation_ref,
    }


def observed_answer(item: Any) -> Any:
    if not isinstance(item, dict):
        return None
    if item.get("satisfied") is not None:
        return item.get("satisfied")
    return item.get("value")


def generate_holder_proof(service_id: str, evaluation_id: str) -> dict[str, Any]:
    helper = Path(__file__).resolve().parent / "generate-holder-proof.js"
    command = [
        "node",
        str(helper),
        "--audience",
        service_id,
        "--evaluation-id",
        evaluation_id,
        "--credential-profile",
        DHIS2_CREDENTIAL_PROFILE,
        "--disclosure",
        "value",
        "--claims-json",
        json.dumps(DHIS2_PROGRAMME_CLAIMS, separators=(",", ":")),
    ]
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
    except FileNotFoundError as error:
        raise SmokeFailure("holder-proof-helper-unavailable", {"error": error.__class__.__name__}) from error
    except subprocess.TimeoutExpired as error:
        raise SmokeFailure("holder-proof-helper-timeout") from error
    if result.returncode != 0:
        raise SmokeFailure(
            "holder-proof-helper-failed",
            {"status": result.returncode, "stderr": result.stderr, "stdout": result.stdout},
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise SmokeFailure("holder-proof-helper-invalid-json", result.stdout) from error
    holder = payload.get("holder") if isinstance(payload, dict) else None
    require(
        isinstance(holder, dict)
        and holder.get("binding") == "did"
        and isinstance(holder.get("id"), str)
        and isinstance(holder.get("proof"), str),
        "holder-proof-helper-shape-mismatch",
        payload,
    )
    return payload


def validate_credential_response(body: Any) -> dict[str, str]:
    require(isinstance(body, dict), "dhis2-credential-shape-mismatch", body)
    credential = body.get("credential")
    require(isinstance(credential, str) and credential, "dhis2-credential-value-missing", body)
    profile = body.get("credential_profile")
    if profile is not None:
        require(profile == DHIS2_CREDENTIAL_PROFILE, "dhis2-credential-profile-mismatch", body)
    fmt = body.get("format")
    if fmt is not None:
        require(fmt == DHIS2_FORMAT, "dhis2-credential-format-mismatch", body)

    payload = decode_compact_credential_payload(credential)
    if payload:
        issuer = payload.get("iss")
        vct = payload.get("vct")
        if issuer is not None:
            require(issuer == DHIS2_EXPECTED_ISSUER, "dhis2-credential-issuer-mismatch", payload)
        if vct is not None:
            require(vct == DHIS2_EXPECTED_VCT, "dhis2-credential-vct-mismatch", payload)
        require("cnf" in payload or "sub" in payload, "dhis2-credential-holder-binding-missing", payload)
        assert_jwt_validity(payload)
    return {
        "credential_profile": str(profile or DHIS2_CREDENTIAL_PROFILE),
        "format": str(fmt or DHIS2_FORMAT),
        "validity": "checked",
    }


def decode_compact_credential_payload(credential: str) -> dict[str, Any]:
    jwt_part = credential.split("~", 1)[0]
    pieces = jwt_part.split(".")
    if len(pieces) < 2:
        return {}
    try:
        return json.loads(base64url_decode(pieces[1]).decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def assert_jwt_validity(payload: dict[str, Any]) -> None:
    iat = payload.get("iat")
    exp = payload.get("exp")
    if isinstance(iat, int) and isinstance(exp, int):
        require(exp > iat, "dhis2-credential-validity-mismatch", {"iat": iat, "exp": exp})
        require(exp > int(datetime.now(timezone.utc).timestamp()), "dhis2-credential-expired", {"exp": exp})
    issued_at = parse_datetime(payload.get("nbf") or payload.get("iat"))
    expires_at = parse_datetime(payload.get("exp"))
    if issued_at and expires_at:
        require(expires_at > issued_at, "dhis2-credential-validity-mismatch", {"issued_at": issued_at, "exp": expires_at})


def parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, int):
        return datetime.fromtimestamp(value, timezone.utc)
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_args(argv: list[str]) -> SmokeConfig:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument(
        "--portal-url",
        default=None,
        help=(
            "Citizen portal base URL. Defaults to the hosted portal for the default lab URL, "
            "or to portal.<lab-host> when the lab host starts with lab."
        ),
    )
    parser.add_argument("--skip-citizen-portal-smoke", action="store_true")
    parser.add_argument("--credential-smoke", action="store_true")
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args(argv)
    return SmokeConfig(
        base_url=args.base_url,
        citizen_portal_smoke=not args.skip_citizen_portal_smoke,
        credential_smoke=args.credential_smoke,
        portal_url=args.portal_url,
        timeout=args.timeout,
    )


def main(argv: list[str] | None = None) -> int:
    config = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        summary = run_smoke(config)
    except SmokeFailure as error:
        print(f"FAIL hosted-smoke {error}", file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001
        print(
            f"FAIL hosted-smoke unexpected: {sanitize_text(error.__class__.__name__ + ': ' + str(error))}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(sanitize_value(summary), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
