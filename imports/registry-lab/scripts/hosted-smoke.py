#!/usr/bin/env python3
"""Public hosted smoke checks for Registry Lab."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin


DEFAULT_BASE_URL = "https://lab.registrystack.org"
DEFAULT_CITIZEN_ISSUER = "https://citizen-notary.lab.registrystack.org"
DEFAULT_DHIS2_NOTARY = "https://dhis2-notary.lab.registrystack.org"
DEFAULT_DHIS2_SERVICE_ID = "dhis2-health-notary"
PERSON_ALIVE_CONFIGURATION = "person_is_alive_sd_jwt"
DHIS2_CREDENTIAL_PROFILE = "dhis2_programme_participation_sd_jwt"
DHIS2_FORMAT = "application/dc+sd-jwt"
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
    "social-aggregate": ["discover", "read-aggregate", "deny-row-with-aggregate", "read-row-with-row-token"],
    "combined-support": [
        "discover",
        "civil-subclaim",
        "social-subclaim",
        "health-subclaim",
        "final-positive",
        "negative-control",
    ],
    "dhis2-programme-vc": [
        "discover",
        "evaluate-programme",
        "preview-vc",
        "reconcile",
        "negative-control",
        "render-cccev",
    ],
}
EXPECTED_STEP_STATUSES = {
    "alive-proof": {
        "discover": "done",
        "prepare-evidence": "done",
        "deny-row": "denied_as_expected",
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
    "dhis2-programme-vc": {
        "discover": "done",
        "evaluate-programme": "done",
        "preview-vc": "done",
        "reconcile": "done",
        "negative-control": "done",
        "render-cccev": "done",
    },
}

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


@dataclass(frozen=True)
class SmokeConfig:
    base_url: str = DEFAULT_BASE_URL
    credential_smoke: bool = False
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
    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

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
        request_headers = {"User-Agent": "registry-lab-hosted-smoke/1.0", **(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(url, headers=request_headers, data=data, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                return HttpJsonResponse(
                    status=response.status,
                    body=parse_json_body(raw),
                    headers={key.lower(): value for key, value in response.headers.items()},
                    url=url,
                    method=method,
                )
        except urllib.error.HTTPError as error:
            raw = error.read()
            return HttpJsonResponse(
                status=error.code,
                body=parse_json_body(raw),
                headers={key.lower(): value for key, value in error.headers.items()},
                url=url,
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


def run_smoke(config: SmokeConfig) -> dict[str, Any]:
    base_url = config.base_url.rstrip("/")
    client = JsonClient(config.timeout)

    health = client.get(joined_url(base_url, "/healthz"))
    require_ok(health, "healthz-unavailable")
    require(health_body_ok(health.body), "healthz-unexpected", health.body)

    catalogue = client.get(joined_url(base_url, "/api/scenarios.json"))
    require_ok(catalogue, "scenario-catalogue-unavailable")
    catalogue_ids = scenario_catalogue_ids(catalogue.body)
    for scenario_id in EXPECTED_STEPS:
        require(scenario_id in catalogue_ids, "scenario-missing", {"scenario": scenario_id, "seen": catalogue_ids})

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

    summary: dict[str, Any] = {
        "base_url": base_url,
        "checks": 1 + 1 + 1 + 1 + sum(len(steps) for steps in EXPECTED_STEP_STATUSES.values()) + len(EXPECTED_STEPS),
        "credential_smoke": "skipped",
        "scenarios": step_summaries,
        "stories": {key: len(value) for key, value in story_summaries.items()},
        "wallet_configuration": PERSON_ALIVE_CONFIGURATION,
    }
    if config.credential_smoke:
        summary["credential_smoke"] = run_credential_smoke(client, lab.body)
    return summary


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
    parser.add_argument("--credential-smoke", action="store_true")
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args(argv)
    return SmokeConfig(base_url=args.base_url, credential_smoke=args.credential_smoke, timeout=args.timeout)


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
