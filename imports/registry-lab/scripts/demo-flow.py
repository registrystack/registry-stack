#!/usr/bin/env python3
"""Narrated client flow for the decentralized evidence demo."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PURPOSE = "https://demo.example.gov/purpose/decentralized-evidence-demo"
CLAIM_RESULT_FORMAT = "application/vnd.registry-notary.claim-result+json"
CCCEV_FORMAT = 'application/ld+json; profile="cccev"'
SD_JWT_FORMAT = "application/dc+sd-jwt"
CORRELATION_ID = os.environ.get("DEMO_CORRELATION_ID", "decentralized-demo-correlation-001")
V1_MATRIX = [
    {"id": "NID-1001", "alive": True, "health": True, "combined": True},
    {"id": "NID-1002", "alive": True, "health": False, "combined": False},
    {"id": "NID-1003", "alive": False, "health": True, "combined": False},
    {"id": "NID-1004", "alive": True, "health": True, "combined": True},
    {"id": "NID-1005", "alive": True, "health": False, "combined": False},
    {"id": "NID-1006", "alive": True, "health": True, "combined": True},
    {"id": "NID-1007", "alive": True, "health": True, "combined": False},
    {"id": "NID-1008", "alive": True, "health": True, "combined": True},
    {"id": "NID-1009", "alive": True, "health": True, "combined": False},
    {"id": "NID-1010", "alive": True, "health": False, "combined": False},
]
# The full matrix above covers all subjects. Keep the batch proof smaller so a
# single request does not saturate Notary's intentional no-queue CEL worker pool.
BATCH_MATRIX = V1_MATRIX[:3]
PRIMARY_SUBJECT = V1_MATRIX[0]["id"]

DEMO_HOLDER_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINpAgYVDwfGjJ/3AJ6IKwVqB8vpnxoX4E4RbnLSFarM+
-----END PRIVATE KEY-----
"""

DEMO_HOLDER_PUBLIC_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "gpb08DSqiqOybeHIDCLRcPdnDbhGL1ypfkLEFd977d8",
    "alg": "EdDSA",
}


@dataclass(frozen=True)
class Service:
    name: str
    url: str
    token_env: str


@dataclass
class HttpResult:
    status: int
    body: Any
    headers: dict[str, str]


class DemoError(RuntimeError):
    pass


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise DemoError(f"missing required environment variable: {name}")
    return value


def output_dir() -> Path:
    path = Path(os.environ.get("DEMO_OUTPUT_DIR", "output"))
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
    timeout: int = 15,
) -> HttpResult:
    req_headers = {
        "Accept": "*/*",
        "x-request-id": CORRELATION_ID,
    }
    if token:
        req_headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        req_headers["Content-Type"] = "application/json"
    if headers:
        req_headers.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HttpResult(resp.status, parse_body(resp.read()), dict(resp.headers))
    except urllib.error.HTTPError as exc:
        return HttpResult(exc.code, parse_body(exc.read()), dict(exc.headers))
    except urllib.error.URLError as exc:
        raise DemoError(f"{method} {url} failed: {exc}") from exc


def save(out: Path, index: int, label: str, payload: Any) -> Path:
    path = out / f"{index:02d}-{label}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"    artifact: {path}")
    return path


def require(result: HttpResult, expected: int, label: str) -> Any:
    if result.status != expected:
        raise DemoError(f"{label} returned HTTP {result.status}, expected {expected}: {result.body}")
    return result.body


def require_problem_code(result: HttpResult, expected_status: int, expected_code: str, label: str) -> None:
    if result.status != expected_status:
        raise DemoError(f"{label} returned HTTP {result.status}, expected {expected_status}: {result.body}")
    if not isinstance(result.body, dict) or result.body.get("code") != expected_code:
        raise DemoError(f"{label} returned problem code {result.body!r}, expected {expected_code}")


def wait_for(label: str, fn, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    last = "not attempted"
    while time.time() < deadline:
        try:
            fn()
            print(f"  ready: {label}")
            return
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            time.sleep(2)
    raise DemoError(f"timed out waiting for {label}: {last}")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def holder_did() -> str:
    did_jwk = {key: DEMO_HOLDER_PUBLIC_JWK[key] for key in ("crv", "kty", "x")}
    encoded = b64url(json.dumps(did_jwk, separators=(",", ":"), sort_keys=True).encode())
    return f"did:jwk:{encoded}"


def sign_holder_proof(
    evaluation_id: str,
    credential_profile: str,
    claims: list[str],
    disclosure: str,
    audience: str,
) -> tuple[str, str]:
    if shutil.which("openssl") is None:
        raise DemoError("openssl is required for the demo holder proof")
    holder_id = holder_did()
    now = int(time.time())
    jti = b64url(hashlib.sha256(f"{holder_id}:{evaluation_id}:{time.time_ns()}".encode()).digest()[:16])
    header = b64url(json.dumps({"alg": "EdDSA", "typ": "kb+jwt", "kid": holder_id}, separators=(",", ":")).encode())
    payload = b64url(
        json.dumps(
            {
                "sub": holder_id,
                "aud": audience,
                "exp": now + 300,
                "iat": now,
                "jti": jti,
                "evaluation_id": evaluation_id,
                "credential_profile": credential_profile,
                "disclosure": b64url(hashlib.sha256(disclosure.encode("utf-8")).digest()),
                "claims": claims,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        key_path = tmp_path / "holder.pem"
        input_path = tmp_path / "input"
        sig_path = tmp_path / "signature"
        key_path.write_text(DEMO_HOLDER_PRIVATE_KEY, encoding="utf-8")
        input_path.write_bytes(signing_input)
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(key_path), "-rawin", "-in", str(input_path), "-out", str(sig_path)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return holder_id, f"{signing_input.decode('ascii')}.{b64url(sig_path.read_bytes())}"


def first_result_id(evaluation: dict[str, Any]) -> str:
    results = evaluation.get("results") or evaluation.get("claim_results") or []
    if not results:
        raise DemoError(f"evaluation response has no results: {evaluation}")
    evaluation_id = results[0].get("evaluation_id")
    if not evaluation_id:
        raise DemoError(f"evaluation response has no evaluation_id: {evaluation}")
    return evaluation_id


def result_for(evaluation: dict[str, Any], expected_claim: str) -> dict[str, Any]:
    results = evaluation.get("results") or evaluation.get("claim_results") or []
    if not results:
        raise DemoError(f"evaluation response has no results: {evaluation}")
    for result in results:
        if isinstance(result, dict) and result.get("claim_id") == expected_claim:
            return result
    raise DemoError(f"evaluation response has no result for {expected_claim}: {evaluation}")


def require_boolean_result(evaluation: dict[str, Any], claim: str, expected: bool, label: str) -> dict[str, Any]:
    result = result_for(evaluation, claim)
    observed = result.get("satisfied")
    if observed is None:
        observed = result.get("value")
    if observed is not expected:
        raise DemoError(f"{label} expected {claim}={expected}, got {observed!r}: {result}")
    return result


def first_data_row(response: dict[str, Any], label: str) -> dict[str, Any]:
    rows = response.get("data") if isinstance(response, dict) else None
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise DemoError(f"{label} response has no first data row: {response}")
    return rows[0]


def household_benefit_decision(row_response: dict[str, Any], aggregate_response: dict[str, Any]) -> dict[str, Any]:
    household = first_data_row(row_response, "household row read")
    eligibility_band = str(household.get("eligibility_band", "unknown"))
    active_members = int(household.get("active_members", 0))
    deceased_members = int(household.get("deceased_member_count", 0))
    poverty_score = float(household.get("poverty_score", 100.0))
    base_amount = {"priority": 120, "standard": 75}.get(eligibility_band, 0)
    adjustment = -25 * deceased_members
    recommended_amount = max(0, base_amount + adjustment)
    return {
        "artifact_type": "demo.household-benefit-decision.v1",
        "correlation_id": CORRELATION_ID,
        "subject": {
            "household_id": household.get("id"),
            "national_id": household.get("national_id"),
            "district": household.get("district"),
        },
        "inputs": {
            "eligibility_band": eligibility_band,
            "poverty_score": poverty_score,
            "active_members": active_members,
            "deceased_member_count": deceased_members,
            "aggregate_id": aggregate_response.get("aggregate_id"),
            "aggregate_groups_seen": len(aggregate_response.get("data", [])),
        },
        "decision": {
            "status": "approved" if recommended_amount > 0 and active_members > 0 else "manual_review",
            "recommended_monthly_amount": recommended_amount,
            "currency": "DEMO",
            "reason_codes": [
                f"eligibility_band:{eligibility_band}",
                f"active_members:{active_members}",
                f"deceased_member_count:{deceased_members}",
            ],
        },
        "boundary": {
            "computed_by": "demo-client",
            "relay_write_back": False,
            "source_rows_embedded": False,
        },
    }


def evaluate_payload(subject: str, claims: list[str], disclosure: str = "predicate", fmt: str = CLAIM_RESULT_FORMAT) -> dict[str, Any]:
    return {
        "target": {
            "type": "Person",
            "identifiers": [{"scheme": "national_id", "value": subject}],
        },
        "claims": claims,
        "disclosure": disclosure,
        "format": fmt,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args()
    out = args.output_dir or output_dir()

    relays = [
        Service("civil", env("CIVIL_RELAY_URL", "http://127.0.0.1:4311"), "CIVIL_METADATA_CLIENT_RAW"),
        Service("social", env("SOCIAL_RELAY_URL", "http://127.0.0.1:4312"), "SOCIAL_METADATA_CLIENT_RAW"),
        Service("health", env("HEALTH_RELAY_URL", "http://127.0.0.1:4313"), "HEALTH_METADATA_CLIENT_RAW"),
    ]
    evidence = [
        Service("civil", env("CIVIL_EVIDENCE_URL", "http://127.0.0.1:4321"), "CIVIL_EVIDENCE_CLIENT_BEARER"),
        Service("social", env("SOCIAL_EVIDENCE_URL", "http://127.0.0.1:4322"), "SOCIAL_EVIDENCE_CLIENT_BEARER"),
        Service("shared", env("SHARED_EVIDENCE_URL", "http://127.0.0.1:4323"), "SHARED_EVIDENCE_CLIENT_BEARER"),
    ]
    static_url = env("STATIC_METADATA_URL", "http://127.0.0.1:4331")

    print("Decentralized evidence demo")
    print(f"  correlation id: {CORRELATION_ID}")
    print(f"  artifacts: {out}")

    for relay in relays:
        wait_for(f"{relay.name} relay /ready", lambda r=relay: require(request("GET", r.url, "/ready", env(r.token_env)), 200, f"{r.name} ready"))
    for service in evidence:
        wait_for(
            f"{service.name} evidence discovery",
            lambda s=service: require(request("GET", s.url, "/.well-known/evidence-service", env(s.token_env)), 200, f"{s.name} discovery"),
        )
    wait_for("static metadata index", lambda: require(request("GET", static_url, "/metadata/index.json", None), 200, "static metadata index"))

    step = 1
    discovered_urls: set[str] = set()
    for relay in relays:
        token = env(relay.token_env)
        print(f"\n{step}. Discover {relay.name} registry metadata")
        body = require(request("GET", relay.url, "/metadata", token), 200, f"{relay.name} metadata")
        save(out, step, f"{relay.name}-metadata", body)
        step += 1

        body = require(request("GET", relay.url, "/v1/datasets", token), 200, f"{relay.name} datasets")
        save(out, step, f"{relay.name}-datasets", body)
        step += 1

        offerings = require(request("GET", relay.url, "/metadata/evidence-offerings", token), 200, f"{relay.name} offerings")
        save(out, step, f"{relay.name}-evidence-offerings", offerings)
        for offering in offerings.get("evidence_offerings", offerings.get("data", [])) if isinstance(offerings, dict) else []:
            access = offering.get("access", {})
            if isinstance(access, dict) and access.get("discovery_url"):
                discovered_urls.add(access["discovery_url"])
        step += 1

        openapi = require(request("GET", relay.url, "/openapi.json"), 200, f"{relay.name} OpenAPI")
        save(out, step, f"{relay.name}-relay-openapi", openapi)
        step += 1

    print(f"\n{step}. Fetch static metadata bundle")
    static_index = require(request("GET", static_url, "/metadata/index.json", None), 200, "static metadata index")
    save(out, step, "static-metadata-index", static_index)
    step += 1
    static_offerings = require(request("GET", static_url, "/metadata/evidence-offerings.json", None), 200, "static offerings")
    save(out, step, "static-evidence-offerings", static_offerings)
    step += 1
    policies = require(request("GET", static_url, "/metadata/policies.jsonld", None), 200, "static policies")
    save(out, step, "static-policies", policies)
    step += 1

    for offering in static_offerings.get("evidence_offerings", static_offerings.get("data", [])) if isinstance(static_offerings, dict) else []:
        access = offering.get("access", {})
        if isinstance(access, dict) and access.get("discovery_url"):
            discovered_urls.add(access["discovery_url"])
    save(out, step, "discovered-evidence-urls", {"discovery_urls": sorted(discovered_urls)})
    step += 1

    for service in evidence:
        token = env(service.token_env)
        discovery = require(request("GET", service.url, "/.well-known/evidence-service", token), 200, f"{service.name} discovery")
        save(out, step, f"{service.name}-evidence-discovery", discovery)
        step += 1
        openapi = require(request("GET", service.url, "/openapi.json"), 200, f"{service.name} Evidence Server OpenAPI")
        save(out, step, f"{service.name}-evidence-openapi", openapi)
        step += 1
        claims = require(request("GET", service.url, "/v1/claims", token), 200, f"{service.name} claims")
        save(out, step, f"{service.name}-claims", claims)
        step += 1

    row_denial = request(
        "GET",
        relays[1].url,
        "/v1/datasets/social_protection_registry/entities/household/records?limit=1",
        env("SOCIAL_EVIDENCE_ONLY_RAW"),
        headers={"Data-Purpose": PURPOSE},
    )
    save(out, step, "row-denial-evidence-only", {"status": row_denial.status, "body": row_denial.body})
    require_problem_code(row_denial, 403, "auth.scope_denied", "evidence-only row denial")
    step += 1

    row = require(
        request(
            "GET",
            relays[1].url,
            "/v1/datasets/social_protection_registry/entities/household/records?limit=1",
            env("SOCIAL_ROW_READER_RAW"),
            headers={"Data-Purpose": PURPOSE},
        ),
        200,
        "positive social row read",
    )
    save(out, step, "positive-social-row-read", row)
    step += 1

    aggregate = require(
        request(
            "GET",
            relays[1].url,
            "/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band",
            env("SOCIAL_AGGREGATE_READER_RAW"),
            headers={"Data-Purpose": PURPOSE},
        ),
        200,
        "positive social aggregate list",
    )
    save(out, step, "positive-social-aggregate", aggregate)
    step += 1

    aggregate_denial = request(
        "GET",
        relays[1].url,
        "/v1/datasets/social_protection_registry/aggregates/households_by_eligibility_band",
        env("SOCIAL_ROW_READER_RAW"),
        headers={"Data-Purpose": PURPOSE},
    )
    save(out, step, "aggregate-denial-row-reader-only", {"status": aggregate_denial.status, "body": aggregate_denial.body})
    require_problem_code(aggregate_denial, 403, "auth.scope_denied", "row-reader aggregate denial")
    step += 1

    edr_area_path = "/ogc/edr/v1/collections/social_protection_households_by_district/area?" + urllib.parse.urlencode(
        {
            "coords": "POLYGON((-0.5 0.5,1.5 0.5,1.5 1.5,-0.5 1.5,-0.5 0.5))",
            "parameter-name": "household_count",
            "group_by": "district",
            "f": "geojson",
        }
    )
    edr_area = require(
        request(
            "GET",
            relays[1].url,
            edr_area_path,
            env("SOCIAL_AGGREGATE_READER_RAW"),
            headers={"Data-Purpose": PURPOSE},
        ),
        200,
        "positive social EDR area aggregate",
    )
    save(out, step, "positive-social-edr-area", edr_area)
    step += 1

    decision = household_benefit_decision(row, aggregate)
    save(out, step, "household-benefit-decision", decision)
    step += 1

    eval_specs = [
        (evidence[0], "civil-claim-evaluation", ["person-is-alive"], PRIMARY_SUBJECT, "predicate", CLAIM_RESULT_FORMAT),
        (evidence[1], "social-claim-evaluation", ["program-enrollment-status"], PRIMARY_SUBJECT, "value", CLAIM_RESULT_FORMAT),
        (evidence[2], "health-claim-evaluation", ["health-service-available"], PRIMARY_SUBJECT, "predicate", CLAIM_RESULT_FORMAT),
        (evidence[2], "shared-cross-source-evaluation", ["eligible-for-combined-support"], PRIMARY_SUBJECT, "predicate", CLAIM_RESULT_FORMAT),
    ]
    first_eval: dict[str, Any] | None = None
    for service, label, claims, subject, disclosure, fmt in eval_specs:
        result = require(
            request(
                "POST",
                service.url,
                "/v1/evaluations",
                env(service.token_env),
                evaluate_payload(subject, claims, disclosure, fmt),
                {"Data-Purpose": PURPOSE, "Accept": fmt},
            ),
            200,
            label,
        )
        save(out, step, label, result)
        first_eval = first_eval or result
        step += 1

    matrix_results = []
    matrix_claims = [
        (evidence[0], "person-is-alive", "alive"),
        (evidence[2], "health-service-available", "health"),
        (evidence[2], "eligible-for-combined-support", "combined"),
    ]
    for case in V1_MATRIX:
        subject = str(case["id"])
        for service, claim, expected_key in matrix_claims:
            expected = bool(case[expected_key])
            label = f"v1 matrix {claim} {subject}"
            result = require(
                request(
                    "POST",
                    service.url,
                    "/v1/evaluations",
                    env(service.token_env),
                    evaluate_payload(subject, [claim], "predicate", CLAIM_RESULT_FORMAT),
                    {"Data-Purpose": PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
                ),
                200,
                label,
            )
            claim_result = require_boolean_result(result, claim, expected, label)
            matrix_results.append(
                {
                    "subject": subject,
                    "claim_id": claim,
                    "expected": expected,
                    "observed": claim_result.get("satisfied")
                    if claim_result.get("satisfied") is not None
                    else claim_result.get("value"),
                    "provenance_source_count": claim_result.get("provenance", {}).get("source_count"),
                }
            )
    save(
        out,
        step,
        "v1-notary-outcome-matrix",
        {
            "subjects": [case["id"] for case in V1_MATRIX],
            "results": matrix_results,
        },
    )
    step += 1

    missing = request(
        "POST",
        evidence[2].url,
        "/v1/evaluations",
        env(evidence[2].token_env),
        evaluate_payload("NID-9999", ["eligible-for-combined-support"]),
        {"Data-Purpose": PURPOSE, "Accept": CLAIM_RESULT_FORMAT},
    )
    save(out, step, "missing-subject-evaluation", {"status": missing.status, "body": missing.body})
    step += 1

    batch = require(
        request(
            "POST",
            evidence[2].url,
            "/v1/batch-evaluations",
            env(evidence[2].token_env),
            {
                "items": [
                    {
                        "target": {
                            "type": "Person",
                            "identifiers": [{"scheme": "national_id", "value": subject}],
                        }
                    }
                    for subject in [case["id"] for case in BATCH_MATRIX]
                ],
                "claims": ["eligible-for-combined-support"],
                "disclosure": "predicate",
                "format": CLAIM_RESULT_FORMAT,
            },
            {"Data-Purpose": PURPOSE, "Idempotency-Key": f"{CORRELATION_ID}-batch"},
        ),
        200,
        "batch evaluation",
    )
    save(out, step, "batch-evaluation", batch)
    step += 1
    batch_items = batch.get("items") if isinstance(batch, dict) else None
    if not isinstance(batch_items, list) or len(batch_items) < len(BATCH_MATRIX):
        raise DemoError(f"batch evaluation expected at least {len(BATCH_MATRIX)} items, got {len(batch_items or [])}")
    for index, case in enumerate(BATCH_MATRIX):
        item = batch_items[index]
        if not isinstance(item, dict) or item.get("status") != "succeeded":
            raise DemoError(f"batch evaluation for {case['id']} did not succeed: {item}")
        claim_result = result_for({"results": item.get("claim_results", [])}, "eligible-for-combined-support")
        observed = claim_result.get("satisfied")
        if observed is None:
            observed = claim_result.get("value")
        if observed is not case["combined"]:
            raise DemoError(f"batch evaluation for {case['id']} expected combined={case['combined']}, got {observed!r}")

    cccev_eval = require(
        request(
            "POST",
            evidence[0].url,
            "/v1/evaluations",
            env(evidence[0].token_env),
            evaluate_payload(PRIMARY_SUBJECT, ["person-is-alive"], "predicate", CCCEV_FORMAT),
            {"Data-Purpose": PURPOSE, "Accept": CCCEV_FORMAT},
        ),
        200,
        "CCCEV-bound evaluation",
    )
    save(out, step, "cccev-bound-evaluation", cccev_eval)
    step += 1
    evaluation_id = first_result_id(cccev_eval)
    cccev = require(
        request(
            "POST",
            evidence[0].url,
            f"/v1/evaluations/{evaluation_id}/render",
            env(evidence[0].token_env),
            {"claims": ["person-is-alive"], "disclosure": "predicate", "format": CCCEV_FORMAT},
        ),
        200,
        "CCCEV render",
    )
    save(out, step, "cccev-render", cccev)
    step += 1

    credential_eval = require(
        request(
            "POST",
            evidence[0].url,
            "/v1/evaluations",
            env(evidence[0].token_env),
            evaluate_payload(PRIMARY_SUBJECT, ["person-is-alive"], "predicate", SD_JWT_FORMAT),
            {"Data-Purpose": PURPOSE, "Accept": SD_JWT_FORMAT},
        ),
        200,
        "credential-bound evaluation",
    )
    save(out, step, "credential-bound-evaluation", credential_eval)
    step += 1
    holder_id, proof = sign_holder_proof(
        first_result_id(credential_eval),
        "life_stage_sd_jwt",
        ["person-is-alive"],
        "predicate",
        "civil-notary",
    )
    credential = require(
        request(
            "POST",
            evidence[0].url,
            "/v1/credentials",
            env(evidence[0].token_env),
            {
                "evaluation_id": first_result_id(credential_eval),
                "credential_profile": "life_stage_sd_jwt",
                "format": SD_JWT_FORMAT,
                "claims": ["person-is-alive"],
                "disclosure": "predicate",
                "holder": {"binding": "did", "id": holder_id, "proof": proof},
            },
        ),
        200,
        "credential issuance",
    )
    save(out, step, "demo-credential", credential)
    step += 1

    scenario_summary = {
        "correlation_id": CORRELATION_ID,
        "scenarios": {
            "Birth Registration To Child Support": {
                "human_journey": "A caregiver applies for support and civil facts are verified without exposing the civil registry row.",
                "system_lane": [
                    "civil Relay metadata/evidence offering discovery",
                    "civil Evidence Server discovery and OpenAPI",
                    "DCI-backed civil claim evaluation",
                    "CCCEV render",
                    "demo-grade credential issuance",
                ],
                "artifact_labels": [
                    "civil-evidence-offerings",
                    "civil-evidence-discovery",
                    "civil-evidence-openapi",
                    "civil-claim-evaluation",
                    "cccev-render",
                    "demo-credential",
                ],
            },
            "Household Benefit Review From Registry Data": {
                "human_journey": "A household benefit case is reviewed from protected registry consultation, then the client computes a decision outside Relay.",
                "system_lane": [
                    "social protection Relay metadata discovery",
                    "row read with row-reader credential and Data-Purpose",
                    "aggregate read with aggregate-reader credential and Data-Purpose",
                    "EDR area aggregate over configured district geometry",
                    "evidence-only row denial",
                    "row-reader aggregate denial",
                    "demo client decision artifact with no Relay write-back",
                ],
                "artifact_labels": [
                    "positive-social-row-read",
                    "positive-social-aggregate",
                    "positive-social-edr-area",
                    "row-denial-evidence-only",
                    "aggregate-denial-row-reader-only",
                    "household-benefit-decision",
                ],
            },
            "Cross-Authority Conditional Health Support": {
                "human_journey": "Static metadata leads the client to a shared verifier that composes civil, social protection, and health facts.",
                "system_lane": [
                    "static metadata index/offering/policy discovery",
                    "shared Evidence Server discovery and OpenAPI",
                    "health-backed claim evaluation",
                    "cross-source CEL evaluation",
                    "full v1 Notary outcome matrix",
                    "batch evaluation with mixed v1 outcomes",
                    "missing-subject failure",
                ],
                "artifact_labels": [
                    "static-metadata-index",
                    "static-evidence-offerings",
                    "static-policies",
                    "shared-evidence-discovery",
                    "shared-evidence-openapi",
                    "health-claim-evaluation",
                    "shared-cross-source-evaluation",
                    "v1-notary-outcome-matrix",
                    "batch-evaluation",
                    "missing-subject-evaluation",
                ],
            },
        },
        "notes": [
            "Evidence Servers call Relay over HTTP only.",
            "Static metadata was fetched before shared eligibility evaluation.",
            "OpenAPI was fetched without demo credentials; data and evidence routes stayed authenticated.",
        ],
    }
    save(out, step, "scenario-summary", scenario_summary)

    print("\nDemo flow complete.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoError as exc:
        print(f"demo-flow failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
