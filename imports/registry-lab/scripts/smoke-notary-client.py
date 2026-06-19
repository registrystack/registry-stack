#!/usr/bin/env python3
"""Exercise the Registry Notary Python client against the lab stack."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
from typing import Any


CLAIM_RESULT_JSON = "application/vnd.registry-notary.claim-result+json"
PURPOSE = "https://demo.example.gov/purpose/decentralized-evidence-demo"
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
    {
        "id": "NID-1010",
        "alive": True,
        "health": {"status": 403, "code": "pdp.evidence_stale"},
        "combined": {"status": 403, "code": "pdp.evidence_stale"},
    },
]


def fail(message: str) -> None:
    raise SystemExit(f"FAILED: {message}")


def load_dotenv(path: Path) -> None:
    if not path.exists():
        fail(f"missing {path}; run scripts/generate-demo-secrets.py first")
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        os.environ.setdefault(key, value)


def resolve_client_source(demo_dir: Path) -> Path:
    candidates = [
        os.environ.get("REGISTRY_NOTARY_CLIENT_SOURCE_DIR"),
        os.environ.get("REGISTRY_NOTARY_SOURCE_DIR"),
        str(demo_dir.parent / "registry-notary"),
        str(demo_dir / "vendor" / "registry-notary"),
    ]
    checked: list[str] = []
    for candidate in candidates:
        if not candidate:
            continue
        source = Path(candidate).expanduser().resolve()
        package_dir = source / "bindings" / "python"
        checked.append(str(package_dir))
        if (package_dir / "registry_notary" / "__init__.py").exists():
            sys.path.insert(0, str(package_dir))
            return source
    fail(
        "Registry Notary Python client was not found. "
        "Set REGISTRY_NOTARY_CLIENT_SOURCE_DIR to a Registry Notary checkout "
        f"that contains bindings/python. Checked: {', '.join(checked)}"
    )


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        fail(f"missing {name}; run just generate")
    return value


def check(name: str, fn: Any) -> Any:
    print(f"check: {name}")
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - smoke output should name the failed check.
        fail(f"{name}: {exc}")


def claim_ids(claims_response: dict[str, Any]) -> set[str]:
    data = claims_response.get("data")
    if not isinstance(data, list):
        fail("/v1/claims response did not contain data[]")
    ids = {item.get("id") for item in data if isinstance(item, dict)}
    return {item for item in ids if isinstance(item, str)}


def claim_by_id(claims_response: dict[str, Any], claim_id: str) -> dict[str, Any]:
    data = claims_response.get("data")
    if not isinstance(data, list):
        fail("/v1/claims response did not contain data[]")
    for item in data:
        if isinstance(item, dict) and item.get("id") == claim_id:
            return item
    fail(f"/v1/claims response did not include {claim_id}")


def result_for(response: dict[str, Any], expected_claim: str) -> dict[str, Any]:
    results = response.get("results") or response.get("claim_results")
    if not isinstance(results, list) or not results:
        fail("evaluation response did not contain results[]")
    for result in results:
        if isinstance(result, dict) and result.get("claim_id") == expected_claim:
            return result
    fail(f"evaluation response did not contain claim_id={expected_claim}")


def assert_boolean_result(response: dict[str, Any], expected_claim: str, expected: bool) -> dict[str, Any]:
    result = result_for(response, expected_claim)
    actual = result.get("satisfied")
    if actual is None:
        actual = result.get("value")
    if actual is not expected:
        fail(f"{expected_claim} expected {expected}, got {actual!r}")
    return result


def provenance_source_count(result: dict[str, Any]) -> int:
    provenance = result.get("provenance")
    if not isinstance(provenance, dict):
        return 0
    source_count = provenance.get("source_count")
    if isinstance(source_count, int):
        return source_count
    used = provenance.get("used")
    if isinstance(used, dict) and isinstance(used.get("source_count"), int):
        return used["source_count"]
    return 0


def assert_service_document(response: dict[str, Any], expected_service: str) -> None:
    actual = response.get("service_id") or response.get("id")
    if actual != expected_service:
        fail(f"service document expected {expected_service}, got {actual!r}")


def assert_jwks(response: dict[str, Any]) -> None:
    keys = response.get("keys")
    if not isinstance(keys, list) or not keys:
        fail("JWKS response did not contain keys[]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Smoke-test the Registry Notary Python client against lab Notary services."
    )
    parser.add_argument("--civil-url", default=os.environ.get("CIVIL_NOTARY_URL", "http://127.0.0.1:4321"))
    parser.add_argument("--shared-url", default=os.environ.get("SHARED_NOTARY_URL", "http://127.0.0.1:4323"))
    parser.add_argument("--output", default=os.environ.get("NOTARY_CLIENT_SMOKE_OUTPUT", "output/smoke-notary-client.json"))
    args = parser.parse_args()

    demo_dir = Path(__file__).resolve().parent.parent
    load_dotenv(demo_dir / ".env")
    client_source = resolve_client_source(demo_dir)

    from registry_notary import RegistryNotaryClient
    from registry_notary.errors import NotaryProblemError

    correlation_id = os.environ.get(
        "DEMO_CORRELATION_ID",
        f"registry-lab-notary-client-{int(time.time())}",
    )
    civil = RegistryNotaryClient(
        base_url=args.civil_url,
        api_key=require_env("CIVIL_EVIDENCE_CLIENT_TOKEN"),
        default_purpose=PURPOSE,
        user_agent="registry-lab-notary-client-smoke/0.1",
    )
    shared = RegistryNotaryClient(
        base_url=args.shared_url,
        bearer_token=require_env("SHARED_EVIDENCE_CLIENT_BEARER"),
        user_agent="registry-lab-notary-client-smoke/0.1",
    )

    artifact: dict[str, Any] = {
        "client_source": str(client_source),
        "checks": [],
    }

    def record(name: str, details: dict[str, Any] | None = None) -> None:
        artifact["checks"].append({"name": name, "ok": True, **(details or {})})

    def evaluate_or_expected_problem(name: str, fn: Any, expected: Any) -> Any:
        if not isinstance(expected, dict):
            return check(name, fn)
        print(f"check: {name} problem code")
        try:
            response = fn()
        except NotaryProblemError as exc:
            if exc.status != expected.get("status") or exc.code != expected.get("code"):
                fail(
                    f"{name}: expected problem {expected}, got "
                    f"status={exc.status!r} code={exc.code!r}"
                )
            return {"problem": {"status": exc.status, "code": exc.code, "request_id": exc.request_id}}
        fail(f"{name}: expected problem {expected}, got successful response {response!r}")

    service = check(
        "civil service discovery through client",
        lambda: civil.service_document(request_id=f"{correlation_id}-discovery"),
    )
    assert_service_document(service, "civil-notary")
    record("civil service discovery", {"service_id": service.get("service_id") or service.get("id")})

    jwks = check(
        "civil JWKS discovery through client",
        lambda: civil.issuer_jwks(request_id=f"{correlation_id}-jwks"),
    )
    assert_jwks(jwks)
    record("civil JWKS discovery", {"key_count": len(jwks.get("keys", []))})

    claims = check(
        "civil claims list through client",
        lambda: civil.list_claims(request_id=f"{correlation_id}-claims"),
    )
    ids = claim_ids(claims)
    if "person-is-alive" not in ids:
        fail("civil claims list did not include person-is-alive")
    alive_claim = claim_by_id(claims, "person-is-alive")
    if alive_claim.get("title") != "Vital Status Attestation":
        fail("civil person-is-alive claim did not expose the Vital Status Attestation title")
    record("civil claims list", {"claim_count": len(ids)})

    specific_claim = check(
        "civil get claim through client",
        lambda: civil.get_claim("person-is-alive", request_id=f"{correlation_id}-claim"),
    )
    if specific_claim.get("id") != "person-is-alive":
        fail("civil get claim returned the wrong claim")
    if specific_claim.get("title") != "Vital Status Attestation":
        fail("civil get claim did not expose the Vital Status Attestation title")
    record(
        "civil get claim",
        {"claim_id": specific_claim.get("id"), "title": specific_claim.get("title")},
    )

    shared_claims = check(
        "shared claims list through client",
        lambda: shared.list_claims(request_id=f"{correlation_id}-shared-claims"),
    )
    shared_expected_titles = {
        "social-program-active": "Program Enrollment Attestation",
        "health-service-available": "Service Availability Attestation",
        "eligible-for-combined-support": "Combined Support Eligibility Attestation",
    }
    for claim_id, title in shared_expected_titles.items():
        shared_claim = claim_by_id(shared_claims, claim_id)
        if shared_claim.get("title") != title:
            fail(f"{claim_id} expected title {title!r}, got {shared_claim.get('title')!r}")
    record("shared attestation-facing claim metadata", {"claim_count": len(shared_expected_titles)})

    matrix_results = []
    for case in V1_MATRIX:
        subject = case["id"]
        civil_evaluation = check(
            f"civil high-level evaluation through client for {subject}",
            lambda subject=subject: civil.evaluate(
                target_id=subject,
                identifier_scheme="national_id",
                claims=["person-is-alive"],
                request_id=f"{correlation_id}-civil-evaluate-{subject}",
            ),
        )
        civil_result = assert_boolean_result(civil_evaluation, "person-is-alive", case["alive"])
        matrix_results.append(
            {
                "subject": subject,
                "claim_id": "person-is-alive",
                "expected": case["alive"],
                "observed": civil_result.get("satisfied") if civil_result.get("satisfied") is not None else civil_result.get("value"),
                "provenance_source_count": provenance_source_count(civil_result),
            }
        )

        health_evaluation = evaluate_or_expected_problem(
            f"shared health evaluation through client for {subject}",
            lambda subject=subject: shared.evaluate_request(
                {
                    "target": {
                        "type": "Person",
                        "identifiers": [{"scheme": "national_id", "value": subject}],
                    },
                    "claims": ["health-service-available"],
                    "disclosure": "predicate",
                    "format": CLAIM_RESULT_JSON,
                    "purpose": PURPOSE,
                },
                request_id=f"{correlation_id}-health-evaluate-{subject}",
            ),
            case["health"],
        )
        if isinstance(case["health"], dict):
            matrix_results.append(
                {
                    "subject": subject,
                    "claim_id": "health-service-available",
                    "expected_problem": case["health"],
                    "observed_problem": health_evaluation["problem"],
                }
            )
        else:
            health_result = assert_boolean_result(health_evaluation, "health-service-available", case["health"])
            matrix_results.append(
                {
                    "subject": subject,
                    "claim_id": "health-service-available",
                    "expected": case["health"],
                    "observed": health_result.get("satisfied") if health_result.get("satisfied") is not None else health_result.get("value"),
                    "provenance_source_count": provenance_source_count(health_result),
                }
            )

        shared_evaluation = evaluate_or_expected_problem(
            f"shared combined-support evaluation through client for {subject}",
            lambda subject=subject: shared.evaluate_request(
                {
                    "target": {
                        "type": "Person",
                        "identifiers": [{"scheme": "national_id", "value": subject}],
                    },
                    "claims": ["eligible-for-combined-support"],
                    "disclosure": "predicate",
                    "format": CLAIM_RESULT_JSON,
                    "purpose": PURPOSE,
                },
                request_id=f"{correlation_id}-shared-evaluate-{subject}",
            ),
            case["combined"],
        )
        if isinstance(case["combined"], dict):
            matrix_results.append(
                {
                    "subject": subject,
                    "claim_id": "eligible-for-combined-support",
                    "expected_problem": case["combined"],
                    "observed_problem": shared_evaluation["problem"],
                }
            )
            continue
        shared_result = assert_boolean_result(shared_evaluation, "eligible-for-combined-support", case["combined"])
        source_count = provenance_source_count(shared_result)
        if case["combined"] and (not isinstance(source_count, int) or source_count < 2):
            fail(f"shared evaluation expected at least 2 sources for {subject}, got {source_count!r}")
        matrix_results.append(
            {
                "subject": subject,
                "claim_id": "eligible-for-combined-support",
                "expected": case["combined"],
                "observed": shared_result.get("satisfied") if shared_result.get("satisfied") is not None else shared_result.get("value"),
                "provenance_source_count": source_count,
            }
        )

    record(
        "v1 Notary outcome matrix",
        {
            "subject_count": len(V1_MATRIX),
            "claim_result_count": len(matrix_results),
            "results": matrix_results,
        },
    )

    def missing_claim() -> None:
        try:
            civil.get_claim("__missing_client_smoke_claim__", request_id=f"{correlation_id}-missing")
        except NotaryProblemError as exc:
            if exc.status != 404:
                fail(f"missing claim expected 404, got {exc.status}")
            return
        fail("missing claim unexpectedly succeeded")

    check("problem error mapping through client", missing_claim)
    record("problem error mapping", {"status": 404})

    output_path = (demo_dir / args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Registry Notary client smoke OK: {output_path}")


if __name__ == "__main__":
    main()
