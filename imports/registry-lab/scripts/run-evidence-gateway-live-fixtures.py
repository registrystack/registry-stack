#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run live evidence-gateway fixture proofs against Lab Notary services.

The static fixture checker validates the declarative evidence-gateway contract.
This runner proves the parts the current live Lab runtime can actually execute
and reports the remaining golden fixture gates as explicit blockers. In strict
mode, those blockers fail the run.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "config" / "evidence-gateway"
CLAIM_RESULT_JSON = "application/vnd.registry-notary.claim-result+json"
SD_JWT_VC = "application/dc+sd-jwt"
LIVE_REQUEST_KEYS = {
    "requester",
    "target",
    "relationship",
    "on_behalf_of",
    "claims",
    "disclosure",
    "format",
    "purpose",
}
AUDIT_FIELD_ALIASES = {
    "binding_id": ("binding_id", "ecosystem_binding_id", "matching_binding_id", "ecosystem_binding.id"),
    "binding_version": (
        "binding_version",
        "ecosystem_binding_version",
        "matching_binding_version",
        "ecosystem_binding.version",
    ),
    "policy_id": ("policy_id", "matching_policy_id", "pdp_policy_id"),
    "policy_hash": ("policy_hash", "matching_policy_hash", "pdp_policy_hash"),
    "evaluated_rule_ids": ("evaluated_rule_ids", "matching_evaluated_rule_ids", "pdp_evaluated_rule_ids"),
    "redacted_fields": ("redacted_fields", "redaction.redacted_fields"),
    "request_provenance": ("request_provenance",),
    "target_ref_hash": (
        "target_ref_hash",
        "target_hash",
        "target.ref_hash",
        "target.hash",
        "target_ref.hash",
        "request_provenance.target_ref_hash",
        "request_provenance.target_hash",
        "request_provenance.target_ref.hash",
        "request_provenance.target.hash",
    ),
    "request_ref_hash": (
        "request_ref_hash",
        "request_hash",
        "claim_hash",
        "request.ref_hash",
        "request.hash",
        "request_ref.hash",
        "request_provenance.request_ref_hash",
        "request_provenance.request_hash",
        "request_provenance.request_ref.hash",
        "request_provenance.request.hash",
    ),
    "correlation_ref_hash": (
        "correlation_ref_hash",
        "correlation_hash",
        "correlation_id_hash",
        "correlation.ref_hash",
        "correlation.hash",
        "correlation_ref.hash",
        "request_provenance.correlation_ref_hash",
        "request_provenance.correlation_hash",
        "request_provenance.correlation_ref.hash",
        "request_provenance.correlation.hash",
    ),
    "requester_ref_hash": (
        "requester_ref_hash",
        "requester_hash",
        "requester.ref_hash",
        "requester.hash",
        "requester_ref.hash",
        "request_provenance.requester_ref_hash",
        "request_provenance.requester_hash",
        "request_provenance.requester_ref.hash",
        "request_provenance.requester.hash",
    ),
    "decision": ("policy_decision", "pdp_decision", "verification_decision", "decision"),
}
REQUEST_ID_ALIASES = (
    "request_id",
    "correlation_id",
    "x_request_id",
    "x-request-id",
    "headers.x-request-id",
    "headers.X-Request-Id",
)
SOURCE_READ_ALIASES = ("source_read_count", "source_reads_count", "sources_read", "source_count")
SOURCE_READ_LIST_ALIASES = ("source_reads", "sources_read")
FORWARD_EVIDENCE_ALIASES = (
    "forwarded",
    "forwarded_to",
    "forwarded_fields",
    "forwarded_claims",
    "forwarded_payload",
    "upstream_forwarded",
)
BINDING_QUALIFIED_RULE_PREFIX = "source-binding-policy:"
BINDING_QUALIFIED_RULE_GATES = {
    "policy_identity",
    "odrl_terms",
    "purpose",
    "jurisdiction",
    "assurance_allowed_set",
    "minimum_assurance",
    "source_freshness",
    "legal_basis_required",
    "consent_required",
    "legal_basis_allowed_set",
    "consent_allowed_set",
    "relationship",
    "relationship_purpose",
    "requested_fact",
    "requested_disclosure",
    "credential_format",
    "source_binding",
    "route_identity",
    "checked_scope",
    "redaction",
}


@dataclass(frozen=True)
class ProfileRuntime:
    profile: str
    base_url: str
    token: str
    auth: str
    subject_override: str | None


class LiveFixtureError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        body = json.load(fh)
    if not isinstance(body, dict):
        raise LiveFixtureError(f"{path} must contain a JSON object")
    return body


def problem(message: str) -> None:
    raise LiveFixtureError(message)


def profile_slug(profile: str) -> str:
    return profile.replace("/", ".")


def golden_path(profile: str) -> Path:
    return FIXTURE_ROOT / "golden" / f"{profile_slug(profile)}.json"


def default_base_url(profile: str) -> str:
    if profile == "baseline-dpi/v1":
        return os.environ.get("SHARED_NOTARY_URL", "http://127.0.0.1:4323")
    if profile == "sp-dci/v1":
        port = os.environ.get("OPENCRVS_DCI_NOTARY_PORT", "4352")
        return os.environ.get("OPENCRVS_DCI_NOTARY_URL", f"http://127.0.0.1:{port}")
    problem(f"unsupported profile {profile!r}")


def default_token_and_auth(profile: str) -> tuple[str, str]:
    if profile == "baseline-dpi/v1":
        bearer = os.environ.get("SHARED_EVIDENCE_CLIENT_BEARER")
        if bearer:
            return bearer, "bearer"
        api_key = os.environ.get("SHARED_EVIDENCE_CLIENT_TOKEN")
        if api_key:
            return api_key, "api-key"
        problem("missing SHARED_EVIDENCE_CLIENT_BEARER or SHARED_EVIDENCE_CLIENT_TOKEN")
    if profile == "sp-dci/v1":
        token = os.environ.get("OPENCRVS_EVIDENCE_CLIENT_TOKEN")
        if token:
            return token, "api-key"
        problem("missing OPENCRVS_EVIDENCE_CLIENT_TOKEN")
    problem(f"unsupported profile {profile!r}")


def default_subject_override(profile: str) -> str | None:
    if profile == "sp-dci/v1":
        return os.environ.get("OPENCRVS_DEMO_SUBJECT_UIN")
    return None


def negative_token_env(profile: str, code: str) -> str | None:
    prefix = {
        "baseline-dpi/v1": "SHARED_EVIDENCE",
        "sp-dci/v1": "OPENCRVS_EVIDENCE",
    }.get(profile)
    suffix = {
        "pdp.assurance_insufficient": "DENY_ASSURANCE_TOKEN",
        "pdp.jurisdiction_not_permitted": "DENY_JURISDICTION_TOKEN",
        "pdp.legal_basis_required": "DENY_LEGAL_BASIS_TOKEN",
        "pdp.consent_required": "DENY_CONSENT_TOKEN",
    }.get(code)
    if not prefix or not suffix:
        return None
    return f"{prefix}_{suffix}"


def runtime_for_case(runtime: ProfileRuntime, case: dict[str, Any]) -> ProfileRuntime:
    code = case.get("expected", {}).get("problem", {}).get("code")
    if not isinstance(code, str):
        return runtime
    env_name = negative_token_env(runtime.profile, code)
    if not env_name:
        return runtime
    token = os.environ.get(env_name)
    if not token:
        problem(f"{case.get('id')} requires {env_name} for live negative gate")
    return ProfileRuntime(
        profile=runtime.profile,
        base_url=runtime.base_url,
        token=token,
        auth="api-key",
        subject_override=runtime.subject_override,
    )


def json_request(
    runtime: ProfileRuntime,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    *,
    purpose: str | None = None,
    request_id: str | None = None,
    accept: str = "*/*",
) -> tuple[int, dict[str, Any], str]:
    url = runtime.base_url.rstrip("/") + path
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {
        "accept": accept,
        "x-request-id": request_id or f"evidence-gateway-live-{int(time.time())}",
    }
    if payload is not None:
        headers["content-type"] = "application/json"
    if purpose:
        headers["data-purpose"] = purpose
    if runtime.auth == "bearer":
        headers["authorization"] = f"Bearer {runtime.token}"
    elif runtime.auth == "api-key":
        headers["x-api-key"] = runtime.token
    else:
        problem(f"unsupported auth mode {runtime.auth!r}")

    request = Request(url, data=payload, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            text = response.read().decode("utf-8")
            return response.status, parse_json_text(text), headers["x-request-id"]
    except HTTPError as exc:
        try:
            text = exc.read().decode("utf-8")
        finally:
            exc.close()
        return exc.code, parse_json_text(text), headers["x-request-id"]
    except URLError as exc:
        problem(f"{method} {url} failed: {exc}")


def parse_json_text(text: str) -> dict[str, Any]:
    if not text.strip():
        return {}
    try:
        body = json.loads(text)
    except json.JSONDecodeError as exc:
        problem(f"response was not JSON: {exc}: {text[:200]}")
    if not isinstance(body, dict):
        problem("response JSON was not an object")
    return body


def live_request(case: dict[str, Any], runtime: ProfileRuntime) -> dict[str, Any]:
    raw = case.get("request")
    if not isinstance(raw, dict):
        problem(f"{case.get('id')} missing request")
    request = {key: copy.deepcopy(value) for key, value in raw.items() if key in LIVE_REQUEST_KEYS}
    if "format" not in request:
        request["format"] = CLAIM_RESULT_JSON
    if runtime.subject_override and isinstance(request.get("target"), dict):
        override_first_identifier(request["target"], runtime.subject_override)
    return request


def override_first_identifier(target: dict[str, Any], value: str) -> None:
    identifiers = target.get("identifiers")
    if isinstance(identifiers, list) and identifiers and isinstance(identifiers[0], dict):
        identifiers[0]["value"] = value


def first_success_target(golden: dict[str, Any], runtime: ProfileRuntime) -> dict[str, Any]:
    for case in golden.get("cases") or []:
        if not isinstance(case, dict) or case.get("type") != "success":
            continue
        target = copy.deepcopy(case.get("request", {}).get("target"))
        if isinstance(target, dict):
            if runtime.subject_override:
                override_first_identifier(target, runtime.subject_override)
            return target
    problem(f"{runtime.profile} has no success target to reuse")


def claim_results(body: dict[str, Any]) -> list[dict[str, Any]]:
    results = body.get("results") or body.get("claim_results")
    if not isinstance(results, list) or not results:
        problem("evaluation response did not contain results[]")
    if not all(isinstance(result, dict) for result in results):
        problem("evaluation results must be objects")
    return results


def result_for(body: dict[str, Any], claim_id: str) -> dict[str, Any]:
    for result in claim_results(body):
        if result.get("claim_id") == claim_id or result.get("claim") == claim_id:
            return result
    problem(f"evaluation response did not include claim {claim_id!r}")


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


def assert_expected_result(case: dict[str, Any], body: dict[str, Any]) -> None:
    expected = case.get("expected", {})
    result_expectation = expected.get("result")
    claims = case.get("request", {}).get("claims") or []
    expected_claim = None
    if isinstance(result_expectation, dict):
        expected_claim = result_expectation.get("claim_id")
    if not expected_claim and claims:
        expected_claim = claims[0]
    if not isinstance(expected_claim, str):
        problem(f"{case.get('id')} has no expected claim")
    result = result_for(body, expected_claim)
    if isinstance(result_expectation, dict):
        for key in ("satisfied", "value", "disclosure"):
            if key in result_expectation and result.get(key) != result_expectation[key]:
                problem(
                    f"{case.get('id')} {expected_claim} expected {key}="
                    f"{result_expectation[key]!r}, got {result.get(key)!r}"
                )
    source_count = provenance_source_count(result)
    minimum = 2 if expected_claim == "eligible-for-combined-support" else 1
    if source_count < minimum:
        problem(f"{case.get('id')} expected source_count >= {minimum}, got {source_count}")


def assert_redaction(case: dict[str, Any], body: dict[str, Any]) -> None:
    payload = json.dumps(body, sort_keys=True)
    for field in case.get("expected", {}).get("absent_fields") or []:
        if field in payload:
            problem(f"{case.get('id')} leaked redacted field {field!r}")
    for claim in case.get("request", {}).get("claims") or []:
        result = result_for(body, claim)
        if provenance_source_count(result) < 1:
            problem(f"{case.get('id')} {claim} did not record source_count")


def audit_expectation_for(
    case: dict[str, Any],
    path: str,
    status: int,
    request_id: str,
) -> dict[str, Any]:
    expected = case.get("expected", {})
    expectation: dict[str, Any] = {
        "case_id": case["id"],
        "path": path,
        "status": status,
        "route_decision": "evaluate" if status < 400 else "evaluate_denied",
        "request_id": request_id,
    }
    if isinstance(expected.get("audit"), dict):
        expectation["audit"] = copy.deepcopy(expected["audit"])
    problem_code = expected.get("problem", {}).get("code")
    if isinstance(problem_code, str):
        expectation["problem_code"] = problem_code
    if isinstance(expected.get("zero_source_reads"), bool):
        expectation["zero_source_reads"] = expected["zero_source_reads"]
        if expected["zero_source_reads"]:
            expectation["no_forward"] = True
    return expectation


def runnable_case_ids(profile: str) -> set[str]:
    if profile == "baseline-dpi/v1":
        return {
            "baseline-success-combined-support",
            "baseline-denial-purpose",
            "baseline-denial-assurance",
            "baseline-denial-stale-evidence",
            "baseline-denial-missing-freshness",
            "baseline-denial-jurisdiction",
            "baseline-denial-legal-basis",
            "baseline-denial-consent",
            "baseline-audit-permit",
        }
    if profile == "sp-dci/v1":
        return {
            "sp-dci-success-birth-record",
            "sp-dci-denial-purpose",
            "sp-dci-denial-assurance",
            "sp-dci-denial-jurisdiction",
            "sp-dci-denial-legal-basis",
            "sp-dci-denial-consent",
            "sp-dci-redaction-birth-attributes",
            "sp-dci-credential-sd-jwt",
            "sp-dci-audit-permit",
        }
    return set()


def skip_blocker(profile: str, case: dict[str, Any]) -> str:
    case_type = case.get("type")
    if case_type == "denial":
        code = case.get("expected", {}).get("problem", {}).get("code")
        if code == "pdp.evidence_stale":
            if profile == "sp-dci/v1":
                return "live-opencrvs-response-timestamp-is-fresh-no-stale-demo-subject"
            return "live-source-observed-at-field-not-configured"
        if code == "pdp.unsupported_policy_term":
            return "live-runtime-policy-terms-are-config-static-not-request-supplied"
        return "live-runtime-missing-evidence-gateway-pdp-context-gate"
    if profile == "baseline-dpi/v1" and case_type == "redaction":
        return "baseline-redaction-fixture-targets-social-notary-not-shared-notary"
    if profile == "baseline-dpi/v1" and case_type == "credential":
        return "baseline-credential-fixture-targets-civil-notary-claim-not-shared-notary"
    if case_type == "credential":
        return "credential-fixture-lacks-live-target-context"
    return "fixture-case-not-exercisable-by-current-live-runtime"


def run_evaluation_case(
    runtime: ProfileRuntime,
    case: dict[str, Any],
    correlation_prefix: str,
) -> dict[str, Any]:
    case_runtime = runtime_for_case(runtime, case)
    request = live_request(case, case_runtime)
    purpose = request.get("purpose") if isinstance(request.get("purpose"), str) else None
    status, body, request_id = json_request(
        case_runtime,
        "POST",
        "/v1/evaluations",
        request,
        purpose=purpose,
        request_id=f"{correlation_prefix}-{case['id']}",
    )
    expected_status = case.get("expected", {}).get("status")
    if expected_status is None and case.get("type") in {"success", "redaction", "audit"}:
        expected_status = 200
    if expected_status is not None and status != expected_status:
        problem(f"{case['id']} expected HTTP {expected_status}, got {status}: {body}")
    if status >= 400:
        expected_code = case.get("expected", {}).get("problem", {}).get("code")
        if expected_code and body.get("code") != expected_code:
            problem(f"{case['id']} expected problem code {expected_code}, got {body.get('code')}")
    elif case.get("type") == "redaction":
        assert_redaction(case, body)
    else:
        assert_expected_result(case, body)
    return {
        "id": case["id"],
        "type": case.get("type"),
        "status": "passed",
        "http_status": status,
        "request_id": request_id,
        "audit_expectation": audit_expectation_for(case, "/v1/evaluations", status, request_id),
    }


def run_credential_case(
    runtime: ProfileRuntime,
    golden: dict[str, Any],
    case: dict[str, Any],
    correlation_prefix: str,
) -> dict[str, Any]:
    case_runtime = runtime_for_case(runtime, case)
    request = live_request(case, case_runtime)
    request["target"] = first_success_target(golden, case_runtime)
    request.setdefault("disclosure", "value")
    request["format"] = case.get("request", {}).get("format", SD_JWT_VC)
    purpose = request.get("purpose") if isinstance(request.get("purpose"), str) else None
    eval_status, eval_body, eval_request_id = json_request(
        case_runtime,
        "POST",
        "/v1/evaluations",
        request,
        purpose=purpose,
        request_id=f"{correlation_prefix}-{case['id']}-evaluate",
        accept=request["format"],
    )
    expected_status = case.get("expected", {}).get("status", 200)
    if eval_status != expected_status:
        problem(f"{case['id']} evaluation expected HTTP {expected_status}, got {eval_status}: {eval_body}")
    results = claim_results(eval_body)
    evaluation_id = results[0].get("evaluation_id")
    if not isinstance(evaluation_id, str) or not evaluation_id:
        problem(f"{case['id']} evaluation did not return evaluation_id")
    issue_body: dict[str, Any] = {
        "evaluation_id": evaluation_id,
        "format": case.get("expected", {}).get("credential_format", SD_JWT_VC),
        "claims": case.get("request", {}).get("claims") or [],
        "disclosure": request.get("disclosure"),
    }
    if case_runtime.profile == "sp-dci/v1":
        issue_body["credential_profile"] = "opencrvs_birth_attributes_sd_jwt"
    issue_status, credential_body, issue_request_id = json_request(
        case_runtime,
        "POST",
        "/v1/credentials",
        issue_body,
        request_id=f"{correlation_prefix}-{case['id']}-issue",
        accept=issue_body["format"],
    )
    if issue_status != expected_status:
        problem(f"{case['id']} issue expected HTTP {expected_status}, got {issue_status}: {credential_body}")
    if credential_body.get("format") != issue_body["format"]:
        problem(f"{case['id']} credential format mismatch: {credential_body.get('format')!r}")
    if not (credential_body.get("credential") or credential_body.get("issuer_signed_jwt")):
        problem(f"{case['id']} did not return credential material")
    return {
        "id": case["id"],
        "type": case.get("type"),
        "status": "passed",
        "http_status": issue_status,
        "request_id": issue_request_id,
        "evaluation_request_id": eval_request_id,
        "audit_expectation": audit_expectation_for(
            case,
            "/v1/evaluations",
            eval_status,
            eval_request_id,
        ),
    }


def run_missing_subject_negative(
    runtime: ProfileRuntime,
    golden: dict[str, Any],
    correlation_prefix: str,
) -> dict[str, Any]:
    success = next(
        case for case in golden.get("cases") or [] if isinstance(case, dict) and case.get("type") == "success"
    )
    request = live_request(success, runtime)
    target = request.get("target")
    if not isinstance(target, dict):
        problem(f"{runtime.profile} success fixture has no live target")
    missing_value = "NID-LIVE-MISSING" if runtime.profile == "baseline-dpi/v1" else "UIN-LIVE-MISSING"
    override_first_identifier(target, missing_value)
    purpose = request.get("purpose") if isinstance(request.get("purpose"), str) else None
    status, body, request_id = json_request(
        runtime,
        "POST",
        "/v1/evaluations",
        request,
        purpose=purpose,
        request_id=f"{correlation_prefix}-{profile_slug(runtime.profile)}-missing-subject",
    )
    if status != 409:
        problem(f"{runtime.profile} missing-subject expected HTTP 409, got {status}: {body}")
    if body.get("code") != "evidence.not_available":
        problem(f"{runtime.profile} missing-subject expected evidence.not_available, got {body.get('code')}")
    return {
        "id": f"{profile_slug(runtime.profile)}-runtime-missing-subject",
        "type": "runtime-negative",
        "status": "passed",
        "http_status": status,
        "problem_code": body.get("code"),
        "request_id": request_id,
        "audit_expectation": {
            "case_id": f"{profile_slug(runtime.profile)}-runtime-missing-subject",
            "path": "/v1/evaluations",
            "route_decision": "evaluate_denied",
            "status": status,
            "request_id": request_id,
            "problem_code": "target.not_found",
        },
    }


def run_profile(runtime: ProfileRuntime, mode: str, correlation_prefix: str) -> dict[str, Any]:
    golden = load_json(golden_path(runtime.profile))
    executed: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    runnable = runnable_case_ids(runtime.profile)
    for case in golden.get("cases") or []:
        if not isinstance(case, dict):
            continue
        case_id = case.get("id")
        if case_id not in runnable:
            skipped.append(
                {
                    "id": str(case_id),
                    "type": str(case.get("type")),
                    "blocker": skip_blocker(runtime.profile, case),
                }
            )
            continue
        if case.get("type") == "credential":
            executed.append(run_credential_case(runtime, golden, case, correlation_prefix))
        else:
            executed.append(run_evaluation_case(runtime, case, correlation_prefix))
    executed.append(run_missing_subject_negative(runtime, golden, correlation_prefix))
    if mode == "strict" and skipped:
        blockers = ", ".join(f"{item['id']}:{item['blocker']}" for item in skipped)
        problem(f"{runtime.profile} strict mode has unexercised fixture blockers: {blockers}")
    return {
        "profile": runtime.profile,
        "mode": mode,
        "executed": executed,
        "skipped": skipped,
        "audit_expectations": [
            result["audit_expectation"]
            for result in executed
            if isinstance(result.get("audit_expectation"), dict)
        ],
    }


def parse_audit_records(path: Path) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        start = line.find("{")
        while start != -1:
            try:
                value, _ = decoder.raw_decode(line[start:])
            except json.JSONDecodeError:
                start = line.find("{", start + 1)
                continue
            if isinstance(value, dict):
                records.append(value.get("record") if isinstance(value.get("record"), dict) else value)
                break
            start = line.find("{", start + 1)
    return records


def record_field(record: dict[str, Any], key: str) -> Any:
    value = first_record_value(record, (key,))
    if value is not None:
        return value
    if key == "status":
        return record.get("status_code")
    return None


def first_record_value(record: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for alias in aliases:
        value = nested_record_value(record, alias)
        if value is not None:
            return value
    return None


def nested_record_value(record: dict[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def assert_audit_log(summary: dict[str, Any], audit_log_path: Path) -> None:
    records = parse_audit_records(audit_log_path)
    if not records:
        problem(f"{audit_log_path} did not contain JSON audit records")
    missing: list[str] = []
    blockers: list[str] = []
    for profile_summary in summary.get("profiles") or []:
        for expectation in profile_summary.get("audit_expectations") or []:
            if not isinstance(expectation, dict):
                continue
            candidates = [record for record in records if audit_record_matches(record, expectation)]
            if not candidates:
                missing.append(json.dumps(expectation, sort_keys=True))
                continue
            candidate_blockers = [assert_audit_record_details(record, expectation) for record in candidates]
            if any(not candidate for candidate in candidate_blockers):
                continue
            blockers.extend(min(candidate_blockers, key=len))
    if missing:
        problem(f"audit log did not contain expected live evidence events: {', '.join(missing)}")
    if blockers:
        problem(f"audit log did not prove required live evidence fields: {', '.join(blockers)}")


def audit_record_matches(record: dict[str, Any], expectation: dict[str, Any]) -> bool:
    for key in ("path", "status"):
        expected = expectation.get(key)
        if expected is not None and record_field(record, key) != expected:
            return False
    expected_request_id = expectation.get("request_id")
    record_request_id = first_record_value(record, REQUEST_ID_ALIASES)
    if isinstance(expected_request_id, str) and record_request_id is not None:
        return record_request_id == expected_request_id
    if "audit" not in expectation and expectation.get("decision") is not None:
        expected = expectation["decision"]
        if normalized_decision(record_field(record, "decision")) != normalized_decision(expected):
            return False
    return True


def assert_audit_record_details(record: dict[str, Any], expectation: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    case_id = expectation.get("case_id", "<unknown-case>")
    audit = expectation.get("audit")
    if isinstance(audit, dict):
        for key, expected in audit.items():
            actual = first_record_value(record, AUDIT_FIELD_ALIASES.get(key, (key,)))
            if actual is None:
                blockers.append(f"{case_id} missing audit field {key}")
                continue
            if key == "decision":
                if normalized_decision(actual) != normalized_decision(expected):
                    blockers.append(f"{case_id} audit field {key} expected {expected!r}, got {actual!r}")
            elif key.endswith("_hash") and isinstance(expected, str):
                if not audit_hash_matches(actual, expected):
                    blockers.append(f"{case_id} audit field {key} expected {expected!r} hash shape, got {actual!r}")
            elif not audit_values_match(actual, expected):
                blockers.append(f"{case_id} audit field {key} expected {expected!r}, got {actual!r}")
    expected_code = expectation.get("problem_code")
    if isinstance(expected_code, str):
        actual_code = first_record_value(
            record,
            ("problem_code", "error_code", "code", "matching_error_code", "denial_code"),
        )
        if actual_code is None:
            blockers.append(f"{case_id} missing audit problem_code")
        elif actual_code != expected_code:
            blockers.append(f"{case_id} audit problem_code expected {expected_code!r}, got {actual_code!r}")
    if expectation.get("zero_source_reads") is True:
        source_read_count = source_read_count_from_record(record)
        if source_read_count is None:
            blockers.append(f"{case_id} missing source-read evidence for zero_source_reads")
        elif source_read_count != 0:
            blockers.append(f"{case_id} expected zero source reads, got {source_read_count}")
    if expectation.get("no_forward") is True:
        no_forward = no_forward_from_record(record)
        if no_forward is None:
            blockers.append(f"{case_id} missing no-forward evidence")
        elif no_forward is not True:
            blockers.append(f"{case_id} audit record shows forwarded evidence")
    return blockers


def audit_values_match(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        if expected == [f"{BINDING_QUALIFIED_RULE_PREFIX}*"]:
            return binding_qualified_rule_ids_match(actual)
        return set(actual) == set(expected)
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            audit_values_match(actual.get(key), value) for key, value in expected.items()
        )
    return actual == expected


def binding_qualified_rule_ids_match(actual: list[Any]) -> bool:
    if not actual or not all(isinstance(item, str) for item in actual):
        return False
    if not any(item.endswith(".policy_identity") for item in actual):
        return False
    return all(is_binding_qualified_rule_id(item) for item in actual)


def is_binding_qualified_rule_id(value: str) -> bool:
    if not value.startswith(BINDING_QUALIFIED_RULE_PREFIX):
        return False
    remainder = value.removeprefix(BINDING_QUALIFIED_RULE_PREFIX)
    entity, separator, gate = remainder.rpartition(".")
    return bool(entity and separator and gate in BINDING_QUALIFIED_RULE_GATES)


def audit_hash_matches(actual: Any, expected: str) -> bool:
    if not isinstance(actual, str):
        return False
    if expected in {"sha256", "sha256:"}:
        return is_hash_ref(actual)
    return actual == expected


def is_hash_ref(value: str) -> bool:
    if value.startswith("sha256:"):
        digest = value.removeprefix("sha256:")
        return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)
    if value.startswith("hmac-sha256:"):
        digest = value.removeprefix("hmac-sha256:")
        return len(digest) >= 32 and all(ch.isalnum() or ch in "-_=" for ch in digest)
    return False


def normalized_decision(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    if normalized in {"permit", "permitted", "allow", "allowed", "approve", "approved", "evaluate"}:
        return "permit"
    if normalized in {"deny", "denied", "reject", "rejected", "evaluate_denied"}:
        return "deny"
    return normalized


def source_read_count_from_record(record: dict[str, Any]) -> int | None:
    value = first_record_value(record, SOURCE_READ_ALIASES)
    if isinstance(value, int):
        return value
    source_reads = first_record_value(record, SOURCE_READ_LIST_ALIASES)
    if isinstance(source_reads, list):
        return len(source_reads)
    return None


def no_forward_from_record(record: dict[str, Any]) -> bool | None:
    values = [
        first_record_value(record, (alias,))
        for alias in FORWARD_EVIDENCE_ALIASES
        if first_record_value(record, (alias,)) is not None
    ]
    if not values:
        return None
    for value in values:
        if value is True:
            return False
        if isinstance(value, (list, dict, str)) and len(value) > 0:
            return False
        if isinstance(value, int) and value != 0:
            return False
    return True


def write_output(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_runtimes(args: argparse.Namespace) -> list[ProfileRuntime]:
    runtimes: list[ProfileRuntime] = []
    for profile in args.profile:
        token, auth = default_token_and_auth(profile)
        if args.token:
            token = args.token
        if args.auth:
            auth = args.auth
        runtimes.append(
            ProfileRuntime(
                profile=profile,
                base_url=args.base_url or default_base_url(profile),
                token=token,
                auth=auth,
                subject_override=args.subject_id or default_subject_override(profile),
            )
        )
    return runtimes


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        action="append",
        choices=["baseline-dpi/v1", "sp-dci/v1"],
        required=True,
        help="Fixture profile to run. Repeat to run multiple profiles.",
    )
    parser.add_argument("--base-url", help="Override Notary base URL for a single profile run.")
    parser.add_argument("--token", help="Override client token.")
    parser.add_argument("--auth", choices=["bearer", "api-key"], help="Override auth mode.")
    parser.add_argument("--subject-id", help="Override the fixture target identifier for live data.")
    parser.add_argument(
        "--mode",
        choices=["prove-live", "strict"],
        default=os.environ.get("EVIDENCE_GATEWAY_LIVE_MODE", "prove-live"),
        help="strict fails when any golden fixture case cannot be exercised live.",
    )
    parser.add_argument(
        "--correlation-prefix",
        default=f"evidence-gateway-live-{int(time.time())}",
        help="Prefix for x-request-id values emitted by this runner.",
    )
    parser.add_argument("--output", type=Path, help="Write a JSON run summary.")
    parser.add_argument("--audit-log-path", type=Path, help="Assert audit fields in this log path.")
    parser.add_argument(
        "--audit-only",
        action="store_true",
        help="Only assert --audit-log-path against an existing --output summary.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.audit_only:
            if not args.output or not args.output.exists():
                problem("--audit-only requires an existing --output summary")
            if not args.audit_log_path:
                problem("--audit-only requires --audit-log-path")
            summary = load_json(args.output)
            assert_audit_log(summary, args.audit_log_path)
        else:
            profiles = [
                run_profile(runtime, args.mode, args.correlation_prefix)
                for runtime in build_runtimes(args)
            ]
            summary = {
                "schema_version": "registry-lab/evidence-gateway-live-fixtures/v1",
                "mode": args.mode,
                "profiles": profiles,
            }
            if args.audit_log_path:
                assert_audit_log(summary, args.audit_log_path)
            if args.output:
                write_output(args.output, summary)
            for profile in profiles:
                print(
                    "evidence gateway live fixtures OK: "
                    f"{profile['profile']} executed={len(profile['executed'])} "
                    f"skipped={len(profile['skipped'])} mode={args.mode}"
                )
                for skipped in profile["skipped"]:
                    print(f"skipped {skipped['id']}: {skipped['blocker']}")
        return 0
    except LiveFixtureError as exc:
        print(f"evidence gateway live fixtures failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
