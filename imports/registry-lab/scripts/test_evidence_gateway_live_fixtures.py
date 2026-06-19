#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = REPO_ROOT / "scripts" / "run-evidence-gateway-live-fixtures.py"

spec = importlib.util.spec_from_file_location("evidence_gateway_live_runner", RUNNER_PATH)
assert spec and spec.loader
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


class FakeNotaryHandler(BaseHTTPRequestHandler):
    audit_records: list[dict[str, Any]] = []
    requests_seen: list[dict[str, Any]] = []

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        self.request_body = body
        self.requests_seen.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
            }
        )
        if self.path == "/v1/evaluations":
            self.handle_evaluation(body)
            return
        if self.path == "/v1/credentials":
            self.respond(
                200,
                {
                    "format": "application/dc+sd-jwt",
                    "credential": "issuer.jwt~disclosure",
                    "issuer_signed_jwt": "issuer.jwt",
                    "disclosures": ["disclosure"],
                },
                decision="credential_issue",
            )
            return
        self.respond(404, {"code": "not_found"})

    def handle_evaluation(self, body: dict[str, Any]) -> None:
        purpose = self.headers.get("data-purpose")
        if purpose == "https://demo.example.gov/purpose/not-authorized":
            self.respond_problem("pdp.purpose_not_permitted")
            return
        if body.get("jurisdiction") == "XY":
            self.respond_problem("pdp.jurisdiction_not_permitted")
            return
        api_key = self.headers.get("x-api-key")
        token_denials = {
            "deny-assurance": "pdp.assurance_insufficient",
            "deny-jurisdiction": "pdp.jurisdiction_not_permitted",
            "deny-legal-basis": "pdp.legal_basis_required",
            "deny-consent": "pdp.consent_required",
        }
        if api_key in token_denials:
            self.respond_problem(token_denials[api_key])
            return
        target = body.get("target") or {}
        identifiers = target.get("identifiers") or []
        value = identifiers[0].get("value") if identifiers else ""
        if value in {"NID-1010", "NID-1011"}:
            self.respond_problem("pdp.evidence_stale")
            return
        if value in {"NID-LIVE-MISSING", "UIN-LIVE-MISSING", "WAVE-A-LIVE-MISSING"}:
            self.respond(
                409,
                {
                    "type": "https://example.test/problems/evidence/not_available",
                    "title": "Evidence not available",
                    "status": 409,
                    "detail": "missing",
                    "code": "evidence.not_available",
                },
                decision="evaluate_denied",
            )
            return
        claims = body.get("claims") or []
        results = []
        for claim in claims:
            result: dict[str, Any] = {
                "evaluation_id": f"eval-{claim}",
                "claim_id": claim,
                "claim_version": "2026-05",
                "value": True,
                "satisfied": True,
                "disclosure": body.get("disclosure") or "predicate",
                "format": body.get("format") or "application/vnd.registry-notary.claim-result+json",
                "provenance": {
                    "schema_version": "registry-notary-claim-provenance/v1",
                    "generated_by": {
                        "type": "claim_evaluation",
                        "service_id": "fake-notary",
                        "evaluation_id": f"eval-{claim}",
                        "claim_id": claim,
                        "claim_version": "2026-05",
                    },
                    "used": {
                        "source_count": 3 if claim == "eligible-for-combined-support" else 1,
                        "source_versions": {},
                        "source_runtimes": [],
                    },
                    "derived_from": [],
                },
            }
            if claim == "opencrvs-age-band":
                result["value"] = "child"
                result["satisfied"] = None
            if claim == "opencrvs-sex":
                result["value"] = "F"
                result["satisfied"] = None
            results.append(result)
        self.respond(200, {"results": results}, decision="evaluate")

    def respond_problem(self, code: str) -> None:
        self.respond(
            403,
            {
                "type": f"https://example.test/problems/{code}",
                "title": "Policy decision denied",
                "status": 403,
                "detail": "denied",
                "code": code,
            },
            decision="evaluate_denied",
        )

    def respond(self, status: int, body: dict[str, Any], *, decision: str = "evaluate") -> None:
        request_body = getattr(self, "request_body", {})
        self.audit_records.append(self.audit_record(status, body, request_body, decision))
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def audit_record(
        self,
        status: int,
        response_body: dict[str, Any],
        request_body: dict[str, Any],
        route_decision: str,
    ) -> dict[str, Any]:
        profile = self.profile_for_request(request_body)
        baseline_rule_ids = [
            "source-binding-policy:health_facility.policy_identity",
            "source-binding-policy:health_facility.odrl_terms",
            "source-binding-policy:health_facility.purpose",
            "source-binding-policy:health_facility.jurisdiction",
            "source-binding-policy:health_facility.assurance_allowed_set",
            "source-binding-policy:health_facility.legal_basis_required",
            "source-binding-policy:health_facility.consent_required",
            "source-binding-policy:health_facility.requested_fact",
            "source-binding-policy:health_facility.requested_disclosure",
            "source-binding-policy:health_facility.credential_format",
            "source-binding-policy:health_facility.source_binding",
            "source-binding-policy:health_facility.route_identity",
            "source-binding-policy:health_facility.checked_scope",
        ]
        sp_dci_rule_ids = [
            "source-binding-policy:birth_registration.policy_identity",
            "source-binding-policy:birth_registration.odrl_terms",
            "source-binding-policy:birth_registration.purpose",
            "source-binding-policy:birth_registration.jurisdiction",
            "source-binding-policy:birth_registration.assurance_allowed_set",
            "source-binding-policy:birth_registration.legal_basis_required",
            "source-binding-policy:birth_registration.consent_required",
            "source-binding-policy:birth_registration.requested_fact",
            "source-binding-policy:birth_registration.requested_disclosure",
            "source-binding-policy:birth_registration.credential_format",
            "source-binding-policy:birth_registration.source_binding",
            "source-binding-policy:birth_registration.route_identity",
            "source-binding-policy:birth_registration.checked_scope",
        ]
        oots_birth_rule_ids = [
            "source-binding-policy:oots_birth.policy_identity",
            "source-binding-policy:oots_birth.odrl_terms",
            "source-binding-policy:oots_birth.purpose",
            "source-binding-policy:oots_birth.jurisdiction",
            "source-binding-policy:oots_birth.assurance_allowed_set",
            "source-binding-policy:oots_birth.legal_basis_required",
            "source-binding-policy:oots_birth.consent_required",
            "source-binding-policy:oots_birth.credential_format",
        ]
        oots_marriage_rule_ids = [
            "source-binding-policy:oots_marriage.policy_identity",
            "source-binding-policy:oots_marriage.odrl_terms",
            "source-binding-policy:oots_marriage.purpose",
            "source-binding-policy:oots_marriage.jurisdiction",
            "source-binding-policy:oots_marriage.assurance_allowed_set",
            "source-binding-policy:oots_marriage.legal_basis_required",
            "source-binding-policy:oots_marriage.consent_required",
            "source-binding-policy:oots_marriage.credential_format",
        ]
        policy = {
            "baseline-dpi/v1": (
                "lab.baseline-dpi.governed-evidence.v1",
                "sha256:9818125ad99b32b4eb996780c12cc68730fbcb0b406c4124dbb36dea4ccc6bdb",
                baseline_rule_ids,
            ),
            "sp-dci/v1": (
                "lab.sp-dci.governed-evidence.v1",
                "sha256:479cfba9c5895f5f827b855244436a5b4a9f84c76fbd5472e861ad56983254db",
                sp_dci_rule_ids,
            ),
            "oots-birth-evidence/v1": (
                "lab.oots-birth-evidence.governed-evidence.v1",
                "sha256:a4804f81f3287b7922e8c3d5bad49377584b7ab8727fe62cbae23c1f5bc85e1c",
                oots_birth_rule_ids,
            ),
            "oots-marriage-evidence/v1": (
                "lab.oots-marriage-evidence.governed-evidence.v1",
                "sha256:e5193284535dfa9689dd081942ec847f51eacd50ebc71d93b482247207b63dcf",
                oots_marriage_rule_ids,
            ),
        }[profile]
        claims = request_body.get("claims") or []
        record: dict[str, Any] = {
            "action": route_decision,
            "binding_id": profile,
            "binding_version": "v1",
            "decision": "permit" if status < 400 else "deny",
            "forwarded": False,
            "method": "POST",
            "path": self.path,
            "policy_hash": policy[1],
            "policy_id": policy[0],
            "request_id": self.headers.get("x-request-id"),
            "source_read_count": 0 if status >= 400 else 1,
            "status": status,
        }
        if profile == "baseline-dpi/v1":
            record.update(
                {
                    "target_ref_hash": "hmac-sha256:targettargettargettargettargettarget",
                    "claim_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "correlation_id_hash": "hmac-sha256:correlationcorrelationcorrelation",
                    "requester_ref_hash": "hmac-sha256:requesterrequesterrequesterrequester",
                }
            )
        else:
            record.update(
                {
                    "target_ref_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    if profile.startswith("oots-")
                    else "hmac-sha256:spdcitargettargettargettargettargettarget",
                    "claim_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "correlation_id_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                    if profile.startswith("oots-")
                    else "hmac-sha256:spdcicorrelationcorrelationcorrelation",
                    "request_ref_hash": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                }
            )
        if status < 400:
            record["evaluated_rule_ids"] = policy[2]
        if response_body.get("code"):
            if response_body["code"] == "evidence.not_available":
                record["problem_code"] = "target.not_found"
            else:
                record["problem_code"] = response_body["code"]
        if set(claims) >= {"opencrvs-age-band", "opencrvs-sex"}:
            record["redacted_fields"] = ["opencrvs-age-band", "opencrvs-sex"]
        return record

    def profile_for_request(self, request_body: dict[str, Any]) -> str:
        claims = request_body.get("claims") or []
        if any(isinstance(claim, str) and claim.startswith("opencrvs-") for claim in claims):
            return "sp-dci/v1"
        if set(claims) & {"birth.certificate_summary", "birth.event_exists"}:
            return "oots-birth-evidence/v1"
        if set(claims) & {"marriage.certificate_summary", "marriage.event_exists"}:
            return "oots-marriage-evidence/v1"
        return "baseline-dpi/v1"


class FakeNotaryServer:
    def __enter__(self) -> "FakeNotaryServer":
        FakeNotaryHandler.audit_records = []
        FakeNotaryHandler.requests_seen = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeNotaryHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    @property
    def requests_seen(self) -> list[dict[str, Any]]:
        return FakeNotaryHandler.requests_seen

    @property
    def audit_records(self) -> list[dict[str, Any]]:
        return FakeNotaryHandler.audit_records


@contextmanager
def temporary_env(values: dict[str, str]):
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def write_audit_log(records: list[dict[str, Any]]) -> Path:
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
    with handle:
        for record in records:
            handle.write("svc | ")
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")
    return Path(handle.name)


NEGATIVE_ENV = {
    "SHARED_EVIDENCE_DENY_ASSURANCE_TOKEN": "deny-assurance",
    "SHARED_EVIDENCE_DENY_JURISDICTION_TOKEN": "deny-jurisdiction",
    "SHARED_EVIDENCE_DENY_LEGAL_BASIS_TOKEN": "deny-legal-basis",
    "SHARED_EVIDENCE_DENY_CONSENT_TOKEN": "deny-consent",
    "OPENCRVS_EVIDENCE_DENY_ASSURANCE_TOKEN": "deny-assurance",
    "OPENCRVS_EVIDENCE_DENY_JURISDICTION_TOKEN": "deny-jurisdiction",
    "OPENCRVS_EVIDENCE_DENY_LEGAL_BASIS_TOKEN": "deny-legal-basis",
    "OPENCRVS_EVIDENCE_DENY_CONSENT_TOKEN": "deny-consent",
    "CIVIL_EVIDENCE_DENY_ASSURANCE_TOKEN": "deny-assurance",
    "CIVIL_EVIDENCE_DENY_JURISDICTION_TOKEN": "deny-jurisdiction",
    "CIVIL_EVIDENCE_DENY_LEGAL_BASIS_TOKEN": "deny-legal-basis",
    "CIVIL_EVIDENCE_DENY_CONSENT_TOKEN": "deny-consent",
}


class EvidenceGatewayLiveFixtureRunnerTest(unittest.TestCase):
    def test_baseline_prove_live_runs_success_audit_and_runtime_negative(self) -> None:
        with temporary_env(NEGATIVE_ENV), FakeNotaryServer() as server:
            runtime = runner.ProfileRuntime(
                profile="baseline-dpi/v1",
                base_url=server.url,
                token="token",
                auth="bearer",
                subject_override=None,
            )
            summary = runner.run_profile(runtime, "prove-live", "test-live")

        executed = {item["id"] for item in summary["executed"]}
        self.assertIn("baseline-success-combined-support", executed)
        self.assertIn("baseline-denial-assurance", executed)
        self.assertIn("baseline-denial-stale-evidence", executed)
        self.assertIn("baseline-denial-missing-freshness", executed)
        self.assertIn("baseline-denial-jurisdiction", executed)
        self.assertIn("baseline-denial-legal-basis", executed)
        self.assertIn("baseline-denial-consent", executed)
        self.assertIn("baseline-audit-permit", executed)
        self.assertIn("baseline-dpi.v1-runtime-missing-subject", executed)
        self.assertFalse(any(item["blocker"] == "live-source-observed-at-field-not-configured" for item in summary["skipped"]))
        auth_header = server.requests_seen[0]["headers"].get("Authorization")
        self.assertEqual(auth_header, "Bearer token")
        audit_log = write_audit_log(server.audit_records)
        try:
            runner.assert_audit_log({"profiles": [summary]}, audit_log)
        finally:
            audit_log.unlink(missing_ok=True)

    def test_strict_mode_fails_on_unexercised_context_gates(self) -> None:
        with temporary_env(NEGATIVE_ENV), FakeNotaryServer() as server:
            runtime = runner.ProfileRuntime(
                profile="baseline-dpi/v1",
                base_url=server.url,
                token="token",
                auth="api-key",
                subject_override=None,
            )
            with self.assertRaisesRegex(runner.LiveFixtureError, "strict mode has unexercised fixture blockers"):
                runner.run_profile(runtime, "strict", "test-live")

    def test_sp_dci_subject_override_and_credential_flow(self) -> None:
        with FakeNotaryServer() as server:
            runtime = runner.ProfileRuntime(
                profile="sp-dci/v1",
                base_url=server.url,
                token="token",
                auth="api-key",
                subject_override="REAL-UIN-123",
            )
            with temporary_env(NEGATIVE_ENV):
                summary = runner.run_profile(runtime, "prove-live", "test-live")

        executed = {item["id"] for item in summary["executed"]}
        self.assertIn("sp-dci-success-birth-record", executed)
        self.assertIn("sp-dci-denial-assurance", executed)
        self.assertIn("sp-dci-denial-jurisdiction", executed)
        self.assertIn("sp-dci-denial-legal-basis", executed)
        self.assertIn("sp-dci-denial-consent", executed)
        self.assertIn("sp-dci-redaction-birth-attributes", executed)
        self.assertIn("sp-dci-credential-sd-jwt", executed)
        first_eval = next(request for request in server.requests_seen if request["path"] == "/v1/evaluations")
        self.assertEqual(
            first_eval["body"]["target"]["identifiers"][0]["value"],
            "REAL-UIN-123",
        )
        headers = {key.lower(): value for key, value in first_eval["headers"].items()}
        self.assertEqual(headers.get("x-api-key"), "token")
        audit_log = write_audit_log(server.audit_records)
        try:
            runner.assert_audit_log({"profiles": [summary]}, audit_log)
        finally:
            audit_log.unlink(missing_ok=True)

    def test_wave_a_birth_and_marriage_minimized_json(self) -> None:
        with temporary_env(NEGATIVE_ENV), FakeNotaryServer() as server:
            profiles = []
            for profile in ("oots-birth-evidence/v1", "oots-marriage-evidence/v1"):
                runtime = runner.ProfileRuntime(
                    profile=profile,
                    base_url=server.url,
                    token="token",
                    auth="bearer",
                    subject_override=None,
                )
                profiles.append(runner.run_profile(runtime, "prove-live", "test-live"))

        executed = {item["id"] for profile in profiles for item in profile["executed"]}
        self.assertIn("oots-birth-success-minimized-json", executed)
        self.assertIn("oots-birth-success-predicate", executed)
        self.assertIn("oots-birth-denial-purpose", executed)
        self.assertIn("oots-birth-denial-jurisdiction", executed)
        self.assertIn("oots-birth-audit-permit", executed)
        self.assertIn("oots-birth-evidence.v1-runtime-missing-subject", executed)
        self.assertIn("oots-marriage-success-minimized-json", executed)
        self.assertIn("oots-marriage-success-predicate", executed)
        self.assertIn("oots-marriage-denial-purpose", executed)
        self.assertIn("oots-marriage-denial-jurisdiction", executed)
        self.assertIn("oots-marriage-audit-permit", executed)
        self.assertIn("oots-marriage-evidence.v1-runtime-missing-subject", executed)
        wave_a_requests = [
            request["body"]
            for request in server.requests_seen
            if request["path"] == "/v1/evaluations"
            and set(request["body"].get("claims") or [])
            & {
                "birth.certificate_summary",
                "birth.event_exists",
                "marriage.certificate_summary",
                "marriage.event_exists",
            }
        ]
        self.assertTrue(wave_a_requests)
        self.assertTrue(all(request.get("format") == "minimized_json" for request in wave_a_requests))
        audit_log = write_audit_log(server.audit_records)
        try:
            runner.assert_audit_log({"profiles": profiles}, audit_log)
        finally:
            audit_log.unlink(missing_ok=True)

    def test_audit_only_asserts_summary_expectations_against_log(self) -> None:
        summary = {
            "profiles": [
                {
                    "audit_expectations": [
                        {"path": "/v1/evaluations", "decision": "evaluate", "status": 200},
                        {"path": "/v1/evaluations", "decision": "evaluate_denied", "status": 409},
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log_path.write_text(
                'svc | {"path":"/v1/evaluations","decision":"evaluate","status":200}\n'
                'svc | {"path":"/v1/evaluations","decision":"evaluate_denied","status":409}\n',
                encoding="utf-8",
            )
            runner.assert_audit_log(summary, log_path)

    def test_audit_log_reports_blocker_when_zero_source_reads_lacks_evidence(self) -> None:
        summary = {
            "profiles": [
                {
                    "audit_expectations": [
                        {
                            "case_id": "baseline-denial-purpose",
                            "path": "/v1/evaluations",
                            "status": 403,
                            "request_id": "req-1",
                            "audit": {
                                "binding_id": "baseline-dpi/v1",
                                "policy_id": "lab.baseline-dpi.governed-evidence.v1",
                                "policy_hash": "sha256:policy",
                                "decision": "deny",
                            },
                            "problem_code": "pdp.purpose_not_permitted",
                            "zero_source_reads": True,
                            "no_forward": True,
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log_path.write_text(
                "svc | "
                + json.dumps(
                    {
                        "binding_id": "baseline-dpi/v1",
                        "decision": "deny",
                        "method": "POST",
                        "path": "/v1/evaluations",
                        "policy_hash": "sha256:policy",
                        "policy_id": "lab.baseline-dpi.governed-evidence.v1",
                        "problem_code": "pdp.purpose_not_permitted",
                        "request_id": "req-1",
                        "status": 403,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(runner.LiveFixtureError, "missing source-read evidence"):
                runner.assert_audit_log(summary, log_path)

    def test_audit_log_requires_hash_shaped_redacted_refs(self) -> None:
        summary = {
            "profiles": [
                {
                    "audit_expectations": [
                        {
                            "case_id": "baseline-audit-permit",
                            "path": "/v1/evaluations",
                            "status": 200,
                            "audit": {
                                "target_ref_hash": "sha256",
                                "claim_hash": "sha256",
                                "correlation_id_hash": "sha256",
                                "requester_ref_hash": "sha256",
                            },
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log_path.write_text(
                "svc | "
                + json.dumps(
                    {
                        "path": "/v1/evaluations",
                        "status": 200,
                        "target_ref_hash": "hash:nid-1001",
                        "claim_hash": "sha256:" + ("1" * 64),
                        "correlation_id_hash": "hmac-sha256:correlationcorrelationcorrelation",
                        "requester_ref_hash": "hmac-sha256:requesterrequesterrequesterrequester",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(runner.LiveFixtureError, "hash shape"):
                runner.assert_audit_log(summary, log_path)
            log_path.write_text(
                "svc | "
                + json.dumps(
                    {
                        "path": "/v1/evaluations",
                        "status": 200,
                        "target_ref_hash": "hmac-sha256:targettargettargettargettargettarget",
                        "claim_hash": "sha256:" + ("1" * 64),
                        "correlation_id_hash": "hmac-sha256:correlationcorrelationcorrelation",
                        "requester_ref_hash": "hmac-sha256:requesterrequesterrequesterrequester",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            runner.assert_audit_log(summary, log_path)

    def test_audit_log_requires_binding_qualified_rule_id_shape(self) -> None:
        summary = {
            "profiles": [
                {
                    "audit_expectations": [
                        {
                            "case_id": "baseline-success-combined-support",
                            "path": "/v1/evaluations",
                            "status": 200,
                            "audit": {"evaluated_rule_ids": ["source-binding-policy:*"]},
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.log"
            log_path.write_text(
                'svc | {"path":"/v1/evaluations","status":200,'
                '"evaluated_rule_ids":["urn:registry-lab:rule:baseline-dpi:purpose"]}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(runner.LiveFixtureError, "evaluated_rule_ids"):
                runner.assert_audit_log(summary, log_path)
            log_path.write_text(
                'svc | {"path":"/v1/evaluations","status":200,'
                '"evaluated_rule_ids":["source-binding-policy:health_facility.policy_identity",'
                '"source-binding-policy:health_facility.purpose"]}\n',
                encoding="utf-8",
            )
            runner.assert_audit_log(summary, log_path)


if __name__ == "__main__":
    unittest.main()
