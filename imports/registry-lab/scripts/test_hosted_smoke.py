#!/usr/bin/env python3
"""Focused tests for hosted-smoke.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
import unittest
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).resolve().parent / "hosted-smoke.py"
SPEC = importlib.util.spec_from_file_location("hosted_smoke", SCRIPT)
hosted_smoke = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules["hosted_smoke"] = hosted_smoke
SPEC.loader.exec_module(hosted_smoke)


class StubServer:
    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = routes
        self.requests: list[tuple[str, str, Any]] = []
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def __enter__(self) -> "StubServer":
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def _handle(self, method: str) -> None:
                body = {}
                if method == "POST":
                    raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                outer.requests.append((method, self.path, body))
                route = outer.routes.get((method, self.path))
                if route is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                status, payload = route(outer, method, self.path, body) if callable(route) else route
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        assert self.server is not None
        self.server.shutdown()
        self.server.server_close()
        assert self.thread is not None
        self.thread.join(timeout=5)

    @property
    def url(self) -> str:
        assert self.server is not None
        host, port = self.server.server_address
        return f"http://{host}:{port}"


def base_routes() -> dict[tuple[str, str], Any]:
    routes: dict[tuple[str, str], Any] = {
        ("GET", "/healthz"): (200, {"status": "ok", "checks": {"ok": 1, "failed": 0, "total": 1}}),
        ("GET", "/api/scenarios.json"): (
            200,
            {
                "default_scenario_id": "alive-proof",
                "scenarios": [
                    {"id": "alive-proof", "steps": 3},
                    {"id": "civil-birth-demographics", "steps": 2},
                    {"id": "civil-birth-evidence", "steps": 2},
                    {"id": "civil-birth-evidence-demographics", "steps": 2},
                    {"id": "civil-marriage-evidence", "steps": 2},
                    {"id": "wallet-credential", "steps": 5},
                    {"id": "dhis2-programme-vc", "steps": 6},
                    {"id": "social-aggregate", "steps": 4},
                    {"id": "combined-support", "steps": 6},
                    {"id": "agriculture-voucher", "steps": 5},
                ],
            },
        ),
        ("GET", "/api/lab.json"): lab_route,
        ("GET", "/.well-known/openid-credential-issuer"): (
            200,
            {
                "credential_issuer": "https://issuer.example",
                "credential_endpoint": "https://issuer.example/oid4vci/credential",
                "credential_configurations_supported": {
                    "person_is_alive_sd_jwt": {"format": "dc+sd-jwt"},
                },
            },
        ),
        ("GET", "/api/scenarios/alive-proof.json"): (
            200,
            {"story": {"steps": [{"id": "discover"}, {"id": "prepare-evidence"}, {"id": "deny-row"}]}},
        ),
        ("GET", "/api/scenarios/civil-birth-demographics.json"): (
            200,
            {"story": {"steps": [{"id": "discover"}, {"id": "lookup"}]}},
        ),
        ("GET", "/api/scenarios/civil-birth-evidence.json"): (
            200,
            {"story": {"steps": [{"id": "discover"}, {"id": "evaluate"}]}},
        ),
        ("GET", "/api/scenarios/civil-birth-evidence-demographics.json"): (
            200,
            {"story": {"steps": [{"id": "discover"}, {"id": "evaluate"}]}},
        ),
        ("GET", "/api/scenarios/civil-marriage-evidence.json"): (
            200,
            {"story": {"steps": [{"id": "discover"}, {"id": "evaluate"}]}},
        ),
        ("GET", "/api/scenarios/wallet-credential.json"): (
            200,
            {
                "story": {
                    "steps": [
                        {"id": "issuer-metadata"},
                        {"id": "credential-offer"},
                        {"id": "holder-key"},
                        {"id": "nonce"},
                        {"id": "credential-preview"},
                    ]
                }
            },
        ),
        ("GET", "/api/scenarios/dhis2-programme-vc.json"): (
            200,
            {
                "story": {
                    "steps": [
                        {"id": "discover"},
                        {"id": "evaluate-programme"},
                        {"id": "preview-vc"},
                        {"id": "reconcile"},
                        {"id": "negative-control"},
                        {"id": "render-cccev"},
                    ]
                }
            },
        ),
        ("GET", "/api/scenarios/social-aggregate.json"): (
            200,
            {
                "story": {
                    "steps": [
                        {"id": "discover"},
                        {"id": "read-aggregate"},
                        {"id": "deny-row-with-aggregate"},
                        {"id": "read-row-with-row-token"},
                    ]
                }
            },
        ),
        ("GET", "/api/scenarios/combined-support.json"): (
            200,
            {
                "story": {
                    "steps": [
                        {"id": "discover"},
                        {"id": "civil-subclaim"},
                        {"id": "social-subclaim"},
                        {"id": "health-subclaim"},
                        {"id": "final-positive"},
                        {"id": "negative-control"},
                    ]
                }
            },
        ),
        ("GET", "/api/scenarios/agriculture-voucher.json"): (
            200,
            {
                "story": {
                    "steps": [
                        {"id": "discover"},
                        {"id": "positive-voucher"},
                        {"id": "inactive-parcel-control"},
                        {"id": "redeemed-control"},
                        {"id": "reason-code"},
                    ]
                }
            },
        ),
        ("GET", "/api/explorer/registries.json"): (
            200,
            {
                "registries": [
                    {
                        "id": "civil",
                        "default_dataset": "civil_registry",
                        "default_entity": "civil_person",
                        "default_limit": 1,
                    },
                    {
                        "id": "social-protection",
                        "default_dataset": "social_protection_registry",
                        "default_entity": "household",
                        "default_aggregate": "households_by_eligibility_band",
                        "default_limit": 1,
                    },
                ]
            },
        ),
        ("GET", "/api/explorer/registries/civil/metadata.json"): (200, {"ok": True, "registry": {"id": "civil"}}),
        ("GET", "/api/explorer/registries/civil/entity-schema.json?dataset=civil_registry&entity=civil_person"): (
            200,
            {"fields": [{"name": "national_id"}]},
        ),
        ("GET", "/api/explorer/registries/civil/records.json?dataset=civil_registry&entity=civil_person&limit=1"): (
            200,
            {"records": [{"national_id": "NID-1001"}]},
        ),
        ("GET", "/api/explorer/registries/social-protection/metadata.json"): (
            200,
            {"ok": True, "registry": {"id": "social-protection"}},
        ),
        (
            "GET",
            "/api/explorer/registries/social-protection/entity-schema.json?dataset=social_protection_registry&entity=household",
        ): (200, {"fields": [{"name": "household_id"}]}),
        (
            "GET",
            "/api/explorer/registries/social-protection/records.json?dataset=social_protection_registry&entity=household&limit=1",
        ): (200, {"records": [{"household_id": "HH-1001"}]}),
        ("GET", "/api/explorer/registries/social-protection/aggregates.json?dataset=social_protection_registry"): (
            200,
            {"aggregates": [{"id": "households_by_eligibility_band"}]},
        ),
        (
            "GET",
            "/api/explorer/registries/social-protection/aggregate.json?dataset=social_protection_registry&aggregate=households_by_eligibility_band",
        ): (200, {"records": [{"eligibility_band": "priority", "household_count": 3}]}),
        ("GET", "/api/explorer/claims.json"): (
            200,
            {
                "default_format": "application/vnd.registry-notary.claim-result+json",
                "claim_services": [
                    {"id": "civil-notary"},
                    {"id": "social-protection-notary"},
                    {"id": "shared-eligibility-notary"},
                    {"id": "dhis2-notary"},
                    {"id": "opencrvs-notary"},
                    {"id": "agriculture-notary"},
                ],
            },
        ),
    }
    for service_id, default_claim, subject, scheme in [
        ("civil-notary", "person-is-alive", "NID-1001", "national_id"),
        ("social-protection-notary", "beneficiary-active", "NID-1001", "national_id"),
        ("shared-eligibility-notary", "eligible-for-combined-support", "NID-1001", "national_id"),
        ("dhis2-notary", "dhis2-child-program-active", "PQfMcpmXeFE", "dhis2_tracked_entity"),
        ("opencrvs-notary", "opencrvs-birth-record-exists", "BIRTH-1001", "birth_registration_id"),
        ("agriculture-notary", "eligible-for-climate-smart-input-voucher", "FARMER-1001", "farmer_id"),
    ]:
        routes[("GET", f"/api/explorer/claims/{service_id}/metadata.json")] = (
            200,
            {
                "ok": True,
                "claim_service": {
                    "id": service_id,
                    "default_claim": default_claim,
                    "default_subject": subject,
                    "default_identifier_scheme": scheme,
                    "default_purpose": "https://demo.example.gov/purpose/decentralized-evidence-demo",
                    "claims": [
                        {
                            "id": default_claim,
                            "default_disclosure": "predicate",
                            "formats": ["application/vnd.registry-notary.claim-result+json"],
                        }
                    ],
                },
            },
        )
        if service_id in hosted_smoke.DEFAULT_EVALUATED_CLAIM_SERVICES:
            routes[("POST", f"/api/explorer/claims/{service_id}/evaluate.json")] = (
                200,
                {"mode": "live", "answer": {"claim_id": default_claim, "satisfied": True}},
            )
    for scenario, steps in hosted_smoke.EXPECTED_STEP_STATUSES.items():
        for step, status in steps.items():
            routes[("POST", f"/api/scenarios/{scenario}/{step}")] = (
                200,
                {"step_id": step, "friendly": {"status": status, "facts": []}},
            )
    return routes


def lab_route(server: StubServer, method: str, path: str, body: Any) -> tuple[int, dict[str, Any]]:
    return (
        200,
        {
            "wallet": {
                "issuer": server.url,
                "credential_configuration_id": "person_is_alive_sd_jwt",
            },
            "credentials": [
                {
                    "id": "dhis2-bearer",
                    "env": "DHIS2_EVIDENCE_CLIENT_BEARER",
                    "service_url": server.url,
                    "token": "",
                }
            ],
        },
    )


class HostedSmokeTest(unittest.TestCase):
    def test_success_smoke_checks_public_contract(self) -> None:
        with StubServer(base_routes()) as server:
            summary = hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))

        self.assertEqual(summary["credential_smoke"], "skipped")
        self.assertEqual(summary["scenarios"]["alive-proof"]["deny-row"], "denied_as_expected")
        self.assertEqual(summary["scenarios"]["civil-birth-demographics"]["lookup"], "done")
        self.assertEqual(summary["scenarios"]["social-aggregate"]["deny-row-with-aggregate"], "denied_as_expected")
        self.assertEqual(summary["scenarios"]["combined-support"]["final-positive"], "done")
        self.assertEqual(summary["scenarios"]["agriculture-voucher"]["positive-voucher"], "done")
        self.assertEqual(summary["explorers"]["claims"]["agriculture-notary"]["default_evaluation"], "live")
        self.assertEqual(summary["explorers"]["claims"]["opencrvs-notary"]["default_evaluation"], "metadata")
        self.assertEqual(summary["explorers"]["registries"]["social-protection"]["aggregate_records"], 1)
        requested_paths = [path for _, path, _ in server.requests]
        self.assertIn("/api/scenarios/alive-proof/discover", requested_paths)
        self.assertIn("/api/scenarios/civil-birth-demographics/lookup", requested_paths)
        self.assertIn("/api/scenarios/wallet-credential/credential-preview", requested_paths)
        self.assertIn("/api/scenarios/social-aggregate/read-aggregate", requested_paths)
        self.assertIn("/api/scenarios/combined-support/final-positive", requested_paths)
        self.assertIn("/api/scenarios/dhis2-programme-vc/render-cccev", requested_paths)
        self.assertIn("/api/scenarios/agriculture-voucher/positive-voucher", requested_paths)
        self.assertIn("/api/explorer/registries/civil/records.json?dataset=civil_registry&entity=civil_person&limit=1", requested_paths)
        self.assertIn("/api/explorer/claims/agriculture-notary/evaluate.json", requested_paths)
        self.assertIn("/.well-known/openid-credential-issuer", requested_paths)

    def test_scenario_catalogue_order_does_not_matter(self) -> None:
        routes = base_routes()
        status, body = routes[("GET", "/api/scenarios.json")]
        body = dict(body)
        body["scenarios"] = list(reversed(body["scenarios"]))
        routes[("GET", "/api/scenarios.json")] = (status, body)

        with StubServer(routes) as server:
            summary = hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))

        self.assertEqual(summary["stories"]["civil-birth-demographics"], 2)

    def test_none_registry_defaults_fail_without_none_url_requests(self) -> None:
        routes = base_routes()
        routes[("GET", "/api/explorer/registries.json")] = (
            200,
            {"registries": [{"id": "civil", "default_dataset": None, "default_entity": "civil_person"}]},
        )

        with StubServer(routes) as server:
            with self.assertRaises(hosted_smoke.SmokeFailure) as raised:
                hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))
            requested_paths = [path for _, path, _ in server.requests]

        self.assertIn("registry-explorer-defaults-missing", str(raised.exception))
        self.assertFalse(any("None" in path for path in requested_paths))

    def test_none_registry_aggregate_is_skipped(self) -> None:
        routes = base_routes()
        routes[("GET", "/api/explorer/registries.json")] = (
            200,
            {
                "registries": [
                    {
                        "id": "civil",
                        "default_dataset": "civil_registry",
                        "default_entity": "civil_person",
                        "default_aggregate": None,
                        "default_limit": 1,
                    }
                ]
            },
        )

        with StubServer(routes) as server:
            summary = hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))
            requested_paths = [path for _, path, _ in server.requests]

        self.assertEqual(summary["explorers"]["registries"]["civil"]["aggregate_records"], 0)
        self.assertFalse(any("/aggregates" in path or "/aggregate.json" in path for path in requested_paths))

    def test_none_claim_service_id_fails_without_none_url_requests(self) -> None:
        routes = base_routes()
        routes[("GET", "/api/explorer/claims.json")] = (
            200,
            {"default_format": "application/vnd.registry-notary.claim-result+json", "claim_services": [{"id": None}]},
        )

        with StubServer(routes) as server:
            with self.assertRaises(hosted_smoke.SmokeFailure) as raised:
                hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))
            requested_paths = [path for _, path, _ in server.requests]

        self.assertIn("claims-explorer-service-id-missing", str(raised.exception))
        self.assertFalse(any("/claims/None/" in path for path in requested_paths))

    def test_none_default_claim_fails_without_evaluation_request(self) -> None:
        routes = base_routes()
        routes[("GET", "/api/explorer/claims/civil-notary/metadata.json")] = (
            200,
            {
                "ok": True,
                "claim_service": {
                    "id": "civil-notary",
                    "default_claim": None,
                    "claims": [
                        {
                            "id": "person-is-alive",
                            "default_disclosure": "predicate",
                            "formats": ["application/vnd.registry-notary.claim-result+json"],
                        }
                    ],
                },
            },
        )

        with StubServer(routes) as server:
            with self.assertRaises(hosted_smoke.SmokeFailure) as raised:
                hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))
            requested_paths = [path for _, path, _ in server.requests]

        self.assertIn("claims-explorer-default-claim-missing", str(raised.exception))
        self.assertNotIn("/api/explorer/claims/civil-notary/evaluate.json", requested_paths)

    def test_missing_story_step_fails_with_clear_contract_error(self) -> None:
        routes = base_routes()
        routes[("GET", "/api/scenarios/dhis2-programme-vc.json")] = (
            200,
            {"story": {"steps": [{"id": "discover"}, {"id": "evaluate-programme"}]}},
        )
        with StubServer(routes) as server:
            with self.assertRaises(hosted_smoke.SmokeFailure) as raised:
                hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))

        self.assertIn("scenario-story-step-mismatch", str(raised.exception))
        self.assertIn("render-cccev", str(raised.exception))

    def test_bad_friendly_status_fails(self) -> None:
        routes = base_routes()
        routes[("POST", "/api/scenarios/alive-proof/prepare-evidence")] = (
            200,
            {"step_id": "prepare-evidence", "friendly": {"status": "needs_attention"}},
        )
        with StubServer(routes) as server:
            with self.assertRaises(hosted_smoke.SmokeFailure) as raised:
                hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))

        text = str(raised.exception)
        self.assertIn("scenario-step-status-mismatch", text)
        self.assertIn("prepare-evidence", text)
        self.assertIn("needs_attention", text)

    def test_missing_oid4vci_metadata_fails(self) -> None:
        routes = base_routes()
        routes[("GET", "/.well-known/openid-credential-issuer")] = (
            200,
            {
                "credential_issuer": "https://issuer.example",
                "credential_endpoint": "https://issuer.example/oid4vci/credential",
                "credential_configurations_supported": {},
            },
        )
        with StubServer(routes) as server:
            with self.assertRaises(hosted_smoke.SmokeFailure) as raised:
                hosted_smoke.run_smoke(hosted_smoke.SmokeConfig(base_url=server.url))

        self.assertIn("citizen-issuer-configuration-missing", str(raised.exception))
        self.assertNotIn("person_is_alive_sd_jwt", str(raised.exception).split("seen", 1)[-1])

    def test_failure_redaction_removes_sensitive_fields(self) -> None:
        raw_credential = (
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImRjK3NkLWp3dCJ9."
            "eyJpc3MiOiJkaWQ6d2ViOmV4YW1wbGUifQ.signature"
        )
        failure = hosted_smoke.SmokeFailure(
            "redaction-check",
            {
                "Authorization": "Bearer super-secret-demo-token",
                "auth_header": "Authorization: Bearer second-secret-demo-token",
                "credential": raw_credential,
                "disclosures": ["very-sensitive-disclosure"],
                "holder": {
                    "id": "did:jwk:eyJrdHkiOiJFZDI1NTE5IiwieCI6InNlbnNpdGl2ZSJ9",
                    "proof": raw_credential,
                },
                "message": f"server echoed {raw_credential}",
            },
        )
        text = str(failure)

        self.assertIn("[redacted]", text)
        self.assertNotIn("super-secret-demo-token", text)
        self.assertNotIn("second-secret-demo-token", text)
        self.assertNotIn("very-sensitive-disclosure", text)
        self.assertNotIn(raw_credential, text)
        self.assertNotIn("did:jwk:eyJrdHki", text)

    def test_observed_answer_falls_back_to_value_when_satisfied_is_null(self) -> None:
        self.assertEqual(
            hosted_smoke.observed_answer({"satisfied": None, "value": "dhis2:tracked-entity:PQfMcpmXeFE"}),
            "dhis2:tracked-entity:PQfMcpmXeFE",
        )


if __name__ == "__main__":
    unittest.main()
