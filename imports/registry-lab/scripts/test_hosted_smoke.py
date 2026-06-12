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
                    {"id": "social-aggregate", "steps": 4},
                    {"id": "combined-support", "steps": 6},
                    {"id": "dhis2-programme-vc", "steps": 6},
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
    }
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
        self.assertEqual(summary["scenarios"]["social-aggregate"]["deny-row-with-aggregate"], "denied_as_expected")
        self.assertEqual(summary["scenarios"]["combined-support"]["final-positive"], "done")
        requested_paths = [path for _, path, _ in server.requests]
        self.assertIn("/api/scenarios/alive-proof/discover", requested_paths)
        self.assertIn("/api/scenarios/social-aggregate/read-aggregate", requested_paths)
        self.assertIn("/api/scenarios/combined-support/final-positive", requested_paths)
        self.assertIn("/api/scenarios/dhis2-programme-vc/render-cccev", requested_paths)
        self.assertIn("/.well-known/openid-credential-issuer", requested_paths)

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
