from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from registry_notary import RegistryNotaryClient, RetryPolicy
from registry_notary.client import _parse_retry_after
from registry_notary.errors import NotaryError, NotaryProblemError


class _Recorder:
    requests: list[dict[str, Any]]

    def __init__(
        self,
        status: int = 200,
        body: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        responses: list[tuple[int, dict[str, Any] | bytes, dict[str, str] | None]] | None = None,
    ) -> None:
        self.status = status
        self.body = (
            body if body is not None else {"results": [{"claim_id": "age", "value": True}]}
        )
        self.raw_body = raw_body
        self.responses = responses or []
        self.requests = []

    def response(self) -> tuple[int, bytes, dict[str, str]]:
        if self.responses:
            status, body, headers = self.responses.pop(0)
            payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            return status, payload, headers or {}
        payload = self.raw_body or json.dumps(self.body).encode("utf-8")
        return self.status, payload, {}


class _Handler(BaseHTTPRequestHandler):
    recorder: _Recorder

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        raw_body = self.rfile.read(length)
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = raw_body.decode("utf-8", errors="replace")
        self.recorder.requests.append(
            {
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": body,
            }
        )
        status, payload, extra_headers = self.recorder.response()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("x-request-id", "req-test-1")
        for key, value in extra_headers.items():
            self.send_header(key, value)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        self.recorder.requests.append(
            {
                "path": self.path,
                "headers": dict(self.headers.items()),
                "body": None,
            }
        )
        status, payload, extra_headers = self.recorder.response()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("x-request-id", "req-test-1")
        for key, value in extra_headers.items():
            self.send_header(key, value)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *args: object) -> None:
        return


class Server:
    def __init__(self, recorder: _Recorder) -> None:
        handler = type("RecorderHandler", (_Handler,), {"recorder": recorder})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True

    def __enter__(self) -> str:
        self.thread.start()
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class RegistryNotaryClientTests(unittest.TestCase):
    def test_constructor_rejects_multiple_auth_modes_and_cleartext_non_loopback(self) -> None:
        with self.assertRaises(NotaryError) as multiple:
            RegistryNotaryClient(
                base_url="https://notary.example",
                bearer_token="token",
                api_key="key",
            )
        self.assertEqual(multiple.exception.code, "build.multiple_auth_modes")

        with self.assertRaises(NotaryError) as cleartext:
            RegistryNotaryClient(base_url="http://notary.example")
        self.assertEqual(cleartext.exception.code, "build.insecure_base_url")

        client = RegistryNotaryClient(
            base_url="http://registry-notary:8080",
            allow_insecure_internal_http=True,
        )
        self.assertIn("http://registry-notary:8080", repr(client))

    def test_high_level_evaluate_uses_target_args_and_wire_snake_case(self) -> None:
        recorder = _Recorder()
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url, default_purpose="benefits")
            result = client.evaluate(target_id="subj-1", identifier_scheme="NATIONAL_ID", claims=["age"])

        self.assertEqual(result["results"][0]["claim_id"], "age")
        self.assertEqual(recorder.requests[0]["path"], "/v1/evaluations")
        self.assertEqual(
            recorder.requests[0]["body"],
            {
                "target": {
                    "type": "Person",
                    "identifiers": [{"scheme": "NATIONAL_ID", "value": "subj-1"}],
                },
                "claims": ["age"],
            },
        )
        self.assertNotIn("idType", json.dumps(recorder.requests[0]["body"]))
        self.assertEqual(
            recorder.requests[0]["headers"]["Accept"],
            "application/vnd.registry-notary.claim-result+json",
        )
        self.assertEqual(recorder.requests[0]["headers"]["Data-Purpose"], "benefits")

    def test_raw_evaluate_request_passes_snake_case_through(self) -> None:
        recorder = _Recorder()
        raw_request = {
            "target": {"type": "Person", "identifiers": [{"scheme": "NATIONAL_ID", "value": "subj-2"}]},
            "claims": ["age"],
            "purpose": "eligibility",
        }
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            client.evaluate_request(raw_request)

        self.assertEqual(recorder.requests[0]["body"], raw_request)
        self.assertEqual(recorder.requests[0]["headers"]["Data-Purpose"], "eligibility")

    def test_high_level_evaluate_rejects_single_claim_string_or_mapping(self) -> None:
        client = RegistryNotaryClient(base_url="https://notary.example")

        with self.assertRaises(NotaryError) as string_error:
            client.evaluate(
                target_id="subj-1",
                identifier_scheme="NATIONAL_ID",
                claims="age",  # type: ignore[arg-type]
            )
        self.assertEqual(string_error.exception.code, "request.invalid_claims")

        with self.assertRaises(NotaryError) as mapping_error:
            client.evaluate(
                target_id="subj-1",
                identifier_scheme="NATIONAL_ID",
                claims={"id": "age", "version": "2026-05"},  # type: ignore[arg-type]
            )
        self.assertEqual(mapping_error.exception.code, "request.invalid_claims")

    def test_async_evaluate_returns_response(self) -> None:
        recorder = _Recorder()
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            result = asyncio.run(
                client.aevaluate(target_id="subj-3", identifier_scheme="NATIONAL_ID", claims=["age"])
            )

        self.assertEqual(result["results"][0]["value"], True)
        self.assertEqual(
            recorder.requests[0]["body"]["target"]["identifiers"][0]["scheme"],
            "NATIONAL_ID",
        )

    def test_batch_evaluate_sends_idempotency_key(self) -> None:
        recorder = _Recorder(body={"batch_id": "batch-1", "status": "completed"})
        request = {
            "items": [{"target": {"type": "Person", "identifiers": [{"scheme": "NATIONAL_ID", "value": "subj-1"}]}}],
            "claims": ["age"],
        }
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url, default_purpose="benefits")
            result = client.batch_evaluate_request(request, idempotency_key="batch-key")

        self.assertEqual(result["batch_id"], "batch-1")
        self.assertEqual(recorder.requests[0]["path"], "/v1/batch-evaluations")
        self.assertEqual(recorder.requests[0]["headers"]["Idempotency-Key"], "batch-key")
        self.assertEqual(recorder.requests[0]["headers"]["Data-Purpose"], "benefits")

    def test_async_batch_render_and_issue_methods_return_responses(self) -> None:
        recorder = _Recorder(body={"batch_id": "batch-1"})
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            batch = asyncio.run(
                client.abatch_evaluate_request(
                    {"items": [{"target": {"type": "Person", "id": "subj-1"}}], "claims": ["age"]},
                    idempotency_key="batch-key",
                )
            )
        self.assertEqual(batch["batch_id"], "batch-1")
        self.assertEqual(recorder.requests[0]["headers"]["Idempotency-Key"], "batch-key")

        recorder = _Recorder(body={"rendered": True})
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            rendered = asyncio.run(client.arender_request({"evaluation_id": "eval-1"}))
        self.assertTrue(rendered["rendered"])

        recorder = _Recorder(body={"credential_id": "cred-1"})
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            issued = asyncio.run(client.aissue_credential_request({"evaluation_id": "eval-1"}))
        self.assertEqual(issued["credential_id"], "cred-1")

    def test_core_route_helpers_cover_get_render_issue_and_status(self) -> None:
        recorder = _Recorder(body={"data": [{"id": "age"}]})
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            listed = client.list_claims()

        self.assertEqual(listed["data"][0]["id"], "age")
        self.assertEqual(recorder.requests[0]["path"], "/v1/claims")

        recorder = _Recorder(body={"document": {"ok": True}})
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            rendered = client.render_request({"evaluation_id": "eval-1", "format": "json"})

        self.assertEqual(rendered["document"]["ok"], True)
        self.assertEqual(recorder.requests[0]["path"], "/v1/evaluations/eval-1/render")
        self.assertNotIn("evaluation_id", recorder.requests[0]["body"])

        recorder = _Recorder(body={"credential_id": "cred-1"})
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            issued = client.issue_credential_request({"evaluation_id": "eval-1"})

        self.assertEqual(issued["credential_id"], "cred-1")
        self.assertEqual(recorder.requests[0]["path"], "/v1/credentials")

        recorder = _Recorder(body={"credential_id": "cred-1", "status": "valid"})
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            status = client.credential_status("cred-1")

        self.assertEqual(status["status"], "valid")
        self.assertEqual(recorder.requests[0]["path"], "/v1/credentials/cred-1/status")

        recorder = _Recorder(body={"id": "claim one"})
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            claim = client.get_claim("claim one")

        self.assertEqual(claim["id"], "claim one")
        self.assertEqual(recorder.requests[0]["path"], "/v1/claims/claim%20one")

    def test_cross_origin_redirect_strips_sdk_auth_headers(self) -> None:
        redirector = _Recorder()
        target = _Recorder(body={"data": []})
        with Server(target) as target_url:
            with Server(redirector) as base_url:
                redirector.responses = [
                    (302, b"", {"Location": f"{target_url}/v1/claims"}),
                ]
                client = RegistryNotaryClient(base_url=base_url, api_key="secret-api-key")
                client.list_claims()

        self.assertEqual(redirector.requests[0]["headers"]["X-Api-Key"], "secret-api-key")
        self.assertEqual(target.requests[0]["path"], "/v1/claims")
        self.assertNotIn("X-Api-Key", target.requests[0]["headers"])
        self.assertNotIn("Authorization", target.requests[0]["headers"])

    def test_same_origin_redirect_preserves_sdk_auth_headers(self) -> None:
        recorder = _Recorder(body={"data": []})
        with Server(recorder) as base_url:
            recorder.responses = [
                (302, b"", {"Location": f"{base_url}/v1/claims?redirected=true"}),
            ]
            client = RegistryNotaryClient(base_url=base_url, bearer_token="secret-bearer")
            client.list_claims()

        self.assertEqual(recorder.requests[0]["headers"]["Authorization"], "Bearer secret-bearer")
        self.assertEqual(recorder.requests[1]["path"], "/v1/claims?redirected=true")
        self.assertEqual(recorder.requests[1]["headers"]["Authorization"], "Bearer secret-bearer")

    def test_render_request_rejects_invalid_request_type(self) -> None:
        client = RegistryNotaryClient(base_url="https://notary.example")

        with self.assertRaises(NotaryError) as error:
            client.render_request(None)  # type: ignore[arg-type]

        self.assertEqual(error.exception.code, "request.invalid_type")

    def test_problem_error_mapping_redacts_detail(self) -> None:
        recorder = _Recorder(
            status=404,
            body={
                "type": "https://id.registrystack.org/problems/registry-notary/target/not-found",
                "title": "Target not found",
                "status": 404,
                "detail": "target subj-secret was not found",
                "code": "target.not_found",
            },
        )
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            with self.assertRaises(NotaryProblemError) as raised:
                client.evaluate(target_id="subj-secret", identifier_scheme="NATIONAL_ID", claims=["age"])

        error = raised.exception
        self.assertEqual(error.kind, "problem")
        self.assertEqual(error.status, 404)
        self.assertEqual(error.code, "target.not_found")
        self.assertEqual(error.title, "Target not found")
        self.assertFalse(error.retryable)
        self.assertEqual(error.request_id, "req-test-1")
        self.assertNotIn("target subj-secret", str(error))
        self.assertFalse(hasattr(error, "detail"))

    def test_decode_and_oversized_response_errors_are_redacted(self) -> None:
        recorder = _Recorder(raw_body=b"not-json-containing-subj-secret")
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            with self.assertRaises(NotaryProblemError) as decoded:
                client.list_claims()

        self.assertEqual(decoded.exception.kind, "decode")
        self.assertNotIn("subj-secret", str(decoded.exception))

        recorder = _Recorder(raw_body=b"x" * (8 * 1024 * 1024 + 1))
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            with self.assertRaises(NotaryProblemError) as oversized:
                client.list_claims()

        self.assertEqual(oversized.exception.kind, "body_too_large")
        self.assertNotIn("xxx", str(oversized.exception))

    def test_purpose_conflict_is_client_side_error(self) -> None:
        client = RegistryNotaryClient(base_url="http://127.0.0.1:1", default_purpose="one")
        with self.assertRaises(NotaryError) as raised:
            client.evaluate_request(
                {
                    "target": {"type": "Person", "identifiers": [{"scheme": "NATIONAL_ID", "value": "subj-4"}]},
                    "claims": ["age"],
                    "purpose": "two",
                }
            )
        self.assertEqual(raised.exception.code, "request.purpose_conflict")

    def test_retry_policy_retries_get_and_batch_only_when_safe(self) -> None:
        policy = RetryPolicy(
            max_attempts=2,
            base_delay=0,
            max_delay=0,
            retry_rate_limited=True,
            retry_unavailable=True,
        )
        recorder = _Recorder(
            responses=[
                (503, {"code": "busy", "title": "Busy"}, {"retry-after": "0"}),
                (200, {"data": [{"id": "age"}]}, None),
            ]
        )
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url, retry_policy=policy)
            listed = client.list_claims()

        self.assertEqual(listed["data"][0]["id"], "age")
        self.assertEqual(len(recorder.requests), 2)

        recorder = _Recorder(
            responses=[
                (503, {"code": "busy", "title": "Busy"}, None),
                (200, {"batch_id": "batch-1"}, None),
            ]
        )
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url, retry_policy=policy)
            batch = client.batch_evaluate_request(
                {"items": [{"target": {"type": "Person", "id": "subj-1"}}], "claims": ["age"]},
                idempotency_key="batch-key",
            )

        self.assertEqual(batch["batch_id"], "batch-1")
        self.assertEqual(len(recorder.requests), 2)

        recorder = _Recorder(
            responses=[
                (503, {"code": "busy", "title": "Busy"}, None),
                (200, {"results": []}, None),
            ]
        )
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url, retry_policy=policy)
            with self.assertRaises(NotaryProblemError):
                client.evaluate(target_id="subj-1", identifier_scheme="NATIONAL_ID", claims=["age"])

        self.assertEqual(len(recorder.requests), 1)

    def test_http_date_retry_after_uses_server_date_header(self) -> None:
        delay = _parse_retry_after(
            {
                "date": "Wed, 31 Dec 2099 00:00:00 GMT",
                "retry-after": "Wed, 31 Dec 2099 00:00:02 GMT",
            }
        )

        self.assertEqual(delay, 2.0)

    def test_discovery_jwks_oid4vci_and_federation_helpers(self) -> None:
        recorder = _Recorder(
            responses=[
                (200, {"keys": [{"kid": "key-1"}]}, None),
                (200, {"keys": [{"kid": "key-2"}]}, None),
                (200, {"keys": [{"kid": "key-3"}]}, None),
            ]
        )
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            first = client.issuer_jwks()
            second = client.issuer_jwks()
            jwk = client.get_jwk("key-2")
            refreshed = client.refresh_jwks()

        self.assertEqual(first, {"keys": [{"kid": "key-1"}]})
        self.assertEqual(second, first)
        self.assertEqual(jwk, {"kid": "key-2"})
        self.assertEqual(refreshed, {"keys": [{"kid": "key-3"}]})
        self.assertEqual([request["path"] for request in recorder.requests], [
            "/.well-known/evidence/jwks.json",
            "/.well-known/evidence/jwks.json",
            "/.well-known/evidence/jwks.json",
        ])

        recorder = _Recorder(
            responses=[
                (200, {"credential_issuer": "https://issuer.example"}, None),
                (200, {"credential_issuer": "https://issuer.example", "credentials": []}, None),
                (200, {"c_nonce": "nonce-secret"}, None),
                (200, {"format": "vc+sd-jwt", "credential": "credential-secret"}, None),
                (200, b"response.jws.compact", {"content-type": "application/jwt"}),
            ]
        )
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            metadata = client.oid4vci_issuer_metadata()
            offer = client.oid4vci_credential_offer("config one")
            nonce = client.oid4vci_nonce()
            credential = client.oid4vci_credential({"proof": {"jwt": "holder-proof-secret"}})
            jws = client.federation_evaluate_jws("request.jws.compact")

        self.assertEqual(metadata["credential_issuer"], "https://issuer.example")
        self.assertEqual(offer["credentials"], [])
        self.assertEqual(nonce["c_nonce"], "nonce-secret")
        self.assertEqual(credential["credential"], "credential-secret")
        self.assertEqual(jws, "response.jws.compact")
        self.assertEqual(recorder.requests[1]["path"], "/oid4vci/credential-offer?credential_configuration_id=config%20one")
        self.assertEqual(recorder.requests[3]["body"], {"proof": {"jwt": "holder-proof-secret"}})
        self.assertEqual(recorder.requests[4]["body"], "request.jws.compact")
        self.assertEqual(recorder.requests[4]["headers"]["Content-Type"], "application/jwt")

    def test_openspp_contract_routes_versioned_refs_retries_jwks_and_problem_codes(self) -> None:
        retry_policy = RetryPolicy(
            max_attempts=2,
            base_delay=0,
            max_delay=0,
            retry_unavailable=True,
        )
        versioned_ref = {"id": "eligibility.open_spp", "version": "2026-05"}
        recorder = _Recorder(
            responses=[
                (200, {"data": [{"id": "eligibility.open_spp", "version": "2026-05"}]}, None),
                (200, {"id": "eligibility.open_spp", "version": "2026-05"}, None),
                (
                    200,
                    {
                        "evaluation_id": "eval-1",
                        "results": [
                            {
                                "claim_id": "eligibility.open_spp",
                                "claim_version": "2026-05",
                                "satisfied": True,
                            }
                        ],
                    },
                    None,
                ),
                (503, {"code": "source.unavailable", "title": "Source unavailable"}, None),
                (200, {"batch_id": "batch-1", "status": "completed"}, None),
                (200, {"keys": [{"kid": "key-1"}]}, None),
                (200, {"credential_id": "cred-1"}, None),
                (200, {"status": "valid"}, None),
                (404, {"code": "claim.version_not_found", "title": "Claim version not found"}, None),
            ]
        )

        with Server(recorder) as base_url:
            client = RegistryNotaryClient(
                base_url=base_url,
                default_purpose="openspp.eligibility",
                retry_policy=retry_policy,
            )
            claims = client.list_claims()
            claim = client.get_claim("eligibility.open_spp")
            evaluation = client.evaluate(
                target_id="beneficiary-1",
                identifier_scheme="openspp_id",
                claims=[versioned_ref],
            )
            batch = client.batch_evaluate_request(
                {
                    "items": [{"target": {"type": "Person", "identifiers": [{"scheme": "openspp_id", "value": "beneficiary-1"}]}}],
                    "claims": [versioned_ref],
                },
                idempotency_key="openspp-batch-1",
            )
            jwks = client.issuer_jwks()
            issued = client.issue_credential_request({"evaluation_id": "eval-1"})
            status = client.credential_status("cred-1")
            with self.assertRaises(NotaryProblemError) as missing_version:
                client.evaluate_request({
                    "target": {"type": "Person", "identifiers": [{"scheme": "openspp_id", "value": "beneficiary-1"}]},
                    "claims": [{"id": "eligibility.open_spp", "version": "missing"}],
                })

        self.assertEqual(claims["data"][0]["id"], "eligibility.open_spp")
        self.assertEqual(claim["version"], "2026-05")
        self.assertEqual(evaluation["results"][0]["claim_version"], "2026-05")
        self.assertEqual(batch["batch_id"], "batch-1")
        self.assertEqual(jwks["keys"][0]["kid"], "key-1")
        self.assertEqual(issued["credential_id"], "cred-1")
        self.assertEqual(status["status"], "valid")
        self.assertEqual(missing_version.exception.code, "claim.version_not_found")
        self.assertEqual([request["path"] for request in recorder.requests], [
            "/v1/claims",
            "/v1/claims/eligibility.open_spp",
            "/v1/evaluations",
            "/v1/batch-evaluations",
            "/v1/batch-evaluations",
            "/.well-known/evidence/jwks.json",
            "/v1/credentials",
            "/v1/credentials/cred-1/status",
            "/v1/evaluations",
        ])
        self.assertEqual(recorder.requests[2]["body"]["claims"], [versioned_ref])
        self.assertEqual(recorder.requests[2]["headers"]["Accept"], "application/vnd.registry-notary.claim-result+json")
        self.assertEqual(recorder.requests[3]["headers"]["Idempotency-Key"], "openspp-batch-1")
        self.assertEqual(recorder.requests[4]["headers"]["Idempotency-Key"], "openspp-batch-1")

    def test_openspp_problem_codes_are_preserved_for_policy_mapping(self) -> None:
        stable_codes = [
            "target.not_found",
            "target.match_ambiguous",
            "source.unavailable",
            "claim.not_found",
            "claim.version_not_found",
            "claim.format_not_supported",
            "auth.purpose_required",
            "auth.missing_credential",
            "idempotency.conflict",
            "batch.too_large",
            "deployment.custom_problem",
        ]

        for code in stable_codes:
            with self.subTest(code=code):
                recorder = _Recorder(status=400, body={"code": code, "title": "Contract problem"})
                with Server(recorder) as base_url:
                    client = RegistryNotaryClient(base_url=base_url)
                    with self.assertRaises(NotaryProblemError) as raised:
                        client.list_claims()
                self.assertEqual(raised.exception.code, code)

    def test_oid4vci_errors_redact_description_and_nonce(self) -> None:
        recorder = _Recorder(
            status=400,
            body={
                "error": "invalid_proof",
                "error_description": "holder proof includes c_nonce nonce-secret",
            },
        )
        with Server(recorder) as base_url:
            client = RegistryNotaryClient(base_url=base_url)
            with self.assertRaises(NotaryProblemError) as raised:
                client.oid4vci_credential({"proof": {"jwt": "holder-proof-secret"}})

        self.assertEqual(raised.exception.kind, "oid4vci")
        self.assertEqual(raised.exception.code, "invalid_proof")
        self.assertNotIn("nonce-secret", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
