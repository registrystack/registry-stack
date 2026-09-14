"""Native profile plus exchange binding and definition-pin proof."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS_DIR))
import bootstrap  # noqa: E402

bootstrap.ensure_built()
import registry_evidence_client as revc  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[4]
CONTRACTS = json.loads((ROOT / "products/breg/acceptance/farmer-landholding-evidence/evidence/farmer-contracts.json").read_text())
JWKS = json.loads((ROOT / "crates/registry-evidence-client-py/tests/fixtures/jwks.json").read_text())
KEY = {
    "kty": "EC", "crv": "P-256", "alg": "ES256",
    "kid": "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo",
    "d": "MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4",
    "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
    "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU",
}


class ProfileExchangeTest(unittest.TestCase):
    def test_profile_exchange_preserves_authority_and_selected_definition_pins(self):
        requests = []
        revision = [CONTRACTS["definitions"][0]["configurationRevision"]]

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.handle_request()

            def do_POST(self):
                self.handle_request()

            def handle_request(self):
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                requests.append((self.command, self.path, body, self.headers.get("authorization")))
                origin = f"http://127.0.0.1:{self.server.server_port}"
                if self.path == "/.well-known/oauth-protected-resource":
                    payload = {"resource": origin, "authorization_servers": [origin],
                               "jwks_uri": f"{origin}/.well-known/evidence/jwks.json",
                               "bearer_methods_supported": ["header"]}
                elif self.path == "/.well-known/oauth-authorization-server":
                    payload = {"issuer": origin, "token_endpoint": f"{origin}/token",
                               "grant_types_supported": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
                               "token_endpoint_auth_methods_supported": ["private_key_jwt"]}
                elif self.path == "/.well-known/evidence/jwks.json":
                    payload = JWKS
                elif self.path == "/token":
                    form = parse_qs(body.decode())
                    if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:token-exchange"]:
                        self.reply(400, {}, "application/json")
                        return
                    payload = {"access_token": "staff-token", "token_type": "Bearer", "expires_in": 300,
                               "scope": "evidence:invoke", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"}
                elif self.path == "/v1/evidence-definitions":
                    payload = {**CONTRACTS, "schema": "registry.evidence-definitions/v1", "holderBoundBatchMaxSize": 1,
                               "definitions": [dict(CONTRACTS["definitions"][0], configurationRevision=revision[0]),
                                               *CONTRACTS["definitions"][1:]]}
                elif self.path == "/v1/evidence":
                    self.reply(503, {"type": "about:blank", "title": "synthetic refusal", "status": 503},
                               "application/problem+json")
                    return
                else:
                    self.reply(404, {}, "application/json")
                    return
                media = "application/jwk-set+json" if self.path.endswith("jwks.json") else "application/json"
                self.reply(200, payload, media)

            def reply(self, status, payload, media):
                encoded = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", media)
                self.send_header("content-length", str(len(encoded)))
                self.send_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{server.server_port}"
        try:
            with tempfile.TemporaryDirectory(prefix="evidence-profile-exchange-") as directory:
                profile_path = pathlib.Path(directory) / "client.json"
                profile_path.write_text(json.dumps({
                    "schema": "registry.evidence-client-profile/v1", "baseUrl": origin,
                    "clientId": "profile-staff",
                    "privateKey": {"source": "environment", "variable": "UNUSED_PROFILE_EXCHANGE_KEY"},
                    "trust": {"type": "local-loopback-discovery"}, "contracts": {"type": "published"},
                    "oauth": {"resource": "urn:registry:evidence", "scopes": ["evidence:invoke"]},
                    "expected": {"definitions": {"farmer-status": {
                        "configurationRevision": revision[0], "evidenceType": CONTRACTS["definitions"][0]["evidenceType"],
                        "purpose": CONTRACTS["definitions"][0]["purpose"],
                        "assuranceProfile": CONTRACTS["assuranceProfile"], "responseFormat": "signed-jws",
                    }}},
                }))
                profile_path.chmod(0o600)

                def authorization(resource):
                    return {"exchange": {
                        "client": {"token_endpoint": f"{origin}/token", "client_id": "profile-staff",
                                   "client_key": KEY, "resource": resource, "scopes": ["evidence:invoke"]},
                        "context": {"issuer": "https://portal.example", "subject": "person-1",
                                    "audience": origin, "generation": "verified-1",
                                    "deadline_seconds": int(time.time()) + 120},
                        "first_party": {"key": KEY, "attributes": {"registry_actor_kind": "human"}},
                    }}

                request = lambda client: client.request("farmer-status", **{"farmer-number": "F-123"})
                mismatched = revc.EvidenceClient.from_profile_with_authorization(
                    str(profile_path), authorization("urn:wrong"))
                with self.assertRaises(revc.ConfigurationError):
                    request(mismatched)
                self.assertFalse(any(path == "/token" for _, path, _, _ in requests))

                client = revc.EvidenceClient.from_profile_with_authorization(
                    str(profile_path), authorization("urn:registry:evidence"))
                with self.assertRaises(revc.EvidenceClientError):
                    request(client)
                self.assertEqual(sum(path == "/token" for _, path, _, _ in requests), 1)
                self.assertEqual(sum(path == "/v1/evidence" for _, path, _, _ in requests), 1)

                revision[0] = "sha256:" + "2" * 64
                drifted = revc.EvidenceClient.from_profile_with_authorization(
                    str(profile_path), authorization("urn:registry:evidence"))
                with self.assertRaises(revc.ConfigurationError):
                    request(drifted)
                self.assertEqual(sum(path == "/v1/evidence" for _, path, _, _ in requests), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
