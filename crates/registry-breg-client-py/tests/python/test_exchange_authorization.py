"""Real Python binding proof for immutable person and renewable grant authorization."""

import base64
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from bootstrap import ensure_built

ensure_built()
from registry_breg_client import BaseRegistryClient, BaseRegistryClientError  # noqa: E402


KEY = json.loads(Path(__file__).with_name("exchange-test-key.json").read_text())
GRANT = "00000000-0000-4000-8000-000000000042"
TRACE = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def jwt(claims):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    return f"{encode({'alg':'EdDSA','kid':'authority-key','typ':'JWT'})}.{encode(claims)}.signature"


class ExchangeAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.forms = []
        self.assertions = 0
        self.reads = 0
        self.token_expires_in = 1
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path == "/token":
                    form = parse_qs(self.rfile.read(int(self.headers.get("content-length", "0"))).decode())
                    owner.forms.append(form)
                    bootstrap = form["grant_type"] == ["client_credentials"]
                    body = {"access_token": "bootstrap" if bootstrap else "task-token", "token_type": "Bearer",
                            "expires_in": 60 if bootstrap else owner.token_expires_in,
                            "scope": "casework:grants:assert" if bootstrap else "records:get"}
                    if not bootstrap:
                        body["issued_token_type"] = "urn:ietf:params:oauth:token-type:access_token"
                    self.reply(200, body)
                elif self.path == f"/v1/task-grants/{GRANT}/assertion":
                    owner.assertions += 1
                    owner.assertEqual(self.headers.get("authorization"), "Bearer bootstrap")
                    owner.assertEqual(self.rfile.read(int(self.headers.get("content-length", "0"))), b"")
                    if owner.assertions > 1:
                        self.reply(403, {})
                        return
                    now = int(time.time())
                    self.reply(200, {"assertion": jwt({"iss":"https://casework.example", "sub":"agent-1",
                        "aud":"https://issuer.example", "iat":now, "nbf":now, "exp":now+60, "jti":"assertion-1",
                        "scope":"records:get", "registry_actor_kind":"agent", "registry_grant_id":GRANT,
                        "registry_grant_client":"agent-client", "registry_grant_resource":"urn:records",
                        "registry_grant_exp":owner.deadline}), "expiresAt": now+60, "grantExpiresAt": owner.deadline})

            def do_GET(self):
                owner.reads += 1
                owner.assertEqual(self.headers.get("authorization"), owner.expected_token)
                self.reply(200, {}, trace=True)

            def reply(self, status, body, trace=False):
                encoded = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(encoded)))
                if trace:
                    self.send_header("traceparent", TRACE)
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.deadline = int(time.time()) + 120

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def key_client(self, resource, scopes):
        return {"token_endpoint":f"{self.origin}/token", "client_id":"agent-client", "client_key":KEY,
                "resource":resource, "scopes":scopes}

    def test_remote_provider_uses_fresh_casework_assertion_and_refuses_revocation(self):
        self.expected_token = "Bearer task-token"
        config = {"client":self.key_client("urn:records", ["records:get"]),
            "context":{"issuer":"https://casework.example", "subject":"agent-1", "audience":"https://issuer.example",
                       "generation":"grant-1", "deadline_seconds":self.deadline, "grant_id":GRANT},
            "remote":{"endpoint":f"{self.origin}/v1/task-grants/{GRANT}/assertion",
                      "bootstrap":self.key_client("urn:casework", ["casework:grants:assert"]),
                      "bootstrap_resource":"urn:casework", "bootstrap_scope":"casework:grants:assert"}}
        client = BaseRegistryClient(self.origin, authorization={"exchange":config})
        client.registry_metadata()
        with self.assertRaises(BaseRegistryClientError):
            client.registry_metadata()
        self.assertEqual(self.assertions, 2)
        self.assertEqual(self.reads, 1)

    def test_first_party_person_context_is_signed_without_grant_claims(self):
        self.expected_token = "Bearer task-token"
        self.token_expires_in = 300
        config = {"client":self.key_client("urn:records", ["records:get"]),
            "context":{"issuer":"https://portal.example", "subject":"person-1", "audience":"https://issuer.example",
                       "generation":"verified-person-1", "deadline_seconds":self.deadline},
            "first_party":{"key":KEY, "attributes":{"registry_actor_kind":"human", "identity":{"person_reference":"person-1"}}}}
        client = BaseRegistryClient(self.origin, authorization={"exchange":config})
        client.registry_metadata()
        client.registry_metadata()
        self.assertEqual(len(self.forms), 1)
        encoded = self.forms[0]["subject_token"][0].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(claims["sub"], "person-1")
        self.assertEqual(claims["scope"], "records:get")
        self.assertNotIn("registry_grant_id", claims)
