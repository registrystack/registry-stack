from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from bootstrap import ensure_built

ensure_built()
from registry_casework_client import CaseworkClient, CaseworkClientError

ITEM = "00000000-0000-4000-8000-000000000001"
GRANT = "00000000-0000-4000-8000-000000000002"
PREVIEW = {"id": "verify-status", "version": "1", "label": "Verify status", "agent": {"issuer": "https://issuer.example", "subject": "agent-one"}, "client": "agent-client", "resource": "urn:evidence", "scopes": ["evidence:invoke"], "purpose": "verify-status", "bounds": {"type": "evidence", "requirement": "status"}, "subjects": {"person_reference": "synthetic-reference"}, "lifetimeSeconds": 900}
VIEW = {"id": GRANT, "templateId": PREVIEW["id"], "templateVersion": "1", **{k: PREVIEW[k] for k in ("agent", "client", "resource", "scopes", "purpose", "bounds")}, "expiresAt": 2000000900, "invalidated": False}

class TaskGrantTests(unittest.TestCase):
    def test_bounded_human_approval_and_token_only_machine_requests(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self): self.respond()
            def do_POST(self): self.respond()
            def respond(self):
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                requests.append((self.path, dict(self.headers), body))
                if self.path.endswith("/task-templates"): value = {"itemRevision": 7, "templates": [PREVIEW]}
                elif self.path.endswith("/assertion"): value = {"assertion": "synthetic-assertion", "expiresAt": 2000000060, "grantExpiresAt": 2000000900}
                elif self.path.endswith("/status"): value = {"active": False}
                elif self.path.endswith("/revoke"): value = {"id": GRANT, "invalidated": True}
                else: value = VIEW if self.command == "POST" else {"grants": [VIEW]}
                self.send_response(200); self.send_header("content-type", "application/json"); self.send_header("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"); self.end_headers()
                self.wfile.write(json.dumps(value).encode())
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            client = CaseworkClient(f"http://127.0.0.1:{server.server_port}/")
            args = ("human-token", "staff", "source-reviewer", ITEM)
            self.assertEqual(client.preview_task_templates(*args)["value"]["templates"], [PREVIEW])
            self.assertEqual(client.list_task_grants(*args)["value"]["grants"], [VIEW])
            approval = {"templateId": "verify-status", "templateVersion": "1"}
            client.approve_task_grant(*args, 7, "caller-attempt-key", approval)
            headers = {k.lower(): v for k, v in requests[2][1].items()}
            self.assertEqual(headers["if-match"], '\"7\"')
            self.assertEqual(headers["idempotency-key"], "caller-attempt-key")
            self.assertEqual(json.loads(requests[2][2]), approval)
            client.revoke_task_grant(*args, GRANT)
            self.assertEqual(requests[3][2], b"")
            self.assertEqual(client.task_assertion("bootstrap-token", GRANT)["value"]["assertion"], "synthetic-assertion")
            self.assertEqual(client.task_grant_status("resource-token", GRANT)["value"], {"active": False})
            for _, headers, _ in requests[:4]:
                headers = {k.lower(): v for k, v in headers.items()}
                self.assertEqual(headers["registry-casework-profile"], "staff")
                self.assertEqual(headers["registry-source-profile"], "source-reviewer")
            for _, headers, _ in requests[4:]:
                headers = {k.lower(): v for k, v in headers.items()}
                self.assertNotIn("registry-casework-profile", headers)
                self.assertNotIn("registry-source-profile", headers)
            count = len(requests)
            with self.assertRaises(CaseworkClientError): client.approve_task_grant(*args, 7, "caller-attempt-key", {**approval, "resource": "urn:other"})
            with self.assertRaises(CaseworkClientError): client.task_assertion("bootstrap-token", "invalid")
            self.assertEqual(len(requests), count)
        finally:
            server.shutdown(); thread.join(); server.server_close()
