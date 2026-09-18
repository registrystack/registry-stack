from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_casework_client import CaseworkClient  # noqa: E402

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
ITEM_ID = "00000000-0000-4000-8000-000000000001"
EVENT_ID = "00000000-0000-4000-8000-000000000002"
POLICY_DIGEST = f"sha256:{'a' * 64}"

CONSTRAINTS = {
    "batchStatus": {
        "oneOf": [
            {"const": "valid", "title": "All rows valid"},
            {"const": "partial", "title": "Some rows rejected"},
        ],
    },
    "acceptedCount": {"minimum": 0, "maximum": 412},
    "correctedReference": {"maxLength": 32},
}
RESULT = {"batchStatus": "partial", "acceptedCount": 400}


def completed_terminal(item_id: str, result: dict | None) -> dict:
    value = {
        "itemId": item_id,
        "eventId": EVENT_ID,
        "requesterReference": "openfn:run:8f2",
        "state": "completed",
        "outcome": "confirmed",
        "actorRef": "actor_01K4W92K7C8V6M2A",
        "kindPolicyDigest": POLICY_DIGEST,
        "terminalAt": "2026-09-18T01:00:00Z",
    }
    if result is not None:
        value["result"] = result
    return value


class _Handler(BaseHTTPRequestHandler):
    observations: list[dict] = []

    def do_GET(self) -> None:  # noqa: N802
        self.observations.append({"path": self.path})
        if self.path == "/tenant/v1/hosted-items/terminal":
            self.respond({
                "items": [
                    completed_terminal(ITEM_ID, RESULT),
                    completed_terminal("00000000-0000-4000-8000-000000000003", None),
                    {
                        "itemId": "00000000-0000-4000-8000-000000000004",
                        "eventId": EVENT_ID,
                        "requesterReference": "openfn:run:8f2",
                        "state": "cancelled",
                        "cancellationReason": "Withdrawn by the requester",
                        "kindPolicyDigest": POLICY_DIGEST,
                        "terminalAt": "2026-09-18T01:00:00Z",
                    },
                ],
                "status": "complete",
            })
            return
        self.respond({})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length))
        self.observations.append({
            "path": self.path,
            "idempotency_key": self.headers.get("idempotency-key", ""),
            "if_match": self.headers.get("if-match", ""),
            "body": body,
        })
        if self.path.endswith("/hosted-decisions"):
            self.respond(completed_terminal(ITEM_ID, body.get("result")))
            return
        self.respond({
            "itemId": ITEM_ID,
            "requesterReference": body["requesterReference"],
            "kind": body["kind"],
            "version": "1",
            "display": body["display"],
            "resultConstraints": body.get("resultConstraints"),
            "state": "open",
            "revision": 1,
            "kindPolicyDigest": POLICY_DIGEST,
            "createdAt": "2026-09-18T00:00:00Z",
            "updatedAt": "2026-09-18T00:00:00Z",
        }, status=201)

    def respond(self, value: object, status: int = 200) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "no-store")
        self.send_header("traceparent", TRACEPARENT)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class HostedResultTests(unittest.TestCase):
    def setUp(self) -> None:
        _Handler.observations = []
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        port = self.server.server_address[1]
        self.client = CaseworkClient(f"http://127.0.0.1:{port}/tenant")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_create_hosted_item_round_trips_result_constraints(self) -> None:
        created = self.client.create_hosted_item(
            "requester-token", "requester", "create-with-constraints", {
                "kind": "batch-validation",
                "requesterReference": "openfn:run:8f2",
                "display": {"summary": "Review", "batchReference": "B-2026-0912"},
                "resultConstraints": CONSTRAINTS,
            }
        )
        self.assertEqual(created["kind"], "complete")
        observation = _Handler.observations[0]
        self.assertEqual(observation["path"], "/tenant/v1/hosted-items")
        self.assertEqual(observation["body"]["resultConstraints"], CONSTRAINTS)
        self.assertEqual(created["value"]["resultConstraints"], CONSTRAINTS)

    def test_decide_hosted_work_item_round_trips_a_structured_result(self) -> None:
        decided = self.client.decide_hosted_work_item(
            "staff-token",
            "staff",
            {
                "operation": "confirmed",
                "href": f"/v1/work-items/{ITEM_ID}/hosted-decisions",
                "ifMatch": '"2"',
            },
            "decide-with-result",
            {"outcome": "confirmed", "result": RESULT},
        )
        observation = _Handler.observations[0]
        self.assertEqual(observation["path"], f"/tenant/v1/work-items/{ITEM_ID}/hosted-decisions")
        self.assertEqual(observation["body"], {"outcome": "confirmed", "result": RESULT})
        self.assertEqual(observation["if_match"], '"2"')
        self.assertEqual(observation["idempotency_key"], "decide-with-result")
        self.assertEqual(decided["value"]["state"], "completed")
        self.assertEqual(decided["value"]["result"], RESULT)

    def test_terminal_page_exposes_result_exactly_where_the_server_sent_it(self) -> None:
        page = self.client.hosted_terminal_items("requester-token", "requester")
        items = page["value"]["items"]
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]["result"], RESULT)
        self.assertNotIn("result", items[1])
        self.assertEqual(items[2]["state"], "cancelled")
        self.assertNotIn("result", items[2])


if __name__ == "__main__":
    unittest.main()
