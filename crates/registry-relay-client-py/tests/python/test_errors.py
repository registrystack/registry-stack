from __future__ import annotations

import json
import pathlib
import sys
import unittest

TESTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
import bootstrap  # noqa: E402
from relay_server import RelayServer, Response, TRACE_ID  # noqa: E402

bootstrap.ensure_built()
import registry_relay_client as relay  # noqa: E402


def rate_limit_problem(extra: bool = False) -> bytes:
    body: dict[str, object] = {
        "type": "https://id.registrystack.org/problems/registry-relay/consultation/rate_limited",
        "title": "Consultation quota is exhausted",
        "status": 429,
        "detail": "the consultation quota is exhausted",
        "code": "consultation.rate_limited",
        "traceId": TRACE_ID,
    }
    if extra:
        body["rejectedValue"] = "canary-value"
    return json.dumps(body).encode()


class ErrorTest(unittest.TestCase):
    def test_exact_problem_maps_to_stable_value_free_attributes(self):
        with RelayServer(
            lambda _request: Response(
                429,
                "application/problem+json",
                rate_limit_problem(),
                {"retry-after": "7"},
            )
        ) as server:
            client = relay.RelayClient(server.base_url)
            with self.assertRaises(relay.RelayClientError) as raised:
                client.list_records("people")
        error = raised.exception
        self.assertEqual(error.kind, "problem")
        self.assertEqual(error.code, "consultation.rate_limited")
        self.assertEqual(error.status, 429)
        self.assertEqual(error.trace_id, TRACE_ID)
        self.assertEqual(error.retry_after_seconds, 7)
        self.assertIsNone(error.transport_kind)
        self.assertIsNone(error.token_kind)
        self.assertNotIn("canary", str(error))

    def test_non_exact_problem_is_protocol_and_drops_the_body(self):
        with RelayServer(
            lambda _request: Response(
                429,
                "application/problem+json",
                rate_limit_problem(extra=True),
                {"retry-after": "7"},
            )
        ) as server:
            with self.assertRaises(relay.RelayClientError) as raised:
                relay.RelayClient(server.base_url).list_records("people")
        error = raised.exception
        self.assertEqual(error.kind, "protocol")
        self.assertEqual(error.code, "problem")
        self.assertEqual(error.status, 429)
        self.assertEqual(error.trace_id, TRACE_ID)
        self.assertIsNone(error.retry_after_seconds)
        self.assertNotIn("canary-value", str(error))
        self.assertNotIn("canary-value", repr(error))

    def test_transport_and_request_failures_have_closed_discriminants(self):
        client = relay.RelayClient(
            "http://127.0.0.1:9", request_timeout_seconds=0.2, connect_timeout_seconds=0.2
        )
        with self.assertRaises(relay.RelayClientError) as transport:
            client.health()
        self.assertEqual(transport.exception.kind, "transport")
        self.assertIn(transport.exception.transport_kind, {"connect", "exchange"})

        canary = "canary-selector-value"
        with self.assertRaises(relay.RelayClientError) as request:
            client.lookup("people", "by-code", {"code": [canary]})
        self.assertEqual(request.exception.kind, "invalid_request")
        self.assertNotIn(canary, str(request.exception))

    def test_cyclic_request_graph_fails_locally(self):
        filters: dict[str, object] = {}
        filters["cycle"] = filters
        client = relay.RelayClient("http://127.0.0.1:9")
        with self.assertRaises(relay.RelayClientError) as raised:
            client.list_records("people", filters=filters)
        self.assertEqual(raised.exception.kind, "invalid_request")


if __name__ == "__main__":
    unittest.main()
