"""Exercise the durable ingestion-run surface through the Python binding."""

import hashlib
import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, urlsplit

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import (  # noqa: E402
    BRegIngestionChunk,
    BRegIngestionPrefixDigest,
    BaseRegistryClient,
    BaseRegistryClientError,
    encode_ingestion_chunk,
)

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
TRACEPARENT = f"00-{TRACE_ID}-00f067aa0ba902b7-01"
RUN_ID = "00000000-0000-4000-8000-000000000001"
INPUT_DIGEST = "a" * 64
PREFIX_DIGEST = "b" * 64
CHUNK_DIGEST = "afd0c674539faef83a50823a16f6d14567ba387026fc7decfd70959d0f8d4655"
EMPTY_PREFIX_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ITEMS = [{"operation": "create", "data": {"label": "Example Ltd"}}]

REQUEST = {
    "operation": "create",
    "profile_id": "importer.v1",
    "package_revision": "revision-1",
    "schema_fingerprint": "fingerprint-1",
    "input_digest": INPUT_DIGEST,
    "input_length": 4321,
    "item_count": 10,
    "chunk_count": 3,
    "chunk_algorithm_version": "greedy-canonical-http-batch-v1",
}


def run_wire(**overrides) -> dict:
    value = {
        "runId": RUN_ID,
        "status": "open",
        "blockedReason": None,
        "entityId": "people",
        "operation": "create",
        "profileId": "importer.v1",
        "packageRevision": "revision-1",
        "schemaFingerprint": "fingerprint-1",
        "inputDigest": INPUT_DIGEST,
        "inputLength": 4321,
        "itemCount": 10,
        "chunkCount": 3,
        "chunkAlgorithmVersion": "greedy-canonical-http-batch-v1",
        "maximumItems": 100,
        "maximumBytes": 1048576,
        "nextChunkIndex": 1,
        "committedItems": 0,
        "committedPrefixDigest": EMPTY_PREFIX_DIGEST,
        "lastAttempt": None,
        "createdAt": "2026-09-19T00:00:00Z",
        "updatedAt": "2026-09-19T00:01:00Z",
        "complete": False,
    }
    value.update(overrides)
    return value


def receipt_wire() -> dict:
    return {
        "chunkIndex": 0,
        "digest": CHUNK_DIGEST,
        "replayed": False,
        "erased": False,
        "batch": {
            "snapshot": "breg1_00000000-0000-4000-8000-000000000002",
            "results": [
                {
                    "operation": "create",
                    "id": RUN_ID,
                    "revision": 1,
                    "etag": '"breg-record-v1-abcdef012345"',
                    "data": {"label": "Example Ltd"},
                }
            ],
        },
    }


class IngestionRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.record(b"")
                path = self.path.split("?")[0]
                if "/chunks/0/receipt" in path:
                    self.answer(200, {"receipt": receipt_wire()})
                elif re.search(r"/ingestion-runs/[0-9a-f-]+$", path):
                    self.answer(200, {"run": run_wire(status="cancelled")})
                elif "/chunks/1/receipt" in path:
                    body = json.dumps(
                        {
                            "type": "https://id.registrystack.org/problems/"
                            "registry-breg/ingestion/receipt_erased",
                            "title": "Gone",
                            "status": 410,
                            "detail": "The stored receipt of the chunk was "
                            "erased.",
                            "code": "ingestion.receipt_erased",
                            "traceId": TRACE_ID,
                        }
                    ).encode()
                    self.send_response(410)
                    self.send_header("content-type", "application/problem+json")
                    self.send_header("traceparent", TRACEPARENT)
                    self.send_header("cache-control", "no-store")
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif "/ingestion-runs" in path:
                    self.answer(200, {"runs": [run_wire()], "hasMore": False, "nextAfter": None})
                else:
                    self.answer(404, {})

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                self.record(body)
                path = self.path.split("?")[0]
                if path.endswith("/v1/records/people/ingestion-runs"):
                    self.answer(201, {"run": run_wire()})
                elif path.endswith("/chunks"):
                    self.answer(
                        200,
                        {
                            "run": run_wire(committedItems=1, nextChunkIndex=1),
                            "receipt": receipt_wire(),
                        },
                    )
                elif path.endswith("/cancel"):
                    self.answer(200, {"run": run_wire(status="cancelled")})
                else:
                    self.answer(404, {})

            def record(self, body: bytes) -> None:
                requests.append(
                    (self.command, self.path, self.headers.get("content-type"), body)
                )

            def answer(self, status: int, document: dict) -> None:
                body = json.dumps(document, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("traceparent", TRACEPARENT)
                self.send_header("cache-control", "no-store")
                self.send_header("vary", "authorization, accept")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(f"http://127.0.0.1:{self.server.server_port}/tenant")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_prefix_digest_accumulator_follows_the_rust_empty_input_base(self) -> None:
        digest = BRegIngestionPrefixDigest()
        self.assertEqual(digest.digest(), EMPTY_PREFIX_DIGEST)
        digest.update(b"abc")
        self.assertEqual(
            digest.digest(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        digest.update(b"def")
        self.assertEqual(digest.digest(), hashlib.sha256(b"abcdef").hexdigest())
        fresh = BRegIngestionPrefixDigest()
        self.assertEqual(fresh.digest(), EMPTY_PREFIX_DIGEST)

    def test_encode_ingestion_chunk_derives_the_digest_in_rust(self) -> None:
        chunk = encode_ingestion_chunk(2, ITEMS, PREFIX_DIGEST)
        self.assertIsInstance(chunk, BRegIngestionChunk)
        self.assertEqual(chunk.chunk_index, 2)
        self.assertEqual(chunk.item_count, 1)
        self.assertEqual(chunk.digest, CHUNK_DIGEST)
        self.assertEqual(chunk.prefix_digest, PREFIX_DIGEST)

    def test_encode_ingestion_chunk_refuses_broken_planning_inputs(self) -> None:
        with self.assertRaises(BaseRegistryClientError) as raised:
            encode_ingestion_chunk(0, [], PREFIX_DIGEST)
        self.assertEqual(raised.exception.kind, "invalid_request")
        with self.assertRaises(BaseRegistryClientError) as raised:
            encode_ingestion_chunk(0, ["not-an-object"], PREFIX_DIGEST)
        self.assertEqual(raised.exception.kind, "invalid_request")
        with self.assertRaises(BaseRegistryClientError) as raised:
            encode_ingestion_chunk(0, ITEMS, "not-a-digest")
        self.assertEqual(raised.exception.kind, "invalid_request")
        self.assertNotIn("not-a-digest", str(raised.exception))
        with self.assertRaises(TypeError):
            encode_ingestion_chunk(1.5, ITEMS, PREFIX_DIGEST)

    def test_create_ingestion_run_announces_the_exact_run_binding(self) -> None:
        outcome = self.client.create_ingestion_run("people", REQUEST)
        self.assertEqual(outcome["kind"], "complete")
        self.assertEqual(outcome["trace_id"], TRACE_ID)
        self.assertEqual(outcome["value"]["runId"], RUN_ID)
        self.assertEqual(outcome["value"]["status"], "open")
        self.assertEqual(outcome["value"]["itemCount"], 10)
        self.assertIs(outcome["value"]["complete"], False)
        method, path, content_type, body = self.requests[-1]
        self.assertEqual(method, "POST")
        # The run request names the profile, and the exchange selects it.
        self.assertTrue(
            path.endswith("/v1/records/people/ingestion-runs?accessProfile=importer.v1")
        )
        self.assertEqual(json.loads(body), {
            "operation": "create",
            "profileId": "importer.v1",
            "packageRevision": "revision-1",
            "schemaFingerprint": "fingerprint-1",
            "inputDigest": INPUT_DIGEST,
            "inputLength": 4321,
            "itemCount": 10,
            "chunkCount": 3,
            "chunkAlgorithmVersion": "greedy-canonical-http-batch-v1",
        })
        self.assertEqual(content_type, "application/json")

    def test_create_ingestion_run_refuses_unsupported_missing_and_broken_fields(self) -> None:
        extra = dict(REQUEST, extra=1)
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.create_ingestion_run("people", extra)
        self.assertEqual(raised.exception.kind, "invalid_request")

        missing_item_count = dict(REQUEST)
        del missing_item_count["item_count"]
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.create_ingestion_run("people", missing_item_count)
        self.assertEqual(raised.exception.kind, "invalid_request")

        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.create_ingestion_run("people", dict(REQUEST, operation="delete"))
        self.assertEqual(raised.exception.kind, "invalid_request")

        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.create_ingestion_run("people", dict(REQUEST, input_digest="aaaa"))
        self.assertEqual(raised.exception.kind, "invalid_request")

        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.create_ingestion_run(
                "people",
                dict(REQUEST, chunk_algorithm_version="greedy-canonical-http-batch-v2"),
            )
        self.assertEqual(raised.exception.kind, "invalid_request")

    def test_list_ingestion_runs_sends_contract_filters_in_order(self) -> None:
        outcome = self.client.list_ingestion_runs(
            "people",
            limit=25,
            after="cursor+/=",
            status="open",
            input_digest=INPUT_DIGEST,
            access_profile="importer.v1",
        )
        self.assertEqual(len(outcome["value"]["runs"]), 1)
        self.assertEqual(outcome["value"]["runs"][0]["runId"], RUN_ID)
        self.assertIs(outcome["value"]["hasMore"], False)
        self.assertIsNone(outcome["value"]["nextAfter"])
        query = parse_qsl(urlsplit(self.requests[-1][1]).query)
        self.assertEqual(
            [key for key, _ in query],
            ["accessProfile", "limit", "after", "status", "inputDigest"],
        )
        self.assertEqual(dict(query)["accessProfile"], "importer.v1")
        self.assertEqual(dict(query)["status"], "open")
        self.assertEqual(dict(query)["inputDigest"], INPUT_DIGEST)

        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.list_ingestion_runs("people", status="archived")
        self.assertEqual(raised.exception.kind, "invalid_request")
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.list_ingestion_runs("people", limit=0)
        self.assertEqual(raised.exception.kind, "invalid_request")
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.list_ingestion_runs("people", input_digest="xyz")
        self.assertEqual(raised.exception.kind, "invalid_request")
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.list_ingestion_runs("people", access_profile="x\n")
        self.assertEqual(raised.exception.kind, "invalid_request")

        unfiltered = self.client.list_ingestion_runs("people")
        self.assertEqual(len(unfiltered["value"]["runs"]), 1)
        self.assertEqual(urlsplit(self.requests[-1][1]).query, "")

    def test_read_and_cancel_address_one_run(self) -> None:
        read = self.client.read_ingestion_run("people", RUN_ID)
        self.assertEqual(read["value"]["status"], "cancelled")
        self.assertTrue(
            self.requests[-1][1].endswith(f"/v1/records/people/ingestion-runs/{RUN_ID}")
        )
        profiled = self.client.read_ingestion_run("people", RUN_ID, "importer.v1")
        self.assertEqual(profiled["value"]["status"], "cancelled")
        self.assertTrue(
            self.requests[-1][1].endswith(
                f"/v1/records/people/ingestion-runs/{RUN_ID}?accessProfile=importer.v1"
            )
        )
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.read_ingestion_run("people", "not-a-uuid")
        self.assertEqual(raised.exception.kind, "invalid_request")

        cancelled = self.client.cancel_ingestion_run("people", RUN_ID)
        self.assertEqual(cancelled["value"]["status"], "cancelled")
        method, path, content_type, body = self.requests[-1]
        self.assertTrue(path.endswith("/cancel"))
        self.assertEqual(body, b"")
        self.assertIsNone(content_type)
        cancelled_again = self.client.cancel_ingestion_run("people", RUN_ID, "importer.v1")
        self.assertEqual(cancelled_again["value"]["status"], "cancelled")
        method, path, content_type, body = self.requests[-1]
        self.assertTrue(path.endswith("/cancel?accessProfile=importer.v1"))
        self.assertEqual(body, b"")
        self.assertIsNone(content_type)

    def test_submit_ingestion_chunk_returns_run_and_receipt(self) -> None:
        chunk = encode_ingestion_chunk(0, ITEMS, PREFIX_DIGEST)
        outcome = self.client.submit_ingestion_chunk("people", RUN_ID, chunk, "importer.v1")
        self.assertEqual(outcome["kind"], "complete")
        self.assertEqual(outcome["value"]["run"]["committedItems"], 1)
        self.assertEqual(outcome["value"]["receipt"]["chunkIndex"], 0)
        self.assertEqual(outcome["value"]["receipt"]["digest"], CHUNK_DIGEST)
        self.assertEqual(
            outcome["value"]["receipt"]["batch"]["snapshot"],
            "breg1_00000000-0000-4000-8000-000000000002",
        )
        self.assertTrue(
            self.requests[-1][1].endswith(
                f"/v1/records/people/ingestion-runs/{RUN_ID}"
                "/chunks?accessProfile=importer.v1"
            )
        )
        self.assertEqual(
            json.loads(self.requests[-1][3]),
            {
                "chunkIndex": 0,
                "items": ITEMS,
                "digest": chunk.digest,
                "prefixDigest": PREFIX_DIGEST,
            },
        )
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.submit_ingestion_chunk("people", RUN_ID, chunk, "Invalid Profile")
        self.assertEqual(raised.exception.kind, "invalid_request")

    def test_chunk_receipt_reads_one_retained_and_reports_one_erased(self) -> None:
        retained = self.client.ingestion_chunk_receipt("people", RUN_ID, 0, "importer.v1")
        self.assertIs(retained["value"]["replayed"], False)
        self.assertEqual(len(retained["value"]["batch"]["results"]), 1)
        self.assertTrue(
            self.requests[-1][1].endswith(
                f"/v1/records/people/ingestion-runs/{RUN_ID}"
                "/chunks/0/receipt?accessProfile=importer.v1"
            )
        )
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.ingestion_chunk_receipt("people", RUN_ID, 1, "importer.v1")
        self.assertEqual(raised.exception.kind, "problem")
        self.assertEqual(raised.exception.code, "ingestion.receipt_erased")
        self.assertEqual(raised.exception.status, 410)


if __name__ == "__main__":
    unittest.main()
