"""Prove vocabulary strings survive the native Python metadata boundary."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient  # noqa: E402


REVISION = "sha256:" + "a" * 64
VOCABULARIES = (
    "https://example.org/vocabularies/licence-statuses",
    "สถานะใบอนุญาต/許可状態",
    "",
    "line one\nline two\0",
)


def metadata(vocabulary: str) -> dict[str, object]:
    return {
        "id": "fixture-registry", "version": "1", "revision": REVISION,
        "metadataVersion": "2", "recordTypes": [], "operations": [],
        "statisticalDatasets": [{
            "id": "item-counts", "unit": "item", "periodKind": "flow",
            "granularity": "month", "firstPeriod": "2025-01",
            "definitionDigest": REVISION, "operations": ["read-live"],
            "dimensions": [{
                "field": "status", "vocabulary": vocabulary,
                "codes": ["active", "_T"],
            }],
        }],
        "actions": [{
            "id": "update-status", "apiName": "updateStatus", "revision": REVISION,
            "display": {"label": "Update status"},
            "execution": {"mode": "immediate"},
            "route": "/v1/actions/update-status", "inputMode": "handler",
            "maximumInputStringBytes": 16384,
            "inputs": [{
                "id": "status", "apiName": "status",
                "schema": {"type": "string", "enum": ["active"]},
                "fieldType": {
                    "type": "vocabulary-code", "vocabulary": vocabulary,
                    "values": ["active"],
                },
                "required": True, "nullable": False, "classification": "internal",
            }],
            "referenceInputs": [], "requiredConditionKeys": [], "resultEffects": [],
            "access": {"selectedProfile": "writer"},
            "routes": {"invoke": {
                "method": "POST", "path": "/v1/actions/update-status",
                "operationId": "actions.update-status.invoke",
                "requiresIdempotencyKey": True,
                "inputSchema": "action-update-status-invoke-input",
                "responseSchema": "action-update-status-invoke-response",
            }},
            "bounds": {
                "maximumTargets": 1, "maximumFieldMutations": 1,
                "maximumSnapshotBytes": 1024,
            },
        }],
    }


class MetadataVocabularyTests(unittest.TestCase):
    def test_registry_contract_preserves_every_bounded_engine_vocabulary_string(self) -> None:
        current = {"vocabulary": VOCABULARIES[0]}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = json.dumps(metadata(current["vocabulary"])).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                self.send_header("cache-control", "no-store")
                self.send_header("vary", "authorization, accept")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = BaseRegistryClient(f"http://127.0.0.1:{server.server_port}")
            for vocabulary in VOCABULARIES:
                current["vocabulary"] = vocabulary
                contract = client.registry_contract("writer")
                self.assertEqual(
                    contract.statistical_datasets[0]["dimensions"][0]["vocabulary"],
                    vocabulary,
                )
                self.assertEqual(
                    contract.actions[0]["inputs"][0]["field_type"]["vocabulary"],
                    vocabulary,
                )
                contract.select_action("update-status", "writer")
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
