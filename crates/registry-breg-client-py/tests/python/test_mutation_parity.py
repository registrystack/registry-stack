"""Exercise metadata-bound actions, Tombstone, and atomic Batch."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import BaseRegistryClient, BaseRegistryClientError  # noqa: E402

RECORD_ID = "00000000-0000-4000-8000-000000000001"
APPLICATION_ID = "00000000-0000-4000-8000-000000000002"
SNAPSHOT = "breg1_00000000-0000-4000-8000-000000000003"
REVISION = "sha256:" + "a" * 64
ACTION_REVISION = "sha256:" + "b" * 64
ETAG = '"breg-record-000000000001"'
TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
PROFILE_LINK = (
    '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", '
    '</v1/schemas/company>; rel="describedby"'
)


def field() -> dict:
    return {
        "id": "legal-name",
        "apiName": "legalName",
        "label": "Legal name",
        "schema": {"type": "string", "maxLength": 120},
        "required": True,
        "nullable": False,
        "readOnly": False,
        "removable": False,
        "storageValidation": {"kind": "postgresql-are", "pattern": "^[A-Z].+$"},
        "codeLabels": {"active": "Active"},
        "reference": {
            "manualEntry": True,
            "targetEntity": "company",
            "operations": [
                {
                    "operationId": "records.company.get",
                    "accessProfile": "company-writer",
                    "labelFields": ["legal-name"],
                }
            ],
        },
    }


def operation(identifier: str, method: str, path: str, kind: str, request: dict) -> dict:
    return {
        "id": identifier,
        "method": method,
        "path": path,
        "operation": kind,
        "sourceEntity": "company",
        "responseEntity": "company",
        "accessProfile": "company-writer",
        "requiredCapabilities": [],
        "entityLabel": "Companies",
        "identifier": {"apiName": "id", "location": "envelope"},
        "titleFields": ["legal-name"],
        "fields": [field()],
        "readableFields": ["legal-name"],
        "createWritableFields": [],
        "patchWritableFields": [],
        "selectors": [],
        "query": None,
        "request": request,
    }


def metadata() -> dict:
    tombstone = operation(
        "records.company.tombstone",
        "DELETE",
        "/v1/records/companies/{record_id}",
        "tombstone",
        {
            "fieldNames": "api",
            "queryParameters": [],
            "body": "none",
            "ifMatchRequired": True,
            "idempotencyKeyRequired": True,
            "mutationSemantics": "direct",
        },
    )
    batch = operation(
        "records.company.batch",
        "POST",
        "/v1/records/companies:batch",
        "batch",
        {
            "fieldNames": "api",
            "queryParameters": [],
            "body": "batch",
            "contentType": "application/json",
            "idempotencyKeyRequired": True,
            "mutationSemantics": "direct",
            "maximumItems": 20,
            "maximumBodyBytes": 16_384,
            "allowCreate": True,
            "allowPatch": False,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["items"],
                "properties": {
                    "items": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 20,
                        "items": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "properties": {
                                        "operation": {"const": "create"},
                                        "data": {"type": "object"},
                                    },
                                }
                            ]
                        },
                    }
                },
            },
        },
    )
    batch["createWritableFields"] = ["legal-name"]
    get = operation(
        "records.company.get",
        "GET",
        "/v1/records/companies/{record_id}",
        "get",
        {"fieldNames": "api", "queryParameters": [], "body": "none"},
    )
    get["readPath"] = {"id": "related-companies", "label": "Related companies"}
    get["selectors"] = [
        {
            "id": "by-name",
            "label": "By name",
            "valueOrigin": "request",
            "fields": [
                {
                    "id": "legal-name",
                    "apiName": "legalName",
                    "label": "Legal name",
                    "schema": {"type": "string", "maxLength": 120},
                    "required": True,
                }
            ],
            "requestFields": ["legalName"],
        }
    ]
    get["query"] = {
        "kind": "list",
        "selectableFields": [{"id": "legal-name", "apiName": "legalName"}],
        "filterableFields": [],
        "sortableFields": [],
        "allowCount": False,
        "defaultPageSize": 25,
        "maxPageSize": 100,
        "maxFilterClauses": 8,
        "maxInValues": 16,
        "pagination": {
            "parameter": "$skiptoken",
            "responsePath": "pageInfo.nextCursor",
            "exclusive": True,
        },
        "temporal": None,
        "spatialQueries": {
            "bbox": {
                "geometryProperty": "legalName",
                "maximumLongitudeSpanDegrees": 0.5,
                "maximumLatitudeSpanDegrees": 0.25,
                "coordinateReferenceSystem": "CRS84",
                "semantics": "inclusive_2d_non_crossing",
            }
        },
    }
    return {
        "id": "business-registry",
        "version": "1.2.3",
        "revision": REVISION,
        "metadataVersion": "1",
        "entities": [
            {
                "id": "company",
                "datasetIdentifier": "legal-entities",
                "route": "companies",
                "operations": [
                    {"operation": "tombstone", "accessProfile": "company-writer"},
                    {"operation": "batch", "accessProfile": "company-writer"},
                ],
                "readableFields": ["legal-name"],
                "schema": "/v1/schemas/company",
                "changeRequest": {
                    "planner": {
                        "kind": "rhai",
                        "abi": "registry.change-request-plan/v1",
                        "limits": {
                            "maximumTargets": 16,
                            "maximumFieldMutations": 128,
                            "maximumSnapshotBytes": 2_097_152,
                            "maximumSourceBytes": 65_536,
                            "maximumOperations": 100_000,
                            "maximumCallDepth": 32,
                            "maximumExpressionDepth": 64,
                            "maximumStringBytes": 16_384,
                            "maximumArrayItems": 256,
                            "maximumMapEntries": 256,
                            "maximumModules": 0,
                        },
                        "possibleWriteCount": 1,
                        "possibleWriteOperations": ["patch"],
                    },
                    "reviewMode": "none",
                    "application": {
                        "mode": "planner",
                        "allowedDispositions": ["apply", "queue"],
                        "queueReasons": [
                            {"code": "manual-check", "label": "Manual check"}
                        ],
                    },
                },
            }
        ],
        "operations": [get, tombstone, batch],
        "actions": [
            {
                "id": "rename-company",
                "route": "/v1/actions/rename-company",
                "conditionRoute": "/v1/actions/rename-company/target-conditions",
                "contractFingerprint": ACTION_REVISION,
                "inputMode": "fixed",
                "maximumInputStringBytes": None,
                "inputs": [
                    {
                        "id": "target",
                        "apiName": "targetId",
                        "required": True,
                        "nullable": False,
                        "classification": "internal",
                        "fieldType": {
                            "type": "reference",
                            "target": "company",
                            "onDelete": "restrict",
                        },
                    },
                    {
                        "id": "name",
                        "apiName": "legalName",
                        "required": True,
                        "nullable": False,
                        "classification": "internal",
                        "fieldType": {"type": "string", "minLength": 1, "maxLength": 120},
                    },
                ],
                "referenceInputs": [
                    {"input": "target", "apiName": "targetId", "targetEntity": "company"}
                ],
                "requiredConditionKeys": ["targetId"],
                "resultEffects": [
                    {"effect": "company", "entity": "company", "operation": "patch"}
                ],
                "access": {"selectedProfile": "company-writer"},
                "routes": {
                    "invoke": {
                        "method": "POST",
                        "path": "/v1/actions/rename-company",
                        "operationId": "actions.rename-company.invoke",
                        "requiresIdempotencyKey": True,
                        "inputSchema": "action-rename-company-invoke-input",
                        "responseSchema": "action-rename-company-invoke-response",
                    },
                    "targetConditions": {
                        "method": "POST",
                        "path": "/v1/actions/rename-company/target-conditions",
                        "operationId": "actions.rename-company.target_conditions",
                        "requiresIdempotencyKey": False,
                        "inputSchema": "action-rename-company-target-conditions-input",
                        "responseSchema": "action-rename-company-target-conditions-response",
                    },
                },
                "bounds": {
                    "maximumTargets": 4,
                    "maximumFieldMutations": 8,
                    "maximumSnapshotBytes": 4096,
                },
            }
        ],
    }


def record() -> dict:
    return {
        "data": {
            "recordIdentifier": RECORD_ID,
            "revisionIdentifier": "2",
            "domainData": {"legalName": "Tombstoned Ltd"},
            "snapshot": SNAPSHOT,
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company",
        },
    }


class MutationParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests = []
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                requests.append((self.command, self.path, dict(self.headers), b""))
                self.respond(metadata())

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers["content-length"]))
                requests.append((self.command, self.path, dict(self.headers), body))
                if self.path.startswith("/v1/actions/rename-company/target-conditions"):
                    self.respond(
                        {"preconditions": {"targetId": {"ifMatch": ETAG}}},
                        mutation=True,
                    )
                elif self.path.startswith("/v1/actions/rename-company"):
                    self.respond(
                        {
                            "action": "rename-company",
                            "applicationId": APPLICATION_ID,
                            "results": {
                                "company": {
                                    "entity": "company",
                                    "recordId": RECORD_ID,
                                    "revision": 2,
                                }
                            },
                        },
                        mutation=True,
                    )
                else:
                    self.respond(
                        {
                            "snapshot": SNAPSHOT,
                            "results": [
                                {
                                    "operation": "create",
                                    "id": RECORD_ID,
                                    "revision": 1,
                                    "etag": ETAG,
                                    "data": {"legalName": "Batch Ltd"},
                                }
                            ],
                        },
                        mutation=True,
                    )

            def do_DELETE(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers.get("content-length", "0")))
                requests.append((self.command, self.path, dict(self.headers), body))
                self.respond(record(), record_response=True, mutation=True)

            def respond(
                self,
                value: dict,
                record_response: bool = False,
                mutation: bool = False,
            ) -> None:
                body = json.dumps(value, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("traceparent", TRACEPARENT)
                if mutation:
                    self.send_header("cache-control", "no-store")
                    self.send_header("vary", "authorization, accept")
                if record_response:
                    self.send_header("etag", ETAG)
                    self.send_header("link", PROFILE_LINK)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BaseRegistryClient(f"http://127.0.0.1:{self.server.server_port}")
        self.contract = self.client.registry_contract("company-writer")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def test_metadata_descriptors_and_immediate_action(self) -> None:
        get = self.contract.operations[0]
        self.assertEqual(get["selectors"][0]["request_fields"], ["legalName"])
        self.assertEqual(get["read_path"]["id"], "related-companies")
        self.assertEqual(get["fields"][0]["code_labels"], {"active": "Active"})
        self.assertTrue(get["fields"][0]["reference"]["manual_entry"])
        self.assertEqual(
            get["fields"][0]["storage_validation"]["kind"], "postgresql-are"
        )
        self.assertEqual(
            get["query"]["spatialQueries"]["bbox"]["coordinateReferenceSystem"],
            "CRS84",
        )
        capability = self.contract.change_request_capability("company")
        self.assertEqual(capability["planner"]["kind"], "rhai")
        self.assertEqual(capability["planner"]["limits"]["maximum_modules"], 0)
        self.assertEqual(
            capability["application"]["queue_reasons"],
            [{"code": "manual-check", "label": "Manual check"}],
        )
        self.assertEqual(self.contract.immediate_actions[0]["input_mode"], "fixed")

        binding = self.contract.select_immediate_action(
            "rename-company", "company-writer"
        )
        before = len(self.requests)
        with self.assertRaises(BaseRegistryClientError) as invalid:
            self.client.invoke_action(
                binding,
                {"targetId": RECORD_ID, "legalName": ""},
                "rename-invalid",
            )
        self.assertEqual(invalid.exception.kind, "invalid_request")
        self.assertEqual(len(self.requests), before)

        conditions = self.client.action_target_conditions(binding, {"targetId": RECORD_ID})
        self.assertEqual(conditions.document, {"preconditions": {"targetId": {"ifMatch": ETAG}}})
        self.assertNotIn(ETAG, repr(conditions))
        receipt = self.client.invoke_action(
            binding,
            {"targetId": RECORD_ID, "legalName": "Renamed Ltd"},
            "rename-1",
            conditions,
        )
        self.assertEqual(receipt["value"]["applicationId"], APPLICATION_ID)
        method, path, headers, body = self.requests[-1]
        self.assertEqual((method, path), ("POST", "/v1/actions/rename-company?accessProfile=company-writer"))
        self.assertEqual(headers["idempotency-key"], "rename-1")
        self.assertEqual(
            json.loads(body),
            {
                "input": {"legalName": "Renamed Ltd", "targetId": RECORD_ID},
                "preconditions": {"targetId": {"ifMatch": ETAG}},
            },
        )

    def test_tombstone_and_batch_use_exact_conditions_and_context(self) -> None:
        tombstone = self.contract.select_tombstone("company", "company-writer")
        result = self.client.tombstone_record(
            tombstone, RECORD_ID, ETAG, "tombstone-1"
        )
        self.assertEqual(result["value"]["data"]["recordIdentifier"], RECORD_ID)
        method, path, headers, body = self.requests[-1]
        self.assertEqual(
            (method, path, body),
            ("DELETE", f"/v1/records/companies/{RECORD_ID}?accessProfile=company-writer", b""),
        )
        self.assertEqual(headers["if-match"], ETAG)
        self.assertEqual(headers["idempotency-key"], "tombstone-1")

        batch = self.contract.select_batch("company", "company-writer")
        receipt = self.client.batch_records(
            batch,
            [{"operation": "create", "data": {"legalName": "Batch Ltd"}}],
            "batch-1",
            change_context={
                "kind": "correction",
                "reason_code": "verified-source",
                "reason_text": "Corrected from source",
                "source_references": ["register-42"],
            },
        )
        self.assertEqual(receipt["value"]["snapshot"], SNAPSHOT)
        method, path, headers, body = self.requests[-1]
        self.assertEqual((method, path), ("POST", "/v1/records/companies:batch?accessProfile=company-writer"))
        self.assertEqual(headers["idempotency-key"], "batch-1")
        self.assertEqual(
            json.loads(body),
            {
                "items": [{"operation": "create", "data": {"legalName": "Batch Ltd"}}],
                "changeContext": {
                    "kind": "correction",
                    "reasonCode": "verified-source",
                    "reasonText": "Corrected from source",
                    "sourceReferences": ["register-42"],
                },
            },
        )


if __name__ == "__main__":
    unittest.main()
