"""Exercise metadata-bound actions, Tombstone, and atomic Batch."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from bootstrap import ensure_built

ensure_built()

from registry_breg_client import (  # noqa: E402
    BRegPreparedAction,
    BaseRegistryClient,
    BaseRegistryClientError,
)

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
            "targetRecordType": "company",
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
        "sourceRecordType": "company",
        "responseRecordType": "company",
        "accessProfile": "company-writer",
        "requiredCapabilities": [],
        "futureExecutionMember": {"ignored": True},
        "recordTypeLabel": "Companies",
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
        "maximumPageSize": 100,
        "maximumFilterClauses": 8,
        "maximumInValues": 16,
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
        "metadataVersion": "2",
        "futureDescription": {"label": "Future registry description"},
        "recordTypes": [
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
            }
        ],
        "operations": [get, tombstone, batch],
        "actions": [
            {
                "id": "rename-company",
                "apiName": "renameCompany",
                "display": {},
                "route": "/v1/actions/rename-company",
                "conditionRoute": "/v1/actions/rename-company/target-conditions",
                "revision": ACTION_REVISION,
                "execution": {"mode": "immediate"},
                "inputMode": "fixed",
                "maximumInputStringBytes": None,
                "inputs": [
                    {
                        "id": "target",
                        "apiName": "targetId",
                        "required": True,
                        "nullable": False,
                        "classification": "internal",
                        "schema": {"type": "string", "format": "uuid"},
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
                        "schema": {"type": "string", "minLength": 1, "maxLength": 120},
                        "fieldType": {"type": "string", "minimumLength": 1, "maximumLength": 120},
                    },
                ],
                "referenceInputs": [
                    {"input": "target", "apiName": "targetId", "targetRecordType": "company"}
                ],
                "requiredConditionKeys": ["targetId"],
                "resultEffects": [
                    {"effect": "company", "recordType": "company", "operation": "patch"}
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
                        "operationId": "actions.rename-company.target-conditions",
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
        self.metadata_document = metadata()
        metadata_document = self.metadata_document
        self.metadata_body = {"value": None}
        metadata_body = self.metadata_body
        self.lose_next_invocation = {"value": False}
        lose_next_invocation = self.lose_next_invocation
        self.receipt_ids = {"application": APPLICATION_ID, "record": RECORD_ID}
        receipt_ids = self.receipt_ids

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                requests.append((self.command, self.path, dict(self.headers), b""))
                if self.path.startswith("/v1/registry"):
                    self.respond(metadata_body["value"] or metadata_document)
                else:
                    self.respond(record(), record_response=True)

            def do_POST(self) -> None:  # noqa: N802
                body = self.rfile.read(int(self.headers["content-length"]))
                requests.append((self.command, self.path, dict(self.headers), body))
                if self.path.startswith("/v1/actions/rename-company/target-conditions"):
                    self.respond(
                        {"preconditions": {"targetId": {"ifMatch": ETAG}}},
                        mutation=True,
                    )
                elif self.path.startswith("/v1/actions/rename-company"):
                    if lose_next_invocation["value"]:
                        # The engine received the invocation, but its answer
                        # never arrives.
                        lose_next_invocation["value"] = False
                        self.close_connection = True
                        return
                    self.respond(
                        {
                            "action": "rename-company",
                            "applicationId": receipt_ids["application"],
                            "results": {
                                "company": {
                                    "recordType": "company",
                                    "recordId": receipt_ids["record"],
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
                value: dict | bytes,
                record_response: bool = False,
                mutation: bool = False,
            ) -> None:
                body = (
                    value
                    if isinstance(value, bytes)
                    else json.dumps(value, separators=(",", ":")).encode()
                )
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
        self.assertEqual(get["source_record_type"], "company")
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
        self.assertEqual(self.contract.actions[0]["input_mode"], "fixed")
        self.assertEqual(self.contract.actions[0]["inputs"][1]["schema"],
                         {"type": "string", "minLength": 1, "maxLength": 120})
        batch_operation = next(
            operation
            for operation in self.contract.operations
            if operation["id"] == "records.company.batch"
        )
        self.assertIs(batch_operation["request"]["allow_create"], True)
        self.assertIs(batch_operation["request"]["allow_patch"], False)
        get_operation = next(
            operation
            for operation in self.contract.operations
            if operation["id"] == "records.company.get"
        )
        self.assertIsNone(get_operation["request"]["allow_create"])
        self.assertIsNone(get_operation["request"]["allow_patch"])

        read = self.client.get_record(
            "companies", RECORD_ID, access_profile="company-writer"
        )
        self.assertEqual(read["value"]["data"]["recordIdentifier"], RECORD_ID)

        self.metadata_document["operations"][1]["requiredCapabilities"] = [
            "future-tombstone-protocol"
        ]
        partly_unsupported = self.client.registry_contract("company-writer")
        with self.assertRaises(BaseRegistryClientError) as unsupported:
            partly_unsupported.select_tombstone("company", "company-writer")
        self.assertEqual(unsupported.exception.code, "required-capability")
        partly_unsupported.select_batch("company", "company-writer")
        self.metadata_document["operations"][1]["requiredCapabilities"] = []

        encoded = json.dumps(self.metadata_document, separators=(",", ":"))
        self.metadata_body["value"] = encoded.replace(
            '"id":"business-registry"',
            '"id":"business-registry","id":"duplicate-registry"',
            1,
        ).encode()
        with self.assertRaises(BaseRegistryClientError) as duplicate:
            self.client.registry_contract("company-writer")
        self.assertEqual(duplicate.exception.kind, "protocol")
        self.metadata_body["value"] = None

        self.metadata_document["futureDescription"]["label"] = "x" * 65_537
        with self.assertRaises(BaseRegistryClientError) as oversized:
            self.client.registry_contract("company-writer")
        self.assertEqual(oversized.exception.kind, "protocol")
        self.metadata_document["futureDescription"]["label"] = (
            "Future registry description"
        )

        binding = self.contract.select_action(
            "rename-company", "company-writer"
        )
        before = len(self.requests)
        with self.assertRaises(BaseRegistryClientError) as invalid:
            self.client.invoke_action(
                binding,
                {"targetId": RECORD_ID, "legalName": ""},
                "rename-invalid",
            )
        self.assertEqual(invalid.exception.kind, "invalid-request")
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

    def test_immediate_action_application_identity_preserves_nil_record_ids(self) -> None:
        binding = self.contract.select_action("rename-company", "company-writer")
        conditions = self.client.action_target_conditions(binding, {"targetId": RECORD_ID})
        inputs = {"targetId": RECORD_ID, "legalName": "Renamed Ltd"}
        self.receipt_ids.update(application="00000000-0000-0000-0000-000000000000", record="00000000-0000-0000-0000-000000000000")
        count = len(self.requests)
        with self.assertRaises(BaseRegistryClientError) as raised:
            self.client.invoke_action(binding, inputs, "application-identity", conditions)
        self.assertEqual(raised.exception.kind, "protocol")
        self.assertTrue(raised.exception.outcome_unknown)
        self.assertEqual(len(self.requests), count + 1)
        self.receipt_ids["application"] = "0192a870-1234-7abc-8def-123456789abc"
        receipt = self.client.invoke_action(binding, inputs, "application-identity", conditions)["value"]
        self.assertEqual(receipt["applicationId"], self.receipt_ids["application"])
        self.assertEqual(receipt["results"]["company"]["recordId"], self.receipt_ids["record"])

    def test_immediate_action_recovers_after_a_lost_response(self) -> None:
        # The process gives up after the lost answer instead of resending it.
        self.client = BaseRegistryClient(
            f"http://127.0.0.1:{self.server.server_port}", max_mutation_retries=0
        )
        binding = self.contract.select_action(
            "rename-company", "company-writer"
        )
        conditions = self.client.action_target_conditions(binding, {"targetId": RECORD_ID})
        inputs = {"targetId": RECORD_ID, "legalName": "Renamed Ltd"}
        before_prepare = len(self.requests)
        prepared = self.client.prepare_action(binding, inputs, "rename-lost", conditions)
        self.assertEqual(len(self.requests), before_prepare)
        evidence = prepared.to_bytes()
        self.assertIsInstance(evidence, bytes)
        self.assertEqual(repr(prepared), "BRegPreparedAction(<redacted>)")
        for secret in ("Renamed Ltd", "rename-lost", ETAG):
            self.assertNotIn(secret, repr(prepared))

        self.lose_next_invocation["value"] = True
        with self.assertRaises(BaseRegistryClientError) as lost_response:
            self.client.invoke_action(binding, inputs, "rename-lost", conditions)
        self.assertEqual(lost_response.exception.kind, "transport")
        self.assertIs(lost_response.exception.outcome_unknown, True)
        lost = self.requests[-1]
        self.assertEqual(lost[2]["idempotency-key"], "rename-lost")

        restarted = BaseRegistryClient(f"http://127.0.0.1:{self.server.server_port}")
        restarted_binding = restarted.registry_contract(
            "company-writer"
        ).select_action("rename-company", "company-writer")
        restored = BRegPreparedAction.from_bytes(evidence)
        self.assertEqual(restored.to_bytes(), evidence)
        before_recovery = len(self.requests)
        for invalid in (b"{}", b"!" + evidence[1:]):
            with self.assertRaises(BaseRegistryClientError) as refused:
                BRegPreparedAction.from_bytes(invalid)
            self.assertEqual(refused.exception.kind, "invalid-request")
        for changed_inputs, key in (
            (inputs, "another-key"),
            ({"targetId": RECORD_ID, "legalName": "Changed Ltd"}, "rename-lost"),
        ):
            with self.assertRaises(BaseRegistryClientError) as mismatch:
                restarted.recover_action(restarted_binding, restored, changed_inputs, key)
            self.assertEqual(mismatch.exception.kind, "invalid-request")
        foreign = BaseRegistryClient("https://other.example.invalid")
        with self.assertRaises(BaseRegistryClientError) as foreign_recovery:
            foreign.recover_action(restarted_binding, restored, inputs, "rename-lost")
        self.assertEqual(foreign_recovery.exception.kind, "invalid-request")
        recovered = restarted.recover_action(
            restarted_binding, restored, inputs, "rename-lost"
        )
        self.assertEqual(repr(recovered), "BRegRecoveredAction(<redacted>)")
        with self.assertRaises(BaseRegistryClientError) as foreign_execution:
            foreign.execute_recovered_action(restarted_binding, recovered)
        self.assertEqual(foreign_execution.exception.kind, "invalid-request")
        self.assertEqual(len(self.requests), before_recovery)

        receipt = restarted.execute_recovered_action(restarted_binding, recovered)
        self.assertEqual(receipt["value"]["applicationId"], APPLICATION_ID)
        replay = self.requests[-1]
        self.assertEqual(replay[1], lost[1])
        self.assertTrue(replay[1].startswith("/v1/actions/rename-company?"))
        self.assertEqual(replay[2]["idempotency-key"], "rename-lost")
        self.assertEqual(replay[3], lost[3])
        self.assertEqual(
            json.loads(replay[3]),
            {
                "input": {"legalName": "Renamed Ltd", "targetId": RECORD_ID},
                "preconditions": {"targetId": {"ifMatch": ETAG}},
            },
        )
        invocations = [
            request
            for request in self.requests
            if request[1].startswith("/v1/actions/rename-company?")
        ]
        self.assertEqual(len(invocations), 2)
        condition_requests = [
            request for request in self.requests if "/target-conditions" in request[1]
        ]
        self.assertEqual(len(condition_requests), 1)

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
