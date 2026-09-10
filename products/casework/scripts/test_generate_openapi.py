#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = Path(__file__).with_name("generate_openapi.py")
SPEC = importlib.util.spec_from_file_location("casework_generate_openapi", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GENERATOR
SPEC.loader.exec_module(GENERATOR)


def problem_codes(openapi: dict, response: dict) -> set[str]:
    schema = response["content"]["application/problem+json"]["schema"]
    variants = schema.get("oneOf", [schema])
    result = set()
    for variant in variants:
        name = variant["$ref"].rsplit("/", 1)[1]
        component = openapi["components"]["schemas"][name]
        result.add(component["allOf"][1]["properties"]["code"]["const"])
    return result


def parameter_schema(openapi: dict, method: str, path: str, name: str) -> dict:
    parameters = openapi["paths"][path][method]["parameters"]
    return next(parameter["schema"] for parameter in parameters if parameter["name"] == name)


class GeneratedOpenApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = GENERATOR.load_rust_contract(ROOT)
        cls.openapi = GENERATOR.document(cls.contract)

    def test_every_operation_has_its_exact_rust_owned_response_contract(self) -> None:
        framework = set(self.contract["frameworkProblems"])
        signatures = set()
        for rust in self.contract["operations"]:
            operation = self.openapi["paths"][rust["path"]][rust["method"].lower()]
            successes = {
                int(status) for status in operation["responses"] if int(status) < 400
            }
            self.assertEqual(set(rust["successStatuses"]), successes)
            expected_codes = set(rust["problems"])
            expected_codes.update(
                framework & {"request.method-not-allowed", "request.body-too-large"}
            )
            actual_codes = set()
            for status, response in operation["responses"].items():
                if int(status) >= 400:
                    actual_codes.update(problem_codes(self.openapi, response))
            self.assertEqual(expected_codes, actual_codes, (rust["method"], rust["path"]))
            signatures.add(tuple(sorted(actual_codes)))
        self.assertGreater(len(signatures), 8)

    def test_problem_components_preserve_rust_catalog_values(self) -> None:
        for entry in self.contract["entries"]:
            component = self.openapi["components"]["schemas"][
                GENERATOR.problem_component_name(entry["code"])
            ]
            properties = component["allOf"][1]["properties"]
            self.assertEqual(entry["uri"], properties["type"]["const"])
            self.assertEqual(entry["title"], properties["title"]["const"])
            self.assertEqual(entry["description"], properties["detail"]["const"])
            self.assertEqual(entry["httpStatuses"][0], properties["status"]["const"])

    def test_success_status_and_dto_shape_drift_fail_the_generator(self) -> None:
        bad_contract = copy.deepcopy(self.contract)
        bad_contract["operations"][0]["successStatuses"] = [299]
        with self.assertRaisesRegex(ValueError, "success status drifted"):
            GENERATOR.document(bad_contract)

        bad_openapi = copy.deepcopy(self.openapi)
        del bad_openapi["components"]["schemas"]["WorkItem"]["properties"][
            "liveAttempt"
        ]
        with self.assertRaisesRegex(ValueError, "DTO shape drifted from WorkItem"):
            GENERATOR.verify_dto_schemas(ROOT, bad_openapi)

        bad_openapi = copy.deepcopy(self.openapi)
        bad_openapi["paths"]["/health"]["get"]["responses"]["409"] = copy.deepcopy(
            self.openapi["paths"]["/v1/work-items/{item_id}/decisions"]["post"][
                "responses"
            ]["409"]
        )
        catalog = {entry["code"]: entry for entry in self.contract["entries"]}
        with self.assertRaisesRegex(
            ValueError, r"per-operation problem mapping drifted for \('GET', '/health'\)"
        ):
            GENERATOR.verify_operation_responses(
                bad_openapi, self.contract, catalog
            )

    def test_checkpoint_specific_schema_bounds_are_explicit(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        self.assertEqual(
            {"items", "status"}, set(schemas["HistoryPage"]["properties"])
        )
        self.assertEqual(
            "complete", schemas["HistoryPage"]["properties"]["status"]["const"]
        )
        self.assertEqual(
            "^[a-z][a-z0-9_]{0,63}$", schemas["OperationName"]["pattern"]
        )
        limit = next(
            parameter
            for parameter in self.openapi["paths"]["/v1/work-items"]["get"][
                "parameters"
            ]
            if parameter["name"] == "limit"
        )
        self.assertEqual(100, limit["schema"]["maximum"])

    def test_maintained_headers_have_the_exact_bounded_wire_contract(self) -> None:
        profile_schema = {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9_.:-]+$",
        }
        idempotency_schema = {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[!-~]+$",
        }
        for schema_name in ("DecideRequest", "RecoverAttemptRequest"):
            self.assertEqual(
                profile_schema,
                self.openapi["components"]["schemas"][schema_name]["properties"][
                    "sourceProfileId"
                ],
            )
        for rust in self.contract["operations"]:
            method = rust["method"].lower()
            path = rust["path"]
            operation = self.openapi["paths"][path][method]
            names = {parameter["name"] for parameter in operation["parameters"]}
            if path not in {"/health", "/ready", "/events/sources/{source_id}"}:
                self.assertEqual(
                    profile_schema,
                    parameter_schema(
                        self.openapi, method, path, "Registry-Casework-Profile"
                    ),
                )
            if "Registry-Source-Profile" in names:
                self.assertEqual(
                    profile_schema,
                    parameter_schema(
                        self.openapi, method, path, "Registry-Source-Profile"
                    ),
                )
            if "Idempotency-Key" in names:
                self.assertEqual(
                    idempotency_schema,
                    parameter_schema(self.openapi, method, path, "Idempotency-Key"),
                )

        positive_revision_routes = {
            ("post", "/v1/work-items/{item_id}/claim"),
            ("post", "/v1/work-items/{item_id}/release"),
            ("put", "/v1/work-items/{item_id}/draft"),
            ("delete", "/v1/work-items/{item_id}/draft"),
        }
        nonnegative_revision_routes = {
            ("post", "/v1/work-items/{item_id}/decisions"),
            ("post", "/v1/directory/bootstrap"),
        }
        for method, path in positive_revision_routes:
            self.assertEqual(
                '^"[1-9][0-9]{0,18}"$',
                parameter_schema(self.openapi, method, path, "If-Match")["pattern"],
            )
        for method, path in nonnegative_revision_routes:
            self.assertEqual(
                '^"(0|[1-9][0-9]{0,18})"$',
                parameter_schema(self.openapi, method, path, "If-Match")["pattern"],
            )

        event = self.openapi["paths"]["/events/sources/{source_id}"]["post"]
        event_schemas = {
            parameter["name"]: parameter["schema"] for parameter in event["parameters"]
        }
        self.assertEqual("1.0", event_schemas["ce-specversion"]["const"])
        self.assertEqual("uuid", event_schemas["ce-id"]["format"])
        self.assertEqual("date-time", event_schemas["ce-time"]["format"])
        self.assertEqual("uri", event_schemas["ce-source"]["format"])
        self.assertEqual(512, event_schemas["ce-type"]["maxLength"])
        self.assertEqual(2048, event_schemas["ce-dataschema"]["maxLength"])
        self.assertEqual(
            "^sha256:[0-9a-f]{64}$", event_schemas["idempotency-key"]["pattern"]
        )
        self.assertEqual(
            "^v1=[A-Za-z0-9_-]{43}$",
            event_schemas["x-registry-signature"]["pattern"],
        )
        self.assertEqual(1_048_576, event["x-maximum-body-bytes"])
        self.assertEqual(32_768, event["x-maximum-signed-metadata-bytes"])


if __name__ == "__main__":
    unittest.main()
