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
        scopes = schemas["AccessProfile"]["properties"]["requiredScopes"]
        self.assertEqual(1, scopes["minItems"])
        self.assertEqual(1, scopes["items"]["minLength"])
        self.assertEqual(256, scopes["items"]["maxLength"])
        self.assertRegex("casework:staff/read", scopes["items"]["pattern"])
        self.assertNotRegex("casework:staff review", scopes["items"]["pattern"])
        self.assertNotRegex("", scopes["items"]["pattern"])
        self.assertEqual(
            {"items", "nextCursor", "status"},
            set(schemas["HistoryPage"]["properties"]),
        )
        self.assertEqual(
            "complete", schemas["HistoryPage"]["properties"]["status"]["const"]
        )
        history_parameters = {
            parameter["name"]: parameter
            for parameter in self.openapi["paths"]["/v1/work-items/{item_id}/history"][
                "get"
            ]["parameters"]
        }
        self.assertEqual(1, history_parameters["limit"]["schema"]["minimum"])
        self.assertEqual(100, history_parameters["limit"]["schema"]["maximum"])
        self.assertIn("cursor.expired", history_parameters["cursor"]["description"])
        self.assertIn("eventId", history_parameters["cursor"]["description"])
        self.assertEqual(
            {
                "observed", "opened", "claimed", "assigned", "delegated",
                "caseload_moved", "clock_reminder", "clock_step_applied",
                "clock_recomputed", "released", "draft_saved", "attempt_reserved",
                "attempt_uncertain", "action_completed", "attempt_settled", "superseded",
                "completed",
            },
            set(schemas["HistoryEntry"]["properties"]["kind"]["enum"]),
        )

        work_item = schemas["WorkItem"]["properties"]
        self.assertEqual("date-time", work_item["heldSince"]["format"])
        self.assertNotIn("heldSince", schemas["WorkItem"]["required"])
        self.assertEqual(
            {"ruleId", "because", "policyDigest"},
            set(schemas["WorkItemRouting"]["properties"]),
        )
        self.assertNotIn("maxItems", work_item["clockOccurrences"])
        self.assertNotIn("maxItems", schemas["ClockOccurrenceList"])
        next_effects = schemas["ClockNextEffect"]["oneOf"]
        self.assertEqual(
            ["reminder", "reassign"],
            [variant["properties"]["kind"]["const"] for variant in next_effects],
        )
        self.assertEqual(
            {"kind", "id", "at", "because", "queueId"},
            set(next_effects[1]["required"]),
        )
        release_description = self.openapi["paths"][
            "/v1/work-items/{item_id}/release"
        ]["post"]["description"]
        self.assertIn("Supervisor may force-release", release_description)
        self.assertIn("successful current source read", release_description)
        self.assertIn("live source-attempt fence", release_description)
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
        list_operation = self.openapi["paths"]["/v1/work-items"]["get"]
        work_item_page = schemas["WorkItemPage"]
        self.assertIn("servedQueues", work_item_page["required"])
        self.assertTrue(work_item_page["properties"]["servedQueues"]["uniqueItems"])
        self.assertNotIn("maxItems", work_item_page["properties"]["servedQueues"])
        self.assertIn(
            "Present even when items is empty",
            work_item_page["properties"]["servedQueues"]["description"],
        )
        next_operation = self.openapi["paths"]["/v1/work-items/next"]["get"]
        self.assertIn("200", next_operation["responses"])
        self.assertNotIn("204", next_operation["responses"])
        next_schema = next_operation["responses"]["200"]["content"][
            "application/json"
        ]["schema"]
        self.assertEqual(
            {"$ref": "#/components/schemas/WorkItemPage"},
            next_schema["allOf"][0],
        )
        self.assertEqual(
            1,
            next_schema["allOf"][1]["properties"]["items"]["maxItems"],
        )
        self.assertIn("Empty complete", next_operation["description"])
        self.assertIn("budget_exhausted", next_operation["description"])
        next_parameters = {
            parameter["name"]: parameter for parameter in next_operation["parameters"]
        }
        self.assertIn("next-item feed", next_parameters["cursor"]["description"])
        self.assertIn("due ordering", next_parameters["cursor"]["description"])
        list_parameters = {
            parameter["name"]: parameter for parameter in list_operation["parameters"]
        }
        for name in ("sourceId", "subjectKind", "subjectId"):
            self.assertFalse(list_parameters[name]["required"])
            self.assertEqual(1, list_parameters[name]["schema"]["minLength"])
            self.assertNotIn("maxLength", list_parameters[name]["schema"])
        self.assertIn("supply this together", list_parameters["sourceId"]["description"])
        self.assertIn("without normalization", list_parameters["sourceId"]["description"])
        self.assertIn("not restricted to UUID", list_parameters["subjectId"]["description"])
        self.assertIn("follow every page", list_operation["description"])
        self.assertIn("cursor is bound to the full selector", list_operation["description"])
        self.assertEqual(100, limit["schema"]["maximum"])

    def test_history_kind_values_match_the_rust_enum(self) -> None:
        model_source = (ROOT / "crates/registry-casework-core/src/model.rs").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            set(GENERATOR.rust_snake_case_unit_enum_values(model_source, "HistoryKind")),
            set(
                self.openapi["components"]["schemas"]["HistoryEntry"]["properties"][
                    "kind"
                ]["enum"]
            ),
        )

    def test_source_unavailable_can_identify_a_durable_mutation_attempt(self) -> None:
        for path in (
            "/v1/work-items/{item_id}/decisions",
            "/v1/work-items/{item_id}/attempts/recover",
            "/v1/work-items/{item_id}/attempts/{attempt_id}/recover",
        ):
            response = self.openapi["paths"][path]["post"]["responses"]["503"]
            attempt = response["headers"]["Registry-Casework-Attempt"]
            self.assertEqual("uuid", attempt["schema"]["format"])
            self.assertIn("post-write", attempt["description"])
        item_read = self.openapi["paths"]["/v1/work-items/{item_id}"]["get"]
        self.assertNotIn(
            "Registry-Casework-Attempt", item_read["responses"]["503"]["headers"]
        )

    def test_assignment_routes_preserve_authority_and_preconditions(self) -> None:
        def names(method: str, path: str) -> set[str]:
            return {
                parameter["name"]
                for parameter in self.openapi["paths"][path][method]["parameters"]
            }

        self.assertNotIn(
            "Registry-Source-Profile", names("get", "/v1/directory/absences")
        )
        self.assertEqual(
            {"traceparent", "Registry-Casework-Profile", "If-Match", "Idempotency-Key"},
            names("post", "/v1/directory/absences"),
        )
        for method in ("put", "delete"):
            self.assertEqual(
                {
                    "traceparent",
                    "Registry-Casework-Profile",
                    "If-Match",
                    "Idempotency-Key",
                    "absence_id",
                },
                names(method, "/v1/directory/absences/{absence_id}"),
            )

        for path in (
            "/v1/work-items/{item_id}/assign",
            "/v1/work-items/{item_id}/delegate",
        ):
            operation = self.openapi["paths"][path]["post"]
            source = next(
                parameter
                for parameter in operation["parameters"]
                if parameter["name"] == "Registry-Source-Profile"
            )
            self.assertFalse(source["required"])
            self.assertIn("If-Match", names("post", path))
            self.assertIn("Idempotency-Key", names("post", path))

        preview = "/v1/directory/caseload/preview"
        apply = "/v1/directory/caseload/apply"
        for path in (preview, apply):
            source = next(
                parameter
                for parameter in self.openapi["paths"][path]["post"]["parameters"]
                if parameter["name"] == "Registry-Source-Profile"
            )
            self.assertFalse(source["required"])
        self.assertNotIn("If-Match", names("post", preview))
        self.assertNotIn("Idempotency-Key", names("post", preview))
        self.assertEqual({"cursor", "limit"}, names("post", preview) - {
            "traceparent",
            "Registry-Casework-Profile",
            "Registry-Source-Profile",
        })
        self.assertNotIn("If-Match", names("post", apply))
        self.assertIn("Idempotency-Key", names("post", apply))

        team_path = "/v1/directory/teams/{team_id}"
        self.assertEqual(
            {
                "traceparent",
                "Registry-Casework-Profile",
                "If-Match",
                "Idempotency-Key",
                "team_id",
            },
            names("put", team_path),
        )
        team_responses = self.openapi["paths"][team_path]["put"]["responses"]
        self.assertIn("precondition.failed", problem_codes(self.openapi, team_responses["412"]))
        self.assertNotIn("Registry-Source-Profile", names("put", team_path))

    def test_directory_team_update_replaces_only_directory_membership(self) -> None:
        schema = self.openapi["components"]["schemas"][
            "DirectoryTeamUpdateRequest"
        ]
        self.assertEqual(
            {"staff", "supervisors", "servedQueues"}, set(schema["properties"])
        )
        for field in ("staff", "supervisors", "servedQueues"):
            self.assertEqual(100, schema["properties"][field]["maxItems"])
            self.assertTrue(schema["properties"][field]["uniqueItems"])
        principal = self.openapi["components"]["schemas"]["DirectoryMember"]
        self.assertEqual(2048, principal["properties"]["issuer"]["x-maximum-utf8-bytes"])
        self.assertEqual(2048, principal["properties"]["subject"]["x-maximum-utf8-bytes"])
        self.assertEqual(
            500,
            principal["properties"]["displayName"]["anyOf"][0][
                "x-maximum-utf8-bytes"
            ],
        )
        self.assertNotIn("displayName", principal["required"])
        self.assertEqual(
            "#/components/schemas/DirectoryMember",
            schema["properties"]["staff"]["items"]["$ref"],
        )
        operation = self.openapi["paths"]["/v1/directory/teams/{team_id}"][
            "put"
        ]
        self.assertEqual(
            "#/components/schemas/DirectoryResponse",
            operation["responses"]["200"]["content"]["application/json"][
                "schema"
            ]["$ref"],
        )
        self.assertIn("no work-item identifiers", operation["description"])

    def test_holdings_accepts_a_bounded_page_limit(self) -> None:
        parameters = {
            parameter["name"]: parameter
            for parameter in self.openapi["paths"]["/v1/holdings"]["get"][
                "parameters"
            ]
        }
        self.assertEqual(
            {
                "cursor",
                "limit",
                "Registry-Casework-Profile",
                "Registry-Source-Profile",
                "traceparent",
            },
            set(parameters),
        )
        self.assertFalse(parameters["limit"]["required"])
        self.assertEqual(1, parameters["limit"]["schema"]["minimum"])
        self.assertEqual(100, parameters["limit"]["schema"]["maximum"])
        operation = self.openapi["paths"]["/v1/holdings"]["get"]
        self.assertIn("within this page", operation["description"])
        self.assertIn("follow every page and sum matching groups", operation["description"])
        self.assertIn("source_unavailable page contains zero counts", operation["description"])
        self.assertIn("retries the failed page", parameters["cursor"]["description"])

    def test_directory_target_discovery_is_purpose_bound_and_directory_member_only(self) -> None:
        operation = self.openapi["paths"]["/v1/directory/targets"]["get"]
        parameters = {
            parameter["name"]: parameter for parameter in operation["parameters"]
        }
        self.assertEqual(
            ["assignment", "absence_person", "absence_cover"],
            parameters["purpose"]["schema"]["enum"],
        )
        self.assertTrue(parameters["purpose"]["required"])
        for name in ("queue", "personIssuer", "personSubject", "cursor", "limit"):
            self.assertFalse(parameters[name]["required"])
        for name in ("personIssuer", "personSubject"):
            self.assertEqual(2048, parameters[name]["schema"]["x-maximum-utf8-bytes"])
        self.assertEqual(1, parameters["limit"]["schema"]["minimum"])
        self.assertEqual(100, parameters["limit"]["schema"]["maximum"])
        self.assertIn("purpose, queue, and person fields", parameters["cursor"]["description"])
        self.assertIn("cursor.expired", parameters["cursor"]["description"])
        self.assertNotIn(
            "Registry-Source-Profile",
            {parameter["name"] for parameter in operation["parameters"]},
        )
        self.assertIn("across teams", operation["description"])
        self.assertIn("issuer-qualified identity", operation["description"])
        self.assertIn("display name", operation["description"])
        self.assertIn("teams and absence details are never returned", operation["description"])
        page = self.openapi["components"]["schemas"]["DirectoryTargetPage"]
        self.assertEqual(
            "#/components/schemas/DirectoryMember",
            page["properties"]["items"]["items"]["$ref"],
        )
        self.assertEqual({"items", "nextCursor", "status"}, set(page["properties"]))

    def test_assignment_schemas_are_bounded_and_report_per_item_results(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        self.assertIn("assignment", schemas["WorkItem"]["properties"])
        self.assertEqual(
            {"owner", "assignedBy", "absenceIds", "staffingDiagnostic"},
            set(schemas["AssignmentContext"]["properties"]),
        )
        self.assertEqual(
            ["no_cover_available"], schemas["StaffingDiagnostic"]["enum"]
        )
        absence_list = schemas["AbsenceList"]
        self.assertEqual(
            {"directoryRevision", "items", "nextCursor"}, set(absence_list["properties"])
        )
        self.assertEqual(1000, absence_list["properties"]["items"]["maxItems"])
        self.assertNotIn("nextCursor", absence_list["required"])
        absence_parameters = {
            parameter["name"]: parameter
            for parameter in self.openapi["paths"]["/v1/directory/absences"]["get"]["parameters"]
            if parameter["in"] == "query"
        }
        self.assertEqual({"limit", "cursor"}, set(absence_parameters))
        self.assertEqual(
            {"type": "integer", "minimum": 1, "maximum": 1000, "default": 1000},
            absence_parameters["limit"]["schema"],
        )
        self.assertIn(
            "current global directoryRevision",
            self.openapi["paths"]["/v1/directory/absences"]["get"]["description"],
        )
        selections = schemas["CaseloadApplyRequest"]["properties"]["items"]
        self.assertEqual(1, selections["minItems"])
        self.assertEqual(100, selections["maxItems"])
        self.assertEqual("itemId", selections["x-unique-by"])
        self.assertEqual(
            {
                "moved",
                "not_visible",
                "not_eligible",
                "attempt_in_progress",
                "conflict",
            },
            set(schemas["CaseloadItemOutcome"]["enum"]),
        )
        apply_schema = self.openapi["paths"]["/v1/directory/caseload/apply"][
            "post"
        ]["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual("#/components/schemas/CaseloadItemResultList", apply_schema["$ref"])
        self.assertIn(
            "Each item",
            self.openapi["paths"]["/v1/directory/caseload/apply"]["post"][
                "description"
            ],
        )

    def test_absence_validation_problems_are_value_free_and_route_scoped(self) -> None:
        absence_codes = {
            "absence.invalid-period",
            "absence.self-cover",
            "absence.overlap",
            "absence.cover-cycle",
        }
        actual = set()
        for path, path_item in self.openapi["paths"].items():
            for method, operation in path_item.items():
                response = operation["responses"].get("422")
                if response is None:
                    continue
                codes = problem_codes(self.openapi, response)
                if absence_codes & codes:
                    self.assertTrue(absence_codes <= codes)
                    actual.add((method, path))
        self.assertEqual(
            {
                ("post", "/v1/directory/absences"),
                ("put", "/v1/directory/absences/{absence_id}"),
            },
            actual,
        )
        for code in absence_codes:
            component = self.openapi["components"]["schemas"][
                GENERATOR.problem_component_name(code)
            ]
            properties = component["allOf"][1]["properties"]
            self.assertNotIn("value", properties["detail"]["const"].lower())

    def test_authored_routing_and_clock_shapes_are_closed_and_bounded(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        request = schemas["SourceRequestPolicy"]
        self.assertEqual(
            {
                "entity",
                "queue",
                "displayReference",
                "projection",
                "routing",
                "clock",
                "target",
            },
            set(request["properties"]),
        )
        self.assertEqual(
            "#/components/schemas/DisplayReferencePolicy",
            request["properties"]["displayReference"]["anyOf"][0]["$ref"],
        )
        self.assertEqual(
            {"field"}, set(schemas["DisplayReferencePolicy"]["properties"])
        )
        self.assertEqual(32, request["properties"]["projection"]["maxItems"])
        self.assertEqual(64, request["properties"]["routing"]["maxItems"])
        condition = schemas["RoutingCondition"]["properties"]
        self.assertEqual({"activity", "stage", "fields"}, set(condition))
        self.assertEqual(16, condition["fields"]["maxProperties"])
        self.assertEqual(
            {"EqualsPredicate", "OneOfPredicate"},
            {
                variant["$ref"].rsplit("/", 1)[1]
                for variant in schemas["RoutingPredicate"]["oneOf"]
            },
        )
        self.assertEqual(32, schemas["OneOfPredicate"]["properties"]["oneOf"]["maxItems"])

        project = schemas["CaseworkProject"]["properties"]
        self.assertEqual(16, project["calendars"]["maxItems"])
        self.assertEqual(32, project["clocks"]["maxItems"])
        weekdays = schemas["CalendarPolicy"]["properties"]["workingWeekdays"]
        self.assertEqual(7, weekdays["maxItems"])
        self.assertTrue(weekdays["uniqueItems"])
        self.assertEqual(
            {"SubjectClockPolicy", "ActivityClockPolicy"},
            {
                variant["$ref"].rsplit("/", 1)[1]
                for variant in schemas["ClockPolicy"]["oneOf"]
            },
        )
        subject = schemas["SubjectClockPolicy"]["properties"]
        self.assertEqual("firstSubmittedAt", subject["anchor"]["const"])
        self.assertEqual("reviewCompleted", subject["completeOn"]["const"])
        activity = schemas["ActivityClockPolicy"]["properties"]
        self.assertEqual("stageEnteredAt", activity["anchor"]["const"])
        self.assertEqual(8, activity["reminders"]["maxItems"])
        self.assertEqual(8, activity["steps"]["maxItems"])
        self.assertNotIn("holidaySet", project)

    def test_clock_runtime_shapes_are_bounded_and_generation_explicit(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        self.assertEqual(
            {
                "running",
                "paused",
                "completed",
                "cancelled",
                "verification_pending",
                "source_facts_missing",
            },
            set(schemas["ClockRuntimeState"]["enum"]),
        )
        occurrence = schemas["ClockOccurrenceView"]
        self.assertIn("policyDigest", occurrence["properties"])
        self.assertIn("calculationGeneration", occurrence["required"])
        self.assertIn("recomputeGeneration", occurrence["required"])
        upcoming = occurrence["properties"]["upcomingEffects"]
        self.assertNotIn("upcomingEffects", occurrence["required"])
        self.assertEqual(2, upcoming["maxItems"])
        self.assertIn("ordered by time, effect kind, and identifier", upcoming["description"])
        self.assertIn("including while paused", upcoming["description"])
        self.assertIn("not scheduler retry times", upcoming["description"])
        self.assertNotIn("maxItems", schemas["ClockOccurrenceList"])
        self.assertEqual(
            100,
            schemas["ClockRecomputePreview"]["properties"]["changes"][
                "maxItems"
            ],
        )
        self.assertEqual(
            100,
            schemas["ClockRecomputeResult"]["properties"][
                "appliedOccurrences"
            ]["maxItems"],
        )
        self.assertEqual(
            1,
            schemas["HolidaySetDocument"]["properties"]["revision"]["minimum"],
        )
        dates = schemas["HolidaySetDocument"]["properties"]["dates"]
        self.assertEqual(3660, dates["maxItems"])
        self.assertTrue(dates["uniqueItems"])

        description = schemas["Description"]
        self.assertIn("calendars", description["required"])
        self.assertIn("clocks", description["required"])

    def test_clock_routes_preserve_source_and_administrator_boundaries(self) -> None:
        def operation(method: str, path: str) -> dict:
            return self.openapi["paths"][path][method]

        def names(method: str, path: str) -> set[str]:
            return {
                parameter["name"]
                for parameter in operation(method, path)["parameters"]
            }

        clocks_path = "/v1/work-items/{item_id}/clocks"
        clocks = operation("get", clocks_path)
        source = next(
            parameter
            for parameter in clocks["parameters"]
            if parameter["name"] == "Registry-Source-Profile"
        )
        self.assertTrue(source["required"])
        self.assertNotIn("If-Match", names("get", clocks_path))
        self.assertNotIn("Idempotency-Key", names("get", clocks_path))
        self.assertEqual(
            "#/components/schemas/ClockOccurrenceList",
            clocks["responses"]["200"]["content"]["application/json"]["schema"][
                "$ref"
            ],
        )

        create_path = "/v1/directory/holidays"
        read_path = "/v1/directory/holidays/{id}/revisions/{revision}"
        preview_path = "/v1/directory/clocks/recompute/preview"
        apply_path = "/v1/directory/clocks/recompute/apply"
        for method, path in (
            ("post", create_path),
            ("get", read_path),
            ("post", preview_path),
            ("post", apply_path),
        ):
            self.assertNotIn("Registry-Source-Profile", names(method, path))
            self.assertNotIn("If-Match", names(method, path))

        self.assertIn("Idempotency-Key", names("post", create_path))
        self.assertIn("201", operation("post", create_path)["responses"])
        self.assertIn("412", operation("post", create_path)["responses"])
        self.assertNotIn("Idempotency-Key", names("get", read_path))
        self.assertNotIn("Idempotency-Key", names("post", preview_path))
        self.assertIn("Idempotency-Key", names("post", apply_path))

    def test_clock_preview_expiry_is_apply_only_and_actionable(self) -> None:
        expired = "clock.recompute-preview-expired"
        actual = set()
        for path, path_item in self.openapi["paths"].items():
            for method, operation in path_item.items():
                response = operation["responses"].get("410")
                if response is not None and expired in problem_codes(self.openapi, response):
                    actual.add((method, path))
        self.assertEqual(
            {("post", "/v1/directory/clocks/recompute/apply")}, actual
        )
        component = self.openapi["components"]["schemas"][
            GENERATOR.problem_component_name(expired)
        ]
        detail = component["allOf"][1]["properties"]["detail"]["const"]
        self.assertEqual(
            "Create a new recompute preview and review it before applying.", detail
        )
        apply_responses = self.openapi["paths"][
            "/v1/directory/clocks/recompute/apply"
        ]["post"]["responses"]
        self.assertIn("precondition.failed", problem_codes(self.openapi, apply_responses["412"]))
        holiday_responses = self.openapi["paths"]["/v1/directory/holidays"][
            "post"
        ]["responses"]
        self.assertIn(
            "precondition.failed", problem_codes(self.openapi, holiday_responses["412"])
        )

    def test_hosted_routes_preserve_roles_and_source_profile_selection(self) -> None:
        requester_routes = {
            ("post", "/v1/hosted-items"),
            ("get", "/v1/hosted-items/terminal"),
            ("get", "/v1/hosted-items/{item_id}"),
            ("get", "/v1/hosted-items/{item_id}/notes"),
            ("post", "/v1/hosted-items/{item_id}/notes"),
            ("post", "/v1/hosted-items/{item_id}/cancel"),
        }
        for method, path in requester_routes:
            names = {
                parameter["name"]
                for parameter in self.openapi["paths"][path][method]["parameters"]
            }
            self.assertIn("Registry-Casework-Profile", names)
            self.assertNotIn("Registry-Source-Profile", names)

        for method, path in {
            ("get", "/v1/work-items"),
            ("get", "/v1/work-items/{item_id}"),
            ("post", "/v1/work-items/{item_id}/claim"),
            ("post", "/v1/work-items/{item_id}/release"),
        }:
            source = next(
                parameter
                for parameter in self.openapi["paths"][path][method]["parameters"]
                if parameter["name"] == "Registry-Source-Profile"
            )
            self.assertFalse(source["required"])

        hosted_decision = self.openapi["paths"][
            "/v1/work-items/{item_id}/hosted-decisions"
        ]["post"]
        self.assertNotIn(
            "Registry-Source-Profile",
            {parameter["name"] for parameter in hosted_decision["parameters"]},
        )
        for method, path in {
            ("get", "/v1/hosted-accountability/{event_id}"),
            ("get", "/v1/work-items/{item_id}/hosted-history"),
        }:
            names = {
                parameter["name"]
                for parameter in self.openapi["paths"][path][method]["parameters"]
            }
            self.assertIn("Registry-Casework-Profile", names)
            self.assertNotIn("Registry-Source-Profile", names)

    def test_hosted_wire_shapes_are_explicit_and_do_not_disclose_raw_actor(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        self.assertIn("hostedKinds", schemas["Description"]["properties"])
        self.assertIn("hosted", schemas["WorkItem"]["properties"])
        self.assertIn(
            "hosted", schemas["WorkItem"]["properties"]["occurrenceKind"]["enum"]
        )
        self.assertEqual(
            {"open", "claimed", "completed", "cancelled"},
            set(schemas["RequesterHostedItem"]["properties"]["state"]["enum"]),
        )
        self.assertEqual(
            {"HostedTerminalCompleted", "HostedTerminalCancelled"},
            {
                variant["$ref"].rsplit("/", 1)[1]
                for variant in schemas["HostedTerminalResult"]["oneOf"]
            },
        )
        completed = schemas["HostedTerminalCompleted"]["properties"]
        self.assertEqual("completed", completed["state"]["const"])
        self.assertIn("actorRef", completed)
        for forbidden in ("actor", "issuer", "subject", "email", "reason"):
            self.assertNotIn(forbidden, completed)
        cancelled = schemas["HostedTerminalCancelled"]["properties"]
        self.assertEqual("cancelled", cancelled["state"]["const"])
        self.assertIn("cancellationReason", cancelled)
        self.assertNotIn("actorRef", cancelled)
        accountability = schemas["HostedAccountabilityRecord"]["properties"]
        self.assertIn("actor", accountability)
        self.assertIn("retainedUntil", accountability)
        history_fields = schemas["HostedHistoryEntry"]["properties"]
        self.assertIn("actorRef", history_fields)
        self.assertNotIn("actor", history_fields)
        self.assertEqual(
            "HostedAccountabilityRecord",
            self.openapi["paths"]["/v1/hosted-accountability/{event_id}"][
                "get"
            ]["responses"]["200"]["content"]["application/json"]["schema"][
                "$ref"
            ].rsplit("/", 1)[1],
        )

    def test_hosted_validation_headers_are_paired_value_free_metadata(self) -> None:
        for method, path in GENERATOR.HOSTED_VALIDATION_OPERATIONS:
            headers = self.openapi["paths"][path][method]["responses"]["400"][
                "headers"
            ]
            validation = {
                name: value
                for name, value in headers.items()
                if name.startswith("Registry-Casework-Validation-")
            }
            self.assertEqual(
                {
                    "Registry-Casework-Validation-Path",
                    "Registry-Casework-Validation-Reason",
                },
                set(validation),
            )
            self.assertEqual(
                256,
                validation["Registry-Casework-Validation-Path"]["schema"][
                    "maxLength"
                ],
            )
            self.assertEqual(
                GENERATOR.HOSTED_VALIDATION_REASONS,
                validation["Registry-Casework-Validation-Reason"]["schema"][
                    "enum"
                ],
            )
            body = self.openapi["components"]["schemas"]["Problem"]["properties"]
            self.assertNotIn("field", body)
            self.assertNotIn("value", body)

    def test_hosted_idempotency_expiry_has_bounded_recovery(self) -> None:
        expected = {
            ("post", "/v1/hosted-items"),
            ("post", "/v1/hosted-items/{item_id}/notes"),
            ("post", "/v1/hosted-items/{item_id}/cancel"),
            ("post", "/v1/work-items/{item_id}/claim"),
            ("post", "/v1/work-items/{item_id}/release"),
            ("post", "/v1/work-items/{item_id}/hosted-decisions"),
        }
        actual = set()
        for path, path_item in self.openapi["paths"].items():
            for method, operation in path_item.items():
                response = operation["responses"].get("410")
                if response is None:
                    continue
                codes = GENERATOR.schema_problem_codes(
                    self.openapi,
                    response["content"]["application/problem+json"]["schema"],
                )
                if "idempotency.expired" in codes:
                    actual.add((method, path))
        self.assertEqual(expected, actual)

        for method, path in expected:
            operation = self.openapi["paths"][path][method]
            idempotency = next(
                parameter
                for parameter in operation["parameters"]
                if parameter["name"] == "Idempotency-Key"
            )
            self.assertIn("exact retry", idempotency["description"])
            self.assertIn("idempotency.expired", idempotency["description"])
            self.assertIn("idempotency.key-reused", idempotency["description"])
            self.assertIn("key may be reused", idempotency["description"])

    def test_terminal_page_documents_stable_recovery_and_retention(self) -> None:
        operation = self.openapi["paths"]["/v1/hosted-items/terminal"]["get"]
        cursor = next(
            parameter
            for parameter in operation["parameters"]
            if parameter["name"] == "cursor"
        )
        self.assertIn("cursor.expired", cursor["description"])
        self.assertIn("eventId", cursor["description"])
        self.assertIn("terminalAt", operation["description"])
        self.assertIn("retention", operation["description"])
        notes = self.openapi["paths"]["/v1/hosted-items/{item_id}/notes"][
            "get"
        ]
        self.assertIn("recordedAt", notes["description"])
        self.assertIn("noteId", notes["description"])
        history = self.openapi["paths"][
            "/v1/work-items/{item_id}/hosted-history"
        ]["get"]
        self.assertIn("occurredAt", history["description"])
        self.assertIn("eventId", history["description"])
        for paged_operation in (operation, notes, history):
            limit = next(
                parameter
                for parameter in paged_operation["parameters"]
                if parameter["name"] == "limit"
            )
            self.assertIn("request.invalid", limit["description"])
        self.assertEqual(
            {
                "created",
                "claimed",
                "assigned",
                "delegated",
                "caseload_moved",
                "released",
                "note_added",
                "completed",
                "cancelled",
            },
            set(
                self.openapi["components"]["schemas"]["HostedHistoryEntry"][
                    "properties"
                ]["kind"]["enum"]
            ),
        )

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
            ("post", "/v1/work-items/{item_id}/assign"),
            ("post", "/v1/work-items/{item_id}/delegate"),
            ("post", "/v1/work-items/{item_id}/release"),
            ("put", "/v1/work-items/{item_id}/draft"),
            ("delete", "/v1/work-items/{item_id}/draft"),
            ("put", "/v1/directory/absences/{absence_id}"),
            ("delete", "/v1/directory/absences/{absence_id}"),
        }
        nonnegative_revision_routes = {
            ("post", "/v1/work-items/{item_id}/decisions"),
            ("post", "/v1/directory/absences"),
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
