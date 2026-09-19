#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = Path(__file__).with_name("generate_openapi.py")
SPEC = importlib.util.spec_from_file_location("scheduling_generate_openapi", SCRIPT)
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


def parameter(openapi: dict, method: str, path: str, name: str) -> dict:
    parameters = openapi["paths"][path][method]["parameters"]
    return next(item for item in parameters if item["name"] == name)


def operation(openapi: dict, key: tuple[str, str]) -> dict:
    method, path = key
    return openapi["paths"][path][method.lower()]


def codes_of(openapi: dict, key: tuple[str, str]) -> dict[int, set[str]]:
    return {
        int(status): problem_codes(openapi, response)
        for status, response in operation(openapi, key)["responses"].items()
        if int(status) >= 400
    }


def documented_codes(openapi: dict, key: tuple[str, str]) -> set[str]:
    by_status = codes_of(openapi, key)
    return set().union(*by_status.values()) if by_status else set()


class GeneratedOpenApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = GENERATOR.load_rust_contract(ROOT)
        cls.catalog = GENERATOR.catalog_of(cls.contract)
        cls.variants = {
            GENERATOR.code_variant(entry["code"]): entry["code"]
            for entry in cls.contract["entries"]
        }
        cls.openapi = GENERATOR.document(cls.contract)
        cls.committed = (ROOT / GENERATOR.OUTPUT).read_text(encoding="utf-8")

    def test_every_documented_problem_matches_its_pinned_rust_catalog_entry(self) -> None:
        for entry in self.contract["entries"]:
            component = self.openapi["components"]["schemas"][
                GENERATOR.problem_component_name(entry["code"])
            ]
            properties = component["allOf"][1]["properties"]
            self.assertEqual(entry["uri"], properties["type"]["const"])
            self.assertEqual(entry["title"], properties["title"]["const"])
            self.assertEqual(entry["description"], properties["detail"]["const"])
            self.assertEqual(entry["httpStatuses"][0], properties["status"]["const"])
        self.assertEqual(32, len(self.contract["entries"]))
        self.assertEqual(59, len(self.openapi["components"]["schemas"]))

    def test_every_operation_answers_exactly_the_problems_it_was_mapped(self) -> None:
        for key, expected in GENERATOR.OPERATION_PROBLEMS.items():
            by_status = codes_of(self.openapi, key)
            # An operation can reach one refusal down more than one path, and
            # the declaration names every path it has, so the document answers
            # a code once however many groups carry it.
            self.assertEqual(sorted(set(expected)), sorted(set().union(*by_status.values())), key)
            for status, codes in by_status.items():
                for code in codes:
                    self.assertEqual(status, self.catalog[code]["httpStatuses"][0], code)

    def test_problem_status_is_never_documented_by_hand(self) -> None:
        """A mutated catalog status must fail the check, not pass silently."""
        bad_contract = copy.deepcopy(self.contract)
        entry = next(
            entry for entry in bad_contract["entries"] if entry["code"] == "capacity.exhausted"
        )
        entry["httpStatuses"] = [500]
        with self.assertRaisesRegex(ValueError, "per-operation problem mapping drifted"):
            GENERATOR.verify_operation_problems(
                copy.deepcopy(self.openapi),
                bad_contract,
                GENERATOR.catalog_of(bad_contract),
                self.variants,
            )

    def test_a_reserved_code_can_never_be_documented_as_an_answer(self) -> None:
        key = ("GET", "/v1/services")
        saved = list(GENERATOR.OPERATION_PROBLEMS[key])
        GENERATOR.OPERATION_PROBLEMS[key] = saved + ["eligibility.unavailable"]
        try:
            with self.assertRaisesRegex(
                ValueError, "reserved problem documented as an operation answer"
            ):
                GENERATOR.verify_operation_problems(
                    copy.deepcopy(self.openapi), self.contract, self.catalog, self.variants
                )
        finally:
            GENERATOR.OPERATION_PROBLEMS[key] = saved

    def test_a_reserved_code_stays_in_the_vocabulary_it_is_reserved_from(self) -> None:
        documented = {
            code for codes in GENERATOR.OPERATION_PROBLEMS.values() for code in codes
        }
        for code in GENERATOR.RESERVED_PROBLEMS:
            self.assertNotIn(code, documented)
            self.assertIn(code, self.catalog)
            self.assertIn(code, self.openapi["components"]["schemas"]["Problem"]["properties"]["code"]["enum"])

    def test_documented_coverage_is_the_closed_vocabulary_minus_the_unreachable(self) -> None:
        documented = {
            code for codes in GENERATOR.OPERATION_PROBLEMS.values() for code in codes
        }
        self.assertEqual(set(self.catalog) - set(GENERATOR.RESERVED_PROBLEMS), documented)
        self.assertEqual(
            {
                "request.body-too-large",
                "request.invalid",
                "request.method-not-allowed",
                "request.not-found",
                "request.unprocessable",
                "request.unsupported-media-type",
            },
            set(self.openapi["x-registry-scheduling-edge-problems"]),
        )
        self.assertEqual(
            {
                "eligibility.unavailable",
                "hook.unavailable",
                "precondition.failed",
                "resource.unavailable",
            },
            set(self.openapi["x-registry-scheduling-reserved-problems"]),
        )

    def test_only_a_reachable_code_is_documented_as_an_answer(self) -> None:
        produced = GENERATOR.produced_problem_codes(ROOT, self.variants)
        documented = {
            code for codes in GENERATOR.OPERATION_PROBLEMS.values() for code in codes
        }
        self.assertEqual(documented, documented & produced)
        self.assertEqual(set(), set(GENERATOR.UNPRODUCED_PROBLEMS) & produced)
        self.assertIn("resource.unavailable", produced)

    def test_every_route_is_described_by_exactly_one_operation(self) -> None:
        documented = {
            (method.upper(), path)
            for path, path_item in self.openapi["paths"].items()
            for method in path_item
        }
        self.assertEqual(set(GENERATOR.ROUTE_HANDLERS), documented)
        self.assertEqual(GENERATOR.ROUTES, {path for _, path in documented})
        self.assertEqual(set(GENERATOR.OPERATION_IDS), documented)
        for key, operation_id in GENERATOR.OPERATION_IDS.items():
            self.assertEqual(operation_id, operation(self.openapi, key)["operationId"])

    def test_a_drifted_route_table_fails_the_generator(self) -> None:
        saved = set(GENERATOR.ROUTES)
        try:
            GENERATOR.ROUTES.discard("/v1/locations")
            with self.assertRaisesRegex(ValueError, "route inventory drifted"):
                GENERATOR.verify_source(ROOT)
        finally:
            GENERATOR.ROUTES.clear()
            GENERATOR.ROUTES.update(saved)

    def test_an_operation_documents_the_authority_its_handler_uses(self) -> None:
        expected = {
            ("GET", "/healthz"): "unauthenticated",
            ("GET", "/readyz"): "unauthenticated",
            ("GET", "/v1/scheduling"): "reads-scope",
            ("GET", "/v1/services"): "reads-scope",
            ("GET", "/v1/offerings"): "reads-scope",
            ("GET", "/v1/resources"): "reads-scope",
            ("GET", "/v1/locations"): "reads-scope",
            ("GET", "/v1/availability"): "reads-scope",
            ("GET", "/v1/availability/explain"): "explain-scope",
            ("POST", "/v1/holds"): "task-grant",
            ("DELETE", "/v1/holds/{hold_id}"): "task-grant",
            ("POST", "/v1/appointments"): "task-grant",
            ("GET", "/v1/appointments/{appointment_id}"): "reads-scope",
            ("POST", "/v1/appointments/{appointment_id}/reschedule"): "task-grant",
            ("POST", "/v1/appointments/{appointment_id}/cancel"): "task-grant",
            ("GET", "/v1/appointments/{appointment_id}/history"): "reads-scope",
        }
        for key, authority in expected.items():
            documented = operation(self.openapi, key)
            self.assertEqual(authority, documented["x-scheduling-authority"], key)
            if authority == "unauthenticated":
                self.assertEqual([], documented["security"], key)
            else:
                self.assertEqual([{"bearerAuth": []}], documented["security"], key)
        authorities = [
            item["x-scheduling-authority"]
            for path in self.openapi["paths"].values()
            for item in path.values()
        ]
        self.assertEqual(1, authorities.count("explain-scope"))
        self.assertEqual(2, authorities.count("unauthenticated"))
        self.assertEqual(5, authorities.count("task-grant"))
        self.assertEqual(8, authorities.count("reads-scope"))

    def test_an_idempotency_key_is_demanded_exactly_where_the_handler_reads_it(self) -> None:
        expected = {
            ("POST", "/v1/holds"),
            ("POST", "/v1/appointments"),
            ("POST", "/v1/appointments/{appointment_id}/reschedule"),
            ("POST", "/v1/appointments/{appointment_id}/cancel"),
        }
        schema = {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[!-~]+$"}
        for key in GENERATOR.ROUTE_HANDLERS:
            names = {item["name"] for item in operation(self.openapi, key)["parameters"]}
            self.assertEqual(key in expected, "Idempotency-Key" in names, key)
            if key in expected:
                demanded = parameter(self.openapi, key[0].lower(), key[1], "Idempotency-Key")
                self.assertTrue(demanded["required"])
                self.assertEqual(schema, demanded["schema"])
                self.assertIn("idempotency.expired", demanded["description"])
                self.assertIn("idempotency.key-reused", demanded["description"])

    def test_a_release_uses_the_hold_itself_as_its_idempotency_key(self) -> None:
        """No caller key means a reused key is unreachable on this route."""
        key = ("DELETE", "/v1/holds/{hold_id}")
        codes = documented_codes(self.openapi, key)
        self.assertIn("idempotency.expired", codes)
        self.assertNotIn("idempotency.key-reused", codes)
        self.assertIn("own identifier is the idempotency key",
                      operation(self.openapi, key)["description"])
        self.assertNotIn("Idempotency-Key",
                         {item["name"] for item in operation(self.openapi, key)["parameters"]})

    def test_a_request_body_is_demanded_exactly_where_the_handler_extracts_one(self) -> None:
        expected = {
            ("POST", "/v1/holds"): "AdmissionRequest",
            ("POST", "/v1/appointments"): "CreateAppointmentRequest",
            ("POST", "/v1/appointments/{appointment_id}/reschedule"): "RescheduleAppointmentRequest",
            ("POST", "/v1/appointments/{appointment_id}/cancel"): "CancelAppointmentRequest",
        }
        for key in GENERATOR.ROUTE_HANDLERS:
            documented = operation(self.openapi, key)
            self.assertEqual(key in expected, "requestBody" in documented, key)
            if key in expected:
                reference = documented["requestBody"]["content"]["application/json"]["schema"]["$ref"]
                self.assertEqual(f"#/components/schemas/{expected[key]}", reference)
                codes = documented_codes(self.openapi, key)
                self.assertIn("request.invalid", codes, key)
                self.assertIn("request.unprocessable", codes, key)
                self.assertIn("request.unsupported-media-type", codes, key)

    def test_success_statuses_come_from_the_handlers(self) -> None:
        expected = {
            ("POST", "/v1/holds"): "201",
            ("POST", "/v1/appointments"): "201",
            ("DELETE", "/v1/holds/{hold_id}"): "204",
        }
        for key in GENERATOR.ROUTE_HANDLERS:
            statuses = {
                status
                for status in operation(self.openapi, key)["responses"]
                if int(status) < 400
            }
            self.assertEqual({expected.get(key, "200")}, statuses, key)

    def test_a_fallible_service_method_always_documents_an_unavailable_dependency(self) -> None:
        for key in GENERATOR.ROUTE_HANDLERS:
            codes = documented_codes(self.openapi, key)
            # Liveness is the one route that reaches neither the store nor the
            # issuer's key material. Every other route reaches at least one of
            # them, and an outage in either is answered with a retry.
            if key == ("GET", "/healthz"):
                self.assertNotIn("service.unavailable", codes, key)
            else:
                self.assertIn("service.unavailable", codes, key)
                self.assertIn("Retry-After", operation(self.openapi, key)["responses"]["503"]["headers"])

    def test_infrastructure_routes_are_open_and_distinguish_live_from_ready(self) -> None:
        health = operation(self.openapi, ("GET", "/healthz"))
        ready = operation(self.openapi, ("GET", "/readyz"))
        self.assertEqual([], health["security"])
        self.assertEqual([], ready["security"])
        self.assertNotIn("requestBody", health)
        self.assertNotIn("requestBody", ready)
        self.assertNotIn("503", health["responses"])
        self.assertIn("503", ready["responses"])
        self.assertNotIn("401", health["responses"])
        self.assertNotIn("401", ready["responses"])
        self.assertIn("No authentication", health["description"])
        self.assertIn("service.unavailable", ready["description"])

    def test_only_an_authenticated_operation_answers_a_bearer_challenge(self) -> None:
        for key in GENERATOR.ROUTE_HANDLERS:
            item = operation(self.openapi, key)
            codes = documented_codes(self.openapi, key)
            challenge = item["responses"].get("401", {}).get("headers", {}).get("WWW-Authenticate")
            if item["x-scheduling-authority"] == "unauthenticated":
                self.assertNotIn("authentication.refused", codes, key)
                self.assertNotIn("profile.not-authorized", codes, key)
                self.assertIsNone(challenge, key)
            else:
                self.assertIn("authentication.refused", codes, key)
                self.assertIn("profile.not-authorized", codes, key)
                self.assertEqual("Bearer", challenge["schema"]["const"], key)

    def test_every_answer_carries_the_trace_and_the_no_store_policy(self) -> None:
        for path in self.openapi["paths"].values():
            for item in path.values():
                for response in item["responses"].values():
                    self.assertEqual("#/components/headers/TraceparentHeader",
                                     response["headers"]["traceparent"]["$ref"])
                    self.assertEqual("#/components/headers/CacheControlHeader",
                                     response["headers"]["cache-control"]["$ref"])
        self.assertEqual({"const": "no-store"},
                         self.openapi["components"]["headers"]["CacheControlHeader"]["schema"])

    def test_owned_appointment_reads_never_disclose_existence(self) -> None:
        for key in (
            ("GET", "/v1/appointments/{appointment_id}"),
            ("GET", "/v1/appointments/{appointment_id}/history"),
        ):
            codes = documented_codes(self.openapi, key)
            self.assertIn("operation.not-authorized", codes, key)
            self.assertNotIn("request.not-found", codes, key)
            self.assertIn("never disclosed", operation(self.openapi, key)["description"])

    def test_the_cancellation_guard_never_names_the_policy_revision(self) -> None:
        key = ("POST", "/v1/appointments/{appointment_id}/cancel")
        codes = documented_codes(self.openapi, key)
        self.assertIn("cancellation.cutoff-passed", codes)
        self.assertIn("revision.mismatch", codes)
        self.assertNotIn("policy.changed", codes)
        self.assertIn("never by the policy revision", operation(self.openapi, key)["description"])

    def test_a_reschedule_answers_a_moved_policy_but_never_an_absent_offering(self) -> None:
        # A reschedule resolves its offering from the appointment rather than
        # from the caller, so there is no caller-named offering to be absent.
        key = ("POST", "/v1/appointments/{appointment_id}/reschedule")
        codes = documented_codes(self.openapi, key)
        self.assertIn("policy.changed", codes)
        self.assertIn("revision.mismatch", codes)
        self.assertNotIn("request.not-found", codes)

    def test_only_a_confirming_create_answers_an_expired_hold(self) -> None:
        expected = {("POST", "/v1/appointments")}
        for key in GENERATOR.ROUTE_HANDLERS:
            self.assertEqual(
                key in expected,
                "hold.expired" in documented_codes(self.openapi, key),
                key,
            )

    def test_only_an_offering_the_caller_names_can_be_answered_as_absent(self) -> None:
        # The four operations that resolve a caller-named offering against the
        # deployed policy. Everywhere else request.not-found would conceal an
        # owned record rather than name an absence the offering listing
        # already discloses.
        expected = {
            ("GET", "/v1/availability"),
            ("GET", "/v1/availability/explain"),
            ("POST", "/v1/holds"),
            ("POST", "/v1/appointments"),
        }
        for key in GENERATOR.ROUTE_HANDLERS:
            self.assertEqual(
                key in expected,
                "request.not-found" in documented_codes(self.openapi, key),
                key,
            )

    def test_admission_refusals_travel_only_with_the_commitment_routes(self) -> None:
        admission = {
            "booking.duplicate-active",
            "capacity.exhausted",
            "capability.unmatched",
            "horizon.outside",
            "location.closed",
            "party.capacity-inadequate",
            "policy.changed",
            "precondition.required",
            "prerequisite.missing",
            "schedule.unpublished",
        }
        commitments = {
            ("POST", "/v1/holds"),
            ("POST", "/v1/appointments"),
            ("POST", "/v1/appointments/{appointment_id}/reschedule"),
        }
        for key in GENERATOR.ROUTE_HANDLERS:
            codes = documented_codes(self.openapi, key)
            self.assertEqual(key in commitments, bool(admission & codes), key)

    def test_resource_unavailability_is_disclosed_by_the_explain_path_only(self) -> None:
        explain = operation(self.openapi, ("GET", "/v1/availability/explain"))
        self.assertIn("resource.unavailable is disclosed here", explain["description"])
        self.assertIn("capacity.exhausted", explain["description"])
        documented = {
            code for codes in GENERATOR.OPERATION_PROBLEMS.values() for code in codes
        }
        self.assertNotIn("resource.unavailable", documented)
        self.assertIn("resource.unavailable", self.openapi["x-registry-scheduling-reserved-problems"])

    def test_the_catalogue_and_availability_reads_are_cursor_bound(self) -> None:
        for key in (
            ("GET", "/v1/services"),
            ("GET", "/v1/offerings"),
            ("GET", "/v1/resources"),
            ("GET", "/v1/locations"),
            ("GET", "/v1/availability"),
            ("GET", "/v1/appointments/{appointment_id}/history"),
        ):
            names = {item["name"]: item for item in operation(self.openapi, key)["parameters"]}
            self.assertIn("cursor", names, key)
            self.assertIn("limit", names, key)
            self.assertFalse(names["cursor"]["required"])
            self.assertFalse(names["limit"]["required"])
            self.assertEqual(256, names["cursor"]["schema"]["maxLength"])
            self.assertIn("cursor.expired", names["cursor"]["description"])
            codes = documented_codes(self.openapi, key)
            self.assertIn("cursor.expired", codes, key)
            self.assertIn("cursor.invalid", codes, key)
            self.assertEqual({"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
                             names["limit"]["schema"])

    def test_the_security_scheme_tells_the_three_profiles_apart(self) -> None:
        scheme = self.openapi["components"]["securitySchemes"]["bearerAuth"]
        self.assertEqual({"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
                         {key: scheme[key] for key in ("type", "scheme", "bearerFormat")})
        self.assertIn("scheduling-read", scheme["description"])
        self.assertIn("scheduling-explain", scheme["description"])
        self.assertIn("no scope", scheme["description"])
        self.assertIn("complete task grant", scheme["description"])
        self.assertIn("partial grant claims", scheme["description"])

    def test_mutating_routes_name_the_five_task_grant_actions(self) -> None:
        described = " ".join(
            operation(self.openapi, key)["description"]
            for key in GENERATOR.ROUTE_HANDLERS
            if operation(self.openapi, key)["x-scheduling-authority"] == "task-grant"
        )
        for action in (
            "hold.create",
            "hold.release",
            "appointment.create",
            "appointment.reschedule",
            "appointment.cancel",
        ):
            self.assertIn(action, described)
        self.assertIn("hold.create, hold.release, appointment.create, appointment.reschedule, appointment.cancel",
                      self.openapi["components"]["securitySchemes"]["bearerAuth"]["description"])

    def test_the_document_carries_no_tag_list_and_no_timestamp(self) -> None:
        self.assertNotIn("tags", self.openapi)
        self.assertEqual("3.1.0", self.openapi["openapi"])
        self.assertEqual("Registry Scheduling API", self.openapi["info"]["title"])
        self.assertEqual("v1alpha1", self.openapi["info"]["version"])
        self.assertEqual(
            [{
                "url": "https://scheduling.example.test",
                "description": "Operator-managed TLS endpoint in front of the private Scheduling runtime.",
            }],
            self.openapi["servers"],
        )
        self.assertEqual({"name": "Apache-2.0", "identifier": "Apache-2.0"},
                         self.openapi["info"]["license"])
        self.assertNotRegex(self.committed, r"20\d\d-\d\d-\d\d")

    def test_wire_documents_match_the_rust_structs_field_for_field(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        wire = GENERATOR.production_source(ROOT, GENERATOR.WIRE_SOURCE)
        for rust_name, schema_name in GENERATOR.SCHEMA_STRUCTS[GENERATOR.WIRE_SOURCE].items():
            self.assertEqual(
                {GENERATOR.camel_case(field) for field in GENERATOR.rust_struct_fields(wire, rust_name)},
                set(schemas[schema_name]["properties"]),
                rust_name,
            )

    def test_dto_drift_fails_the_generator(self) -> None:
        bad_openapi = copy.deepcopy(self.openapi)
        del bad_openapi["components"]["schemas"]["OfferingDocument"]["properties"]["window"]
        with self.assertRaisesRegex(ValueError, "DTO shape drifted from OfferingDocument"):
            GENERATOR.verify_dto_schemas(ROOT, bad_openapi)

    def test_query_parameter_drift_fails_the_generator(self) -> None:
        bad_openapi = copy.deepcopy(self.openapi)
        parameters = bad_openapi["paths"]["/v1/services"]["get"]["parameters"]
        bad_openapi["paths"]["/v1/services"]["get"]["parameters"] = [
            item for item in parameters if item["name"] != "limit"
        ]
        with self.assertRaisesRegex(ValueError, "OpenAPI query parameters drifted"):
            GENERATOR.verify_handler_wiring(ROOT, bad_openapi["paths"], self.variants)

    def test_a_drifted_problem_response_fails_the_generator(self) -> None:
        bad_openapi = copy.deepcopy(self.openapi)
        bad_openapi["paths"]["/v1/services"]["get"]["responses"]["409"] = copy.deepcopy(
            self.openapi["paths"]["/v1/holds"]["post"]["responses"]["409"]
        )
        with self.assertRaisesRegex(ValueError, "per-operation problem mapping drifted"):
            GENERATOR.verify_operation_problems(
                bad_openapi, self.contract, self.catalog, self.variants
            )

    def test_a_page_is_its_items_and_the_cursor_that_continues_it(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        wire = GENERATOR.production_source(ROOT, GENERATOR.WIRE_SOURCE)
        page_fields = {
            GENERATOR.camel_case(field)
            for field in GENERATOR.rust_struct_fields(wire, "PageDocument")
        }
        self.assertEqual({"items", "nextCursor"}, page_fields)
        for name in (
            "ServicePage",
            "OfferingPage",
            "ResourcePage",
            "LocationPage",
            "AvailabilityPage",
            "AppointmentHistoryPage",
        ):
            self.assertEqual(page_fields, set(schemas[name]["properties"]), name)
            self.assertEqual(["items", "nextCursor"], sorted(schemas[name]["required"]), name)
            self.assertEqual({"anyOf": [{"type": "string"}, {"type": "null"}]},
                             schemas[name]["properties"]["nextCursor"])
        self.assertEqual("#/components/schemas/AvailabilityEntry",
                         schemas["AvailabilityPage"]["properties"]["items"]["items"]["$ref"])

    def test_the_offering_projection_keeps_its_mode_vocabulary_and_its_nulls(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        offering = schemas["OfferingDocument"]
        wire = GENERATOR.production_source(ROOT, GENERATOR.WIRE_SOURCE)
        self.assertEqual({"exact-time", "arrival-window"}, set(offering["properties"]["mode"]["enum"]))
        self.assertEqual(
            set(GENERATOR.rust_kebab_case_unit_enum_values(wire, "SchedulingModeDocument")),
            set(offering["properties"]["mode"]["enum"]),
        )
        for field in ("durationMinutes", "bufferBeforeMinutes", "bufferAfterMinutes",
                      "startIncrementMinutes", "maxRecipients", "window"):
            self.assertNotIn(field, offering["required"], field)
            self.assertEqual({"type": "null"}, offering["properties"][field]["anyOf"][1], field)
        self.assertIn("null, never zero", self.openapi["paths"]["/v1/offerings"]["get"]["description"])

    def test_an_appointment_state_is_the_closed_vocabulary_the_wire_names(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        wire = GENERATOR.production_source(ROOT, GENERATOR.WIRE_SOURCE)
        self.assertEqual({"confirmed", "cancelled"}, set(schemas["AppointmentState"]["enum"]))
        self.assertEqual(
            set(GENERATOR.rust_kebab_case_unit_enum_values(wire, "AppointmentStateDocument")),
            set(schemas["AppointmentState"]["enum"]),
        )

    def test_availability_entries_discriminate_on_the_wire_kind_tag(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        entry = schemas["AvailabilityEntry"]
        self.assertEqual(["AvailabilitySlot", "AvailabilityWindow"],
                         [variant["$ref"].rsplit("/", 1)[1] for variant in entry["oneOf"]])
        self.assertEqual("kind", entry["discriminator"]["propertyName"])
        self.assertEqual("slot", schemas["AvailabilitySlot"]["properties"]["kind"]["const"])
        self.assertEqual("window", schemas["AvailabilityWindow"]["properties"]["kind"]["const"])
        self.assertEqual({"kind", "start", "end", "free"}, set(schemas["AvailabilitySlot"]["required"]))
        self.assertEqual({"kind", "window", "start", "end", "remaining"},
                         set(schemas["AvailabilityWindow"]["required"]))
        self.assertIn("channelRemaining", schemas["AvailabilityWindow"]["properties"])

    def test_the_explain_projection_leaves_a_clean_answer_undefended(self) -> None:
        explain = self.openapi["components"]["schemas"]["ExplainDocument"]
        self.assertEqual(["offering", "start"], sorted(explain["required"]))
        for field in ("publicCode", "detailedCode", "explanation"):
            self.assertNotIn(field, explain["required"], field)
            self.assertNotIn("anyOf", explain["properties"][field], field)
        self.assertIn("answers with no codes at all",
                      self.openapi["paths"]["/v1/availability/explain"]["get"]["description"])

    def test_a_create_carries_exactly_one_of_hold_or_admission(self) -> None:
        create = self.openapi["components"]["schemas"]["CreateAppointmentRequest"]
        self.assertEqual({"hold", "admission"}, set(create["properties"]))
        self.assertEqual(1, create["minProperties"])
        self.assertIn("Exactly one of hold or admission", create["description"])
        self.assertIn("Both, or neither, is request.invalid", create["description"])

    def test_the_documented_bounds_are_the_rust_ones(self) -> None:
        naming = GENERATOR.production_source(ROOT, GENERATOR.NAMING_SOURCE)
        cursors = GENERATOR.production_source(ROOT, GENERATOR.CURSORS_SOURCE)
        service = GENERATOR.production_source(ROOT, GENERATOR.SERVICE_SOURCE)
        http = GENERATOR.production_source(ROOT, GENERATOR.HTTP_SOURCE)
        httpsec = GENERATOR.production_source(ROOT, GENERATOR.HTTPSEC_SOURCE)
        self.assertIn('pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";', naming)
        self.assertIn("pub const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 128;", naming)
        self.assertIn("byte.is_ascii_graphic()", http)
        self.assertIn("value.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES", http)
        self.assertIn("pub const CURSOR_LIFETIME_MINUTES: i64 = 15;", cursors)
        self.assertIn("const MAXIMUM_CURSOR_BYTES: usize = 256;", cursors)
        self.assertIn("pub const DEFAULT_PAGE_LIMIT: usize = 50;", service)
        self.assertIn("pub const MAXIMUM_PAGE_LIMIT: usize = 200;", service)
        self.assertIn("const MAXIMUM_AVAILABILITY_SPAN_DAYS: i64 = 62;", service)
        self.assertIn("pub const DEFAULT_REQUEST_BODY_LIMIT_BYTES: usize = 1024 * 1024;", httpsec)
        for action in ("hold.create", "hold.release", "appointment.create",
                       "appointment.reschedule", "appointment.cancel"):
            self.assertIn(f'"{action}"', service)
        self.assertIn("15-minute", parameter(self.openapi, "get", "/v1/services", "cursor")["description"])
        self.assertIn("62 days", self.openapi["paths"]["/v1/availability"]["get"]["description"])

    def test_the_request_edge_rejection_map_is_the_rust_one(self) -> None:
        http = GENERATOR.production_source(ROOT, GENERATOR.HTTP_SOURCE)
        for text in (
            "StatusCode::BAD_REQUEST => Some(ProblemCode::RequestInvalid)",
            "StatusCode::PAYLOAD_TOO_LARGE => Some(ProblemCode::RequestBodyTooLarge)",
            "StatusCode::UNSUPPORTED_MEDIA_TYPE => Some(ProblemCode::RequestUnsupportedMediaType)",
            "StatusCode::UNPROCESSABLE_ENTITY => Some(ProblemCode::RequestUnprocessable)",
            "problem_response(ProblemCode::RequestNotFound)",
            "problem_response(ProblemCode::RequestMethodNotAllowed)",
        ):
            self.assertIn(text, http)
        for key in GENERATOR.ROUTE_HANDLERS:
            self.assertIn("request.body-too-large", documented_codes(self.openapi, key), key)
            self.assertIn("request.method-not-allowed", documented_codes(self.openapi, key), key)

    def test_the_problem_envelope_is_the_platform_one(self) -> None:
        problem = self.openapi["components"]["schemas"]["Problem"]
        self.assertEqual({"type", "title", "status", "detail", "code", "traceId"},
                         set(problem["properties"]))
        self.assertEqual(["code", "detail", "status", "title", "traceId", "type"],
                         sorted(problem["required"]))
        self.assertEqual(32, len(problem["properties"]["code"]["enum"]))
        httpsec = GENERATOR.production_source(ROOT, GENERATOR.HTTPSEC_SOURCE)
        http = GENERATOR.production_source(ROOT, GENERATOR.HTTP_SOURCE)
        body = GENERATOR.rust_struct_fields(httpsec, "ProblemBody")
        self.assertEqual({"type_uri", "title", "status", "detail", "code", "trace_id"}, body)
        self.assertIn('CACHE_CONTROL,\n        "no-store"', http)
        self.assertIn('RETRY_AFTER,\n            "5"', http)
        self.assertIn('"Bearer"', http)

    def test_the_committed_document_is_the_one_this_generator_writes(self) -> None:
        self.assertEqual(self.committed, json.dumps(self.openapi, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    unittest.main()
