"""Sanitized transport and discovery regressions; no network or live records."""

import importlib.util
import json
from email.message import Message
from pathlib import Path
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source = load("fhir_source", "serve-source.py")
discovery = load("fhir_discovery", "discover-records.py")


class Response:
    status = 200

    def __init__(self, body):
        self.body = body
        self.headers = Message()
        self.headers["Content-Type"] = "application/fhir+json"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, maximum):
        return self.body[:maximum]


def handle(body, path="/Coverage/coverage-synthetic"):
    handler = object.__new__(source.FhirReadThrough)
    handler.path = path
    emitted = []
    handler.send_body = lambda status, data, media: emitted.append((status, data, media))
    with patch.object(source.OPENER, "open", return_value=Response(body)):
        handler.do_GET()
    return emitted


class SourceTests(unittest.TestCase):
    def test_valid_resource_preserves_exact_body(self):
        body = b'{"resourceType":"Coverage","id":"coverage-synthetic","status":"active"}\n'
        self.assertEqual(handle(body), [(200, body, "application/json")])

    def test_non_object_json_is_a_closed_failure(self):
        for value in [None, True, 42, "FHIR-PRIVATE-CANARY", []]:
            with self.subTest(kind=type(value).__name__):
                self.assertEqual(
                    handle(json.dumps(value).encode()),
                    [(502, b'{"error":"FHIR read failed"}\n', "application/json")],
                )

    def test_wrong_identity_and_resource_type_are_closed_failures(self):
        for value in [
            {"resourceType": "Coverage", "id": "another-synthetic"},
            {"resourceType": "Patient", "id": "coverage-synthetic"},
        ]:
            self.assertEqual(handle(json.dumps(value).encode())[0][0], 502)

    def test_malformed_and_oversized_json_are_closed_failures(self):
        for body in [b"invalid-json", b"x" * (source.MAXIMUM_BYTES + 1)]:
            self.assertEqual(handle(body)[0], (502, b'{"error":"FHIR read failed"}\n', "application/json"))

    def test_undeclared_paths_never_call_upstream(self):
        with patch.object(source.OPENER, "open") as upstream:
            for path in ["/Patient/patient-synthetic", "/Coverage/coverage-synthetic?extra=true"]:
                handler = object.__new__(source.FhirReadThrough)
                handler.path = path
                handler.send_body = lambda status, body, media: self.assertEqual(status, 404)
                handler.do_GET()
            upstream.assert_not_called()


class DiscoveryTests(unittest.TestCase):
    def test_non_object_json_is_a_value_free_refusal(self):
        for value in [None, [], "FHIR-PRIVATE-CANARY"]:
            with patch.object(discovery.OPENER, "open", return_value=Response(json.dumps(value).encode())):
                with self.assertRaisesRegex(RuntimeError, "^FHIR response is not an object$"):
                    discovery.read_fhir("Coverage")

    def test_malformed_search_shapes_are_refused(self):
        for bundle in [
            [],
            {"resourceType": "Bundle", "entry": {}},
            {"resourceType": "Bundle", "entry": [None]},
            {"resourceType": "Bundle", "entry": [{"resource": []}]},
        ]:
            with self.assertRaises(RuntimeError) as caught:
                list(discovery.resources(bundle, "Coverage"))
            self.assertNotIn("FHIR-PRIVATE-CANARY", str(caught.exception))

    def test_search_yields_only_resource_objects_of_the_requested_type(self):
        resource = {"resourceType": "Coverage", "id": "coverage-synthetic"}
        bundle = {"resourceType": "Bundle", "entry": [
            {"resource": resource}, {"resource": {"resourceType": "Organization"}}, {},
        ]}
        self.assertEqual(list(discovery.resources(bundle, "Coverage")), [resource])


if __name__ == "__main__":
    unittest.main()
