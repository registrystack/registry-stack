"""Sanitized transport and discovery regressions; owned loopback servers only."""

import contextlib
import http.server
import importlib.util
import json
import os
from email.message import Message
from pathlib import Path
import threading
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


@contextlib.contextmanager
def local_server(handler):
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


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
            for path in [
                "/Patient/patient-synthetic", "/Coverage/coverage-synthetic?extra=true",
                "/Coverage/.", "/Coverage/..", "/Organization/.", "/Organization/..",
                "/Coverage/%2e%2e", "/Coverage/record/extra", "/Coverage/record#fragment",
                "//example.invalid/Coverage/record", "https://example.invalid/Coverage/record",
            ]:
                handler = object.__new__(source.FhirReadThrough)
                handler.path = path
                handler.send_body = lambda status, body, media: self.assertEqual(status, 404)
                handler.do_GET()
            upstream.assert_not_called()

    def test_dotted_and_hyphenated_ids_keep_the_fixed_origin_and_exact_path(self):
        for resource_type in ["Coverage", "Organization"]:
            identifier = "synthetic.record-1"
            body = json.dumps({"resourceType": resource_type, "id": identifier}).encode()
            handler = object.__new__(source.FhirReadThrough)
            handler.path = f"/{resource_type}/{identifier}"
            emitted = []
            handler.send_body = lambda *args: emitted.append(args)
            with patch.object(source.OPENER, "open", return_value=Response(body)) as upstream:
                handler.do_GET()
            request = upstream.call_args.args[0]
            self.assertEqual(request.full_url, f"{source.BASE_URL}/{resource_type}/{identifier}")
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("Accept"), "application/fhir+json")
            self.assertEqual(emitted, [(200, body, "application/json")])

    def test_test_origin_is_numeric_loopback_without_credentials_or_extra_components(self):
        for origin in [
            "http://example.invalid:8003", "http://localhost:8003", "http://[::1]:8003",
            "https://127.0.0.1:8003", "http://127.0.0.1", "http://user@127.0.0.1:8003",
            "http://127.0.0.1:8003/extra", "http://127.0.0.1:8003?query=true",
            "http://127.0.0.1:8003#fragment",
        ]:
            with self.subTest(origin=origin), patch.dict(os.environ, {"FHIR_TUTORIAL_TEST_BASE_URL": origin}):
                with self.assertRaisesRegex(RuntimeError, "numeric loopback HTTP"):
                    load("fhir_invalid_origin", "serve-source.py")
        with patch.dict(os.environ, {"FHIR_TUTORIAL_TEST_BASE_URL": "http://127.0.0.1:8003/"}):
            self.assertEqual(load("fhir_valid_origin", "serve-source.py").BASE_URL, "http://127.0.0.1:8003")

    def test_real_transport_refuses_redirects_and_ignores_ambient_proxies(self):
        seen = []

        class Destination(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                seen.append("destination")
                self.send_response(204)
                self.end_headers()

        with local_server(Destination) as destination:
            class Upstream(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_GET(self):
                    seen.append(self.path)
                    self.send_response(302)
                    self.send_header("Location", destination + "/unexpected")
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            with local_server(Upstream) as upstream, patch.object(source, "BASE_URL", upstream), patch.dict(os.environ, {
                "http_proxy": destination, "HTTP_PROXY": destination, "no_proxy": "", "NO_PROXY": "",
            }):
                handler = object.__new__(source.FhirReadThrough)
                handler.path = "/Coverage/synthetic.record-1"
                emitted = []
                handler.send_body = lambda *args: emitted.append(args)
                handler.do_GET()
        self.assertEqual(seen, ["/Coverage/synthetic.record-1"])
        self.assertEqual(emitted, [(502, b'{"error":"FHIR read failed"}\n', "application/json")])


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
