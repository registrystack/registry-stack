from __future__ import annotations

import http.server
import json
import threading
import unittest

from bootstrap import ensure_built

ensure_built()

from registry_discovery_client import DiscoveryClient, DiscoveryClientError, select_exact


DIGEST = "sha256:" + "1" * 64
SERVICE = {
    "recordId": "record-a",
    "bindingId": "urn:example:binding:a",
    "serviceId": "urn:example:service:a",
    "serviceKind": "evidence",
    "title": "Evidence service",
    "description": "Issues minimum-disclosure evidence",
    "endpointUrl": "https://provider.example/evidence",
    "publisherId": "urn:example:publisher",
    "jurisdictions": ["urn:example:jurisdiction"],
    "conformsTo": ["urn:example:profile"],
    "evidenceTypeIds": ["urn:example:evidence-type"],
    "semanticClassIds": [],
    "operationFamilyIds": [],
    "originId": "origin-a",
    "originUrl": "https://provider.example/catalog.jsonld",
    "originContentDigest": DIGEST,
    "originFetchedAt": "2026-08-15T00:00:00Z",
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if not self.path.startswith("/v1/services"):
            self.send_error(404)
            return
        self._json({"catalogRevision": DIGEST, "items": [SERVICE]})

    def do_POST(self) -> None:
        if self.path != "/v1/evidence-types/resolve":
            self.send_error(404)
            return
        self._json({
            "requirementId": "urn:example:requirement",
            "mappingRevision": DIGEST,
            "alternatives": [{
                "evidenceTypeListId": "urn:example:list",
                "evidenceTypeIds": ["urn:example:evidence-type"],
                "mappingId": "urn:example:mapping",
                "mappingAuthorityId": "urn:example:mapping-authority",
            }],
        })

    def _json(self, value: object) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class DiscoveryClientTests(unittest.TestCase):
    def test_search_resolve_and_inert_selection(self) -> None:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = DiscoveryClient(f"http://127.0.0.1:{server.server_port}/")
            found = client.search_services({
                "serviceKind": ["evidence"],
                "evidenceType": ["urn:example:evidence-type"],
            })
            resolved = client.resolve_evidence_types({
                "requirementId": "urn:example:requirement",
            })
            request = {
                "recordId": "record-a",
                "matchedCapability": {
                    "kind": "evidence-type",
                    "id": "urn:example:evidence-type",
                },
                "mappingRevision": resolved["mappingRevision"],
            }
            selection = client.select_exact(found, request)
            self.assertEqual(selection["originContentDigest"], DIGEST)
            self.assertEqual(select_exact(found, request)["endpointUrl"], SERVICE["endpointUrl"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        self.assertEqual(json.loads(json.dumps(selection))["recordId"], "record-a")

    def test_configuration_failure_has_a_stable_kind(self) -> None:
        with self.assertRaises(DiscoveryClientError) as caught:
            DiscoveryClient("http://provider.example.invalid/")
        self.assertEqual(caught.exception.kind, "configuration")

    def test_configuration_values_are_bounded_and_value_free(self) -> None:
        invalid_configurations = [
            {"request_timeout_seconds": 1e300},
            {"connect_timeout_seconds": float("inf")},
            {"maximum_response_bytes": True},
            {"trusted_root_certificates": bytearray(b"not ordinary bytes")},
            {"trusted_root_certificates": b"x" * (4 * 1024 * 1024 + 1)},
        ]
        for options in invalid_configurations:
            with self.subTest(options=options), self.assertRaises(DiscoveryClientError) as caught:
                DiscoveryClient("https://provider.example.invalid/", **options)
            self.assertEqual(caught.exception.kind, "configuration")
            self.assertEqual(
                str(caught.exception),
                "the Discovery client configuration is invalid",
            )

        with self.assertRaises(DiscoveryClientError) as caught:
            DiscoveryClient(1)
        self.assertEqual(caught.exception.kind, "configuration")
        self.assertEqual(
            str(caught.exception),
            "the Discovery client configuration is invalid",
        )

    def test_query_and_selection_values_use_stable_errors(self) -> None:
        client = DiscoveryClient("https://provider.example.invalid/")
        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        nested: object = {}
        for _ in range(128):
            nested = {"next": nested}

        class JsonLike:
            def __iter__(self) -> object:
                raise AssertionError("the binding must not invoke caller conversion hooks")

        invalid_operations = [
            lambda: client.search_services(cyclic),
            lambda: client.search_services(nested),
            lambda: client.search_services({"serviceKind": JsonLike()}),
            lambda: client.resolve_evidence_types({"requirementId": JsonLike()}),
            lambda: client.search_services({"serviceKind": "secret-filter-canary"}),
            lambda: client.search_services(({"serviceKind": []},)),
            lambda: select_exact([], {"recordId": "record-a"}),
        ]
        for operation in invalid_operations:
            with self.subTest(operation=operation), self.assertRaises(DiscoveryClientError) as caught:
                operation()
            self.assertEqual(caught.exception.kind, "query")
            self.assertEqual(str(caught.exception), "the Discovery query is invalid")
            self.assertNotIn("secret-filter-canary", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
