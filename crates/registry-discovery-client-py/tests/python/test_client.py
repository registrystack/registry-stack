from __future__ import annotations

import http.server
import json
import threading
import unittest

from bootstrap import ensure_built

ensure_built()

from registry_discovery_client import (
    DiscoveryClient,
    DiscoveryClientError,
    select_evidence_alternative,
    select_evidence_service,
    select_relay_service,
    validate_selection,
)


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
RELAY_SERVICE = {
    **SERVICE,
    "bindingId": "urn:example:binding:relay",
    "serviceId": "urn:example:service:relay",
    "serviceKind": "relay",
    "registryAuthorityId": "urn:example:registry-authority",
    "evidenceTypeIds": [],
    "semanticClassIds": ["urn:example:registered-business"],
    "operationFamilyIds": ["urn:example:consultation-list"],
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
            found = client.search_evidence_services({
                "evidenceTypeId": "urn:example:evidence-type",
            })
            resolved = client.resolve_evidence_types({
                "requirementId": "urn:example:requirement",
            })
            resolution = select_evidence_alternative(resolved)
            request = {
                "recordId": "record-a",
                "evidenceTypeId": "urn:example:evidence-type",
                "resolution": resolution,
            }
            selection = client.select_evidence_service(found, request)
            self.assertEqual(selection["originContentDigest"], DIGEST)
            self.assertEqual(
                select_evidence_service(found, request)["endpointUrl"],
                SERVICE["endpointUrl"],
            )
            self.assertEqual(
                selection["evidenceResolution"]["requirementId"],
                "urn:example:requirement",
            )
            self.assertEqual(validate_selection(selection)["recordId"], "record-a")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

        self.assertEqual(json.loads(json.dumps(selection))["recordId"], "record-a")

    def test_configuration_failure_has_a_stable_kind(self) -> None:
        with self.assertRaises(DiscoveryClientError) as caught:
            DiscoveryClient("http://provider.example.invalid/")
        self.assertEqual(caught.exception.kind, "configuration")

    def test_relay_selection_retains_the_correlated_capability_match(self) -> None:
        selection = select_relay_service(
            {"catalogRevision": DIGEST, "items": [RELAY_SERVICE]},
            {
                "recordId": RELAY_SERVICE["recordId"],
                "capabilityMatch": {
                    "semanticClassId": "urn:example:registered-business",
                    "operationFamilyId": "urn:example:consultation-list",
                },
            },
        )
        self.assertEqual(
            selection["relayCapabilityMatch"],
            {
                "semanticClassId": "urn:example:registered-business",
                "operationFamilyId": "urn:example:consultation-list",
            },
        )
        self.assertEqual(validate_selection(selection)["serviceKind"], "relay")

    def test_supported_large_response_remains_selectable(self) -> None:
        items = []
        for index in range(1_100):
            suffix = f"{index:04d}"
            items.append({
                **SERVICE,
                "recordId": f"record-{suffix}",
                "bindingId": f"urn:example:binding:{suffix}",
                "serviceId": f"urn:example:service:{suffix}",
                "description": "x" * 4_096,
            })
        response = {"catalogRevision": DIGEST, "items": items}
        encoded = json.dumps(response, separators=(",", ":")).encode()
        self.assertGreater(len(encoded), 4 * 1024 * 1024)
        self.assertLess(len(encoded), 16 * 1024 * 1024)

        selection = select_evidence_service(response, {
            "recordId": "record-0000",
            "evidenceTypeId": "urn:example:evidence-type",
        })
        self.assertEqual(selection["recordId"], "record-0000")

    def test_supported_large_persisted_selection_remains_validatable(self) -> None:
        def identifiers(namespace: str) -> list[str]:
            values = []
            for index in range(256):
                prefix = f"urn:example:{namespace}:{index:03d}:"
                values.append(prefix + "x" * (4_096 - len(prefix)))
            return values

        semantic_classes = identifiers("semantic")
        operation_families = identifiers("operation")
        service = {
            **RELAY_SERVICE,
            "jurisdictions": identifiers("jurisdiction"),
            "conformsTo": identifiers("profile"),
            "semanticClassIds": semantic_classes,
            "operationFamilyIds": operation_families,
        }
        selection = select_relay_service(
            {"catalogRevision": DIGEST, "items": [service]},
            {
                "recordId": service["recordId"],
                "capabilityMatch": {
                    "semanticClassId": semantic_classes[0],
                    "operationFamilyId": operation_families[0],
                },
            },
        )
        encoded = json.dumps(selection, separators=(",", ":")).encode()
        self.assertGreater(len(encoded), 4 * 1024 * 1024)
        self.assertLess(len(encoded), 16 * 1024 * 1024)
        self.assertEqual(validate_selection(selection)["recordId"], service["recordId"])

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
            lambda: select_evidence_service([], {"recordId": "record-a"}),
        ]
        for operation in invalid_operations:
            with self.subTest(operation=operation), self.assertRaises(DiscoveryClientError) as caught:
                operation()
            self.assertEqual(caught.exception.kind, "query")
            self.assertEqual(str(caught.exception), "the Discovery query is invalid")
            self.assertNotIn("secret-filter-canary", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
