from __future__ import annotations

import copy
import hashlib
import http.server
import json
import threading
import unittest

from bootstrap import ensure_built

ensure_built()

from registry_discovery_client import (
    DiscoveryClient,
    DiscoveryClientError,
    accept_selection,
    renew_unchanged_selection,
    select_evidence_alternative,
    select_evidence_service,
    select_relay_service,
    validate_selection,
    validate_selection_structure,
)


def with_derived_binding_id(value: dict[str, object]) -> dict[str, object]:
    identity = {
        "conformsTo": value["conformsTo"],
        "endpointUrl": value["endpointUrl"],
        "evidenceTypeIds": value["evidenceTypeIds"],
        "operationFamilyIds": value["operationFamilyIds"],
        "semanticClassIds": value["semanticClassIds"],
        "serviceId": value["serviceId"],
        "serviceKind": value["serviceKind"],
    }
    canonical = json.dumps(
        identity,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    return {
        **value,
        "bindingId": f"urn:registrystack:discovery:binding:sha256:{digest}",
    }


DIGEST = "sha256:" + "1" * 64
NEXT_DIGEST = "sha256:" + "2" * 64
NEWEST_DIGEST = "sha256:" + "3" * 64
SERVICE = with_derived_binding_id({
    "recordId": "record-a",
    "serviceId": "urn:example:service:a",
    "serviceKind": "evidence",
    "title": "Evidence service",
    "description": "Issues minimum-disclosure evidence",
    "endpointUrl": "https://provider.example/evidence",
    "publisherId": "urn:example:publisher",
    "legalIssuerId": "urn:example:legal-issuer",
    "technicalProviderId": "urn:example:technical-provider",
    "jurisdictions": ["urn:example:jurisdiction"],
    "conformsTo": ["urn:example:profile"],
    "evidenceTypeIds": ["urn:example:evidence-type"],
    "semanticClassIds": [],
    "operationFamilyIds": [],
    "originId": "origin-a",
    "originUrl": "https://provider.example/catalog.jsonld",
    "originContentDigest": DIGEST,
    "originFetchedAt": "2026-08-15T00:00:00Z",
})
RELAY_SERVICE = with_derived_binding_id({
    **SERVICE,
    "serviceId": "urn:example:service:relay",
    "serviceKind": "relay",
    "registryAuthorityId": "urn:example:registry-authority",
    "evidenceTypeIds": [],
    "semanticClassIds": ["urn:example:registered-business"],
    "operationFamilyIds": ["urn:example:consultation-list"],
})


def evidence_resolution() -> dict[str, object]:
    return select_evidence_alternative({
        "requirementId": "urn:example:requirement",
        "jurisdiction": "urn:example:jurisdiction",
        "mappingRevision": DIGEST,
        "alternatives": [{
            "evidenceTypeListId": "urn:example:list",
            "evidenceTypeIds": ["urn:example:evidence-type"],
            "mappingId": "urn:example:mapping",
            "mappingAuthorityId": "urn:example:mapping-authority",
        }],
    })


def evidence_selection(service: dict[str, object] | None = None) -> dict[str, object]:
    selected_service = SERVICE if service is None else service
    return select_evidence_service(
        {"catalogRevision": DIGEST, "items": [selected_service]},
        {
            "recordId": selected_service["recordId"],
            "evidenceTypeId": "urn:example:evidence-type",
            "resolution": evidence_resolution(),
        },
    )


def evidence_acceptance_subject(candidate: dict[str, object]) -> dict[str, object]:
    """Project only the fields this adopter has independently pinned."""
    return {
        "serviceKind": candidate["serviceKind"],
        "serviceId": candidate["serviceId"],
        "endpointUrl": candidate["endpointUrl"],
        "publisherId": candidate.get("publisherId"),
        "legalIssuerId": candidate.get("legalIssuerId"),
        "technicalProviderId": candidate.get("technicalProviderId"),
        "jurisdictions": candidate["jurisdictions"],
        "conformsTo": candidate["conformsTo"],
        "matchedCapability": candidate["matchedCapability"],
        "evidenceResolution": candidate.get("evidenceResolution"),
        "mappingRevision": candidate.get("mappingRevision"),
        "originId": candidate["originId"],
        "originUrl": candidate["originUrl"],
    }


EVIDENCE_ACCEPTANCE_PINS = {
    "serviceKind": "evidence",
    "serviceId": "urn:example:service:a",
    "endpointUrl": "https://provider.example/evidence",
    "publisherId": "urn:example:publisher",
    "legalIssuerId": "urn:example:legal-issuer",
    "technicalProviderId": "urn:example:technical-provider",
    "jurisdictions": ["urn:example:jurisdiction"],
    "conformsTo": ["urn:example:profile"],
    "matchedCapability": {
        "kind": "evidence-type",
        "id": "urn:example:evidence-type",
    },
    "evidenceResolution": {
        "requirementId": "urn:example:requirement",
        "jurisdiction": "urn:example:jurisdiction",
        "mappingRevision": DIGEST,
        "evidenceTypeListId": "urn:example:list",
        "evidenceTypeIds": ["urn:example:evidence-type"],
        "mappingId": "urn:example:mapping",
        "mappingAuthorityId": "urn:example:mapping-authority",
    },
    "mappingRevision": DIGEST,
    "originId": "origin-a",
    "originUrl": "https://provider.example/catalog.jsonld",
}


def accepts_expected_evidence(candidate: dict[str, object]) -> bool:
    return evidence_acceptance_subject(candidate) == EVIDENCE_ACCEPTANCE_PINS


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

    def test_exact_local_acceptance_precedes_credentials_and_native_io(self) -> None:
        selection = evidence_selection()
        events: list[str] = []

        def accept(candidate: dict[str, object]) -> bool:
            events.append("local-acceptance")
            return accepts_expected_evidence(candidate)

        accepted = accept_selection(selection, accept)
        events.append("credential-construction")
        events.append("native-io")

        self.assertEqual(
            events,
            ["local-acceptance", "credential-construction", "native-io"],
        )
        self.assertEqual(accepted.endpoint_url, SERVICE["endpointUrl"])
        self.assertEqual(accepted.selection, selection)

        mutations: dict[str, dict[str, object]] = {}

        changed = copy.deepcopy(selection)
        changed["endpointUrl"] = "https://attacker.example/evidence"
        mutations["endpoint"] = with_derived_binding_id(changed)

        changed = copy.deepcopy(selection)
        changed["serviceId"] = "urn:example:service:other"
        mutations["service identity"] = with_derived_binding_id(changed)

        changed = copy.deepcopy(selection)
        changed["legalIssuerId"] = "urn:example:legal-issuer:other"
        mutations["legal issuer"] = changed

        changed = copy.deepcopy(selection)
        changed["technicalProviderId"] = "urn:example:technical-provider:other"
        mutations["technical provider"] = changed

        changed = copy.deepcopy(selection)
        changed["conformsTo"] = ["urn:example:profile:other"]
        mutations["profile"] = with_derived_binding_id(changed)

        changed = copy.deepcopy(selection)
        changed["jurisdictions"] = ["urn:example:jurisdiction:other"]
        changed["evidenceResolution"]["jurisdiction"] = (
            "urn:example:jurisdiction:other"
        )
        mutations["jurisdiction"] = changed

        changed = copy.deepcopy(selection)
        changed["evidenceTypeIds"] = ["urn:example:evidence-type:other"]
        changed["matchedCapability"]["id"] = "urn:example:evidence-type:other"
        changed["evidenceResolution"]["evidenceTypeIds"] = [
            "urn:example:evidence-type:other"
        ]
        mutations["capability"] = with_derived_binding_id(changed)

        changed = copy.deepcopy(selection)
        changed["evidenceResolution"]["mappingAuthorityId"] = (
            "urn:example:mapping-authority:other"
        )
        mutations["mapping context"] = changed

        changed = copy.deepcopy(selection)
        changed.pop("evidenceResolution")
        changed.pop("mappingRevision")
        mutations["missing resolution context"] = changed

        for label, candidate in mutations.items():
            with self.subTest(label=label):
                self.assertEqual(validate_selection_structure(candidate), candidate)
                rejected_events: list[str] = []

                def reject_unpinned(value: dict[str, object]) -> bool:
                    rejected_events.append("local-acceptance")
                    return accepts_expected_evidence(value)

                with self.assertRaises(DiscoveryClientError) as caught:
                    accepted_candidate = accept_selection(candidate, reject_unpinned)
                    rejected_events.append("credential-construction")
                    _ = accepted_candidate.endpoint_url
                    rejected_events.append("native-io")
                self.assertEqual(caught.exception.kind, "local_acceptance_refused")
                self.assertEqual(rejected_events, ["local-acceptance"])

    def test_renewal_only_updates_provenance_for_the_same_accepted_subject(self) -> None:
        previous = evidence_selection()
        current = copy.deepcopy(previous)
        current["originContentDigest"] = NEXT_DIGEST
        current["originFetchedAt"] = "2026-08-25T00:00:00Z"
        current["catalogRevision"] = NEWEST_DIGEST

        renewed = renew_unchanged_selection(previous, current)
        self.assertEqual(renewed, current)
        self.assertEqual(renewed["originContentDigest"], NEXT_DIGEST)
        self.assertEqual(renewed["originFetchedAt"], "2026-08-25T00:00:00Z")
        self.assertEqual(renewed["catalogRevision"], NEWEST_DIGEST)
        self.assertEqual(
            accept_selection(renewed, accepts_expected_evidence).endpoint_url,
            SERVICE["endpointUrl"],
        )

        token_constructions = 0
        native_calls = 0

        def continue_after_renewal(
            baseline: dict[str, object],
            candidate: dict[str, object],
        ) -> dict[str, object]:
            nonlocal token_constructions, native_calls
            result = renew_unchanged_selection(baseline, candidate)
            token_constructions += 1
            native_calls += 1
            return result

        changed_subjects: dict[str, dict[str, object]] = {}

        changed = copy.deepcopy(current)
        changed["legalIssuerId"] = "urn:example:legal-issuer:other"
        changed_subjects["issuer"] = changed

        changed = copy.deepcopy(current)
        changed["jurisdictions"] = ["urn:example:jurisdiction:other"]
        changed["evidenceResolution"]["jurisdiction"] = (
            "urn:example:jurisdiction:other"
        )
        changed_subjects["jurisdiction"] = changed

        changed = copy.deepcopy(current)
        changed["mappingRevision"] = NEXT_DIGEST
        changed["evidenceResolution"]["mappingRevision"] = NEXT_DIGEST
        changed_subjects["mapping revision"] = changed

        changed = copy.deepcopy(current)
        changed["evidenceResolution"]["mappingAuthorityId"] = (
            "urn:example:mapping-authority:other"
        )
        changed_subjects["mapping authority"] = changed

        changed = copy.deepcopy(current)
        changed.pop("evidenceResolution")
        changed.pop("mappingRevision")
        changed_subjects["missing resolution context"] = changed

        changed = copy.deepcopy(current)
        changed["endpointUrl"] = "https://provider.example/evidence-v2"
        changed_subjects["endpoint"] = with_derived_binding_id(changed)

        changed = copy.deepcopy(current)
        changed["conformsTo"] = ["urn:example:profile:other"]
        changed_subjects["profile"] = with_derived_binding_id(changed)

        changed = copy.deepcopy(current)
        changed["evidenceTypeIds"] = ["urn:example:evidence-type:other"]
        changed["matchedCapability"]["id"] = "urn:example:evidence-type:other"
        changed["evidenceResolution"]["evidenceTypeIds"] = [
            "urn:example:evidence-type:other"
        ]
        changed_subjects["capability"] = with_derived_binding_id(changed)

        for label, candidate in changed_subjects.items():
            with self.subTest(label=label), self.assertRaises(
                DiscoveryClientError
            ) as caught:
                continue_after_renewal(previous, candidate)
            self.assertEqual(caught.exception.kind, "selection_changed")

        relay_with_two_operations = with_derived_binding_id({
            **RELAY_SERVICE,
            "operationFamilyIds": [
                "urn:example:consultation-list",
                "urn:example:consultation-search",
            ],
        })
        relay_previous = select_relay_service(
            {"catalogRevision": DIGEST, "items": [relay_with_two_operations]},
            {
                "recordId": relay_with_two_operations["recordId"],
                "capabilityMatch": {
                    "semanticClassId": "urn:example:registered-business",
                    "operationFamilyId": "urn:example:consultation-list",
                },
            },
        )
        relay_current = select_relay_service(
            {
                "catalogRevision": NEWEST_DIGEST,
                "items": [relay_with_two_operations],
            },
            {
                "recordId": relay_with_two_operations["recordId"],
                "capabilityMatch": {
                    "semanticClassId": "urn:example:registered-business",
                    "operationFamilyId": "urn:example:consultation-search",
                },
            },
        )
        with self.assertRaises(DiscoveryClientError) as caught:
            continue_after_renewal(relay_previous, relay_current)
        self.assertEqual(caught.exception.kind, "selection_changed")

        reselected = changed_subjects["issuer"]
        new_pins = copy.deepcopy(EVIDENCE_ACCEPTANCE_PINS)
        new_pins["legalIssuerId"] = "urn:example:legal-issuer:other"
        explicitly_accepted = accept_selection(
            reselected,
            lambda candidate: evidence_acceptance_subject(candidate) == new_pins,
        )
        self.assertEqual(
            explicitly_accepted.selection["legalIssuerId"],
            "urn:example:legal-issuer:other",
        )

        with self.assertRaises(DiscoveryClientError) as caught:
            reselected = select_evidence_service(
                {"catalogRevision": NEWEST_DIGEST, "items": []},
                {
                    "recordId": previous["recordId"],
                    "evidenceTypeId": "urn:example:evidence-type",
                    "resolution": evidence_resolution(),
                },
            )
            token_constructions += 1
            native_calls += 1
            _ = reselected
        self.assertEqual(caught.exception.kind, "no_matching_service")
        self.assertEqual(token_constructions, 0)
        self.assertEqual(native_calls, 0)

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
            items.append(with_derived_binding_id({
                **SERVICE,
                "recordId": f"record-{suffix}",
                "serviceId": f"urn:example:service:{suffix}",
                "description": "x" * 4_096,
            }))
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
        service = with_derived_binding_id({
            **RELAY_SERVICE,
            "jurisdictions": identifiers("jurisdiction"),
            "conformsTo": identifiers("profile"),
            "semanticClassIds": semantic_classes,
            "operationFamilyIds": operation_families,
        })
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
