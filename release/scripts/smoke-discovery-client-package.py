#!/usr/bin/env python3
"""Offline smoke for an installed Registry Discovery Python client wheel."""

import json
import typing

import registry_discovery_client as client_module


DIGEST = "sha256:" + "1" * 64
NEXT_DIGEST = "sha256:" + "2" * 64
RESPONSE = {
    "catalogRevision": DIGEST,
    "items": [
        {
            "recordId": "record-a",
            "bindingId": "urn:registrystack:discovery:binding:sha256:3a316636cd4b722c008a02dcf61633c7be64aa85bc9d3c20d932a0a2e8e06129",
            "serviceId": "urn:example:service:a",
            "serviceKind": "evidence",
            "title": "Evidence service",
            "description": "Issues minimum-disclosure evidence",
            "endpointUrl": "https://provider.example/evidence",
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
        }
    ],
}
REQUEST = {
    "recordId": "record-a",
    "matchedCapability": {
        "kind": "evidence-type",
        "id": "urn:example:evidence-type",
    },
}


def main() -> None:
    for name in {
        "AcceptedServiceSelection",
        "DiscoveryClient",
        "DiscoveryClientError",
        "accept_selection",
        "renew_unchanged_selection",
        "select_exact",
        "validate_selection",
        "validate_selection_structure",
    }:
        if not callable(getattr(client_module, name, None)):
            raise SystemExit(f"the package must export {name}")

    # This reserved host makes the smoke fail closed if construction regresses
    # into network I/O. Exact selection is local and returns inert metadata.
    client = client_module.DiscoveryClient("https://discovery.invalid/")
    selection = client.select_exact(RESPONSE, REQUEST)
    if selection["endpointUrl"] != RESPONSE["items"][0]["endpointUrl"]:
        raise SystemExit("the selected endpoint changed")
    if client_module.select_exact(RESPONSE, REQUEST)["recordId"] != "record-a":
        raise SystemExit("the standalone selector changed")
    if json.loads(json.dumps(selection))["originContentDigest"] != DIGEST:
        raise SystemExit("the selection did not remain serializable")

    structurally_valid = client_module.validate_selection_structure(selection)
    if client_module.validate_selection(selection) != structurally_valid:
        raise SystemExit(
            "the legacy validation name is not a structural compatibility alias"
        )

    local_acceptance_calls = 0

    def accepts_expected_service(candidate: dict[str, object]) -> bool:
        nonlocal local_acceptance_calls
        local_acceptance_calls += 1
        return (
            candidate["serviceKind"] == "evidence"
            and candidate["serviceId"] == "urn:example:service:a"
            and candidate["endpointUrl"] == "https://provider.example/evidence"
            and candidate["legalIssuerId"] == "urn:example:legal-issuer"
            and candidate["technicalProviderId"]
            == "urn:example:technical-provider"
            and candidate["jurisdictions"] == ["urn:example:jurisdiction"]
            and candidate["conformsTo"] == ["urn:example:profile"]
            and candidate["matchedCapability"]
            == {
                "kind": "evidence-type",
                "id": "urn:example:evidence-type",
            }
        )

    accepted = client_module.accept_selection(
        structurally_valid,
        accepts_expected_service,
    )
    if not isinstance(accepted, client_module.AcceptedServiceSelection):
        raise SystemExit("explicit local acceptance returned the wrong type")
    if accepted.endpoint_url != RESPONSE["items"][0]["endpointUrl"]:
        raise SystemExit("explicit local acceptance returned the wrong endpoint")
    if accepted.selection != structurally_valid:
        raise SystemExit("explicit local acceptance changed the selection")
    if local_acceptance_calls != 1:
        raise SystemExit("explicit local acceptance did not run exactly once")
    accepted_type = client_module.AcceptedServiceSelection[dict[str, object]]
    if typing.get_origin(accepted_type) is not client_module.AcceptedServiceSelection:
        raise SystemExit("the accepted handoff is not subscriptable at runtime")

    current = {
        **selection,
        "catalogRevision": NEXT_DIGEST,
        "originContentDigest": NEXT_DIGEST,
        "originFetchedAt": "2026-08-25T00:00:00Z",
    }
    if client_module.renew_unchanged_selection(selection, current) != current:
        raise SystemExit("fresh provenance did not renew an unchanged selection")
    try:
        client_module.renew_unchanged_selection(
            selection,
            {
                **current,
                "legalIssuerId": "urn:example:legal-issuer:other",
            },
        )
    except client_module.DiscoveryClientError as error:
        if error.kind != "selection_changed":
            raise SystemExit(f"unexpected renewal error kind {error.kind!r}") from error
    else:
        raise SystemExit("trust-relevant selection drift must require new acceptance")

    try:
        client_module.DiscoveryClient("http://discovery.invalid/")
    except client_module.DiscoveryClientError as error:
        if error.kind != "configuration":
            raise SystemExit(f"unexpected error kind {error.kind!r}") from error
    else:
        raise SystemExit("an insecure base URL must be refused")
    print("Python Discovery client package smoke passed")


if __name__ == "__main__":
    main()
