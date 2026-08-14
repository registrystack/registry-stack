#!/usr/bin/env python3
"""Offline smoke for an installed Registry Discovery Python client wheel."""

import json

import registry_discovery_client as client_module


DIGEST = "sha256:" + "1" * 64
RESPONSE = {
    "catalogRevision": DIGEST,
    "items": [
        {
            "recordId": "record-a",
            "bindingId": "urn:example:binding:a",
            "serviceId": "urn:example:service:a",
            "serviceKind": "evidence",
            "title": "Evidence service",
            "description": "Issues minimum-disclosure evidence",
            "endpointUrl": "https://provider.example/evidence",
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
