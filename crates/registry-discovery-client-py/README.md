# registry-discovery-client-py

Synchronous PyO3 binding for the bounded Rust `registry-discovery-client` SDK.
It performs exact service search, Evidence Type resolution, and ambiguity-safe
selection. A returned selection is inert public metadata. Apply local trust
policy before calling its Evidence or Relay endpoint.

This crate publishes through the unified `registry-stack-client`
distribution, which imports as `registry_client`. Install the exact client
version that matches the Discovery deployment, and use its `discovery`
namespace:

```sh
python -m pip install "registry-stack-client==<version>"
```

The distribution carries manylinux wheels requiring glibc 2.17 or newer for
Linux amd64 and Linux arm64, plus a macOS arm64 wheel.

Registry Stack v0.23.0 through v0.26.0 published this binding on its own, as
the `registry-discovery-client` distribution imported as
`registry_discovery_client`. Those versions stay published and unchanged, and
no later version joins them: from v0.26.1 the maintained Python client is
`registry-stack-client`.

The public methods accept only ordinary built-in JSON values: `None`, `bool`,
signed 64-bit `int`, finite `float`, `str`, `list`, and `dict` with string keys.
They reject custom objects, subclasses, tuples, cycles, and oversized values
before sending a request. Invalid configuration always raises
`DiscoveryClientError(kind="configuration")`; invalid request or selection
values raise `DiscoveryClientError(kind="query")`. Error messages never echo
caller values.

```python
from registry_client.discovery import (
    DiscoveryClient,
    accept_selection,
    select_evidence_alternative,
    select_evidence_service,
    validate_selection_structure,
)
from registry_client.evidence import EvidenceClient

# These values come from application-owned configuration or deployment
# ceremony. They are never copied from the Discovery response being checked.
evidence_pins = {
    "serviceId": "urn:example:service:evidence",
    "endpointUrl": "https://evidence.example.invalid/",
    "publisherId": "urn:example:publisher",
    "legalIssuerId": "urn:example:legal-issuer",
    "technicalProviderId": "urn:example:technical-provider",
    "jurisdictions": ["urn:example:jurisdiction"],
    "conformsTo": ["urn:example:evidence-profile"],
    "matchedCapability": {
        "kind": "evidence-type",
        "id": "urn:example:evidence-type",
    },
    "resolution": {
        "requirementId": "urn:example:requirement",
        "jurisdiction": "urn:example:jurisdiction",
        "mappingRevision": (
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        ),
        "evidenceTypeListId": "urn:example:evidence-list",
        "evidenceTypeIds": ["urn:example:evidence-type"],
        "mappingId": "urn:example:mapping",
        "mappingAuthorityId": "urn:example:mapping-authority",
    },
    "originId": "approved-origin",
    "originUrl": "https://publisher.example.invalid/catalog.jsonld",
}


def accepts_expected_evidence(candidate):
    resolution = candidate.get("evidenceResolution") or {}
    return (
        candidate["serviceKind"] == "evidence"
        and candidate["serviceId"] == evidence_pins["serviceId"]
        and candidate["endpointUrl"] == evidence_pins["endpointUrl"]
        and candidate.get("publisherId") == evidence_pins["publisherId"]
        and candidate.get("legalIssuerId") == evidence_pins["legalIssuerId"]
        and candidate.get("technicalProviderId")
        == evidence_pins["technicalProviderId"]
        and candidate["jurisdictions"] == evidence_pins["jurisdictions"]
        and candidate["conformsTo"] == evidence_pins["conformsTo"]
        and candidate["matchedCapability"] == evidence_pins["matchedCapability"]
        and {
            key: resolution.get(key)
            for key in evidence_pins["resolution"]
        }
        == evidence_pins["resolution"]
        and candidate["originId"] == evidence_pins["originId"]
        and candidate["originUrl"] == evidence_pins["originUrl"]
    )


client = DiscoveryClient("https://discovery.example.invalid/")
resolved = client.resolve_evidence_types({
    "requirementId": "urn:example:requirement",
    "jurisdiction": "urn:example:jurisdiction",
})
context = select_evidence_alternative(resolved)  # refuses zero or many alternatives
for evidence_type_id in context["evidenceTypeIds"]:
    services = client.search_evidence_services({
        "evidenceTypeId": evidence_type_id,
        "jurisdiction": context.get("jurisdiction"),
    })
    # The adopter chooses explicitly. Discovery supplies no catalog ranking.
    matches = [
        item for item in services["items"]
        if item["serviceId"] == evidence_pins["serviceId"]
    ]
    if len(matches) != 1:
        raise ValueError(
            "the locally expected Evidence service is unavailable or ambiguous"
        )
    chosen = matches[0]
    selection = select_evidence_service(services, {
        "recordId": chosen["recordId"],
        "evidenceTypeId": evidence_type_id,
        "resolution": context,
    })

    # Structural validation checks shape and capability binding. It does not
    # establish origin authenticity, currentness, or trust.
    checked = validate_selection_structure(selection)
    accepted = accept_selection(checked, accepts_expected_evidence)

    # Credentials and the native client are created only from the ephemeral
    # accepted handoff. The values below are application-owned configuration.
    evidence = EvidenceClient(
        accepted.endpoint_url,
        trusted_jwks,
        revoked_key_ids,
        token,
    )
    checked = accepted.selection
    resolution = checked.get("evidenceResolution")
    if resolution is None:
        raise ValueError("missing Evidence resolution")
    prepared = evidence.prepare({
        **local_evidence_policy,
        "requirement": resolution["requirementId"],
        "evidence_type": checked["matchedCapability"]["id"],
    })
    verified = evidence.request_and_verify(prepared)
```

An Evidence alternative is an AND-list. The loop performs the search, explicit
choice, trust check, and native request for every `context["evidenceTypeIds"]`
member.
The context supplies the resolved requirement and selected Evidence Type. The
native definition and local policy still supply the purpose, audience,
issuer/provider identity, configuration revision, selectors, and expected
outputs.

`validate_selection` remains a compatibility alias, but its behavior has
always been structural. New code should use `validate_selection_structure` so
the result cannot be mistaken for a trust decision.

## Persisted selections and renewal

Persist only the inert selection dictionary, never `AcceptedServiceSelection`.
Offline loading can establish structural validity, but cannot prove that the
catalog, mapping, endpoint, roles, or application policy are still current:

```python
import json

persisted = validate_selection_structure(json.loads(saved_selection_json))
if application_selection_age_is_acceptable(persisted["originFetchedAt"]):
    accepted = accept_selection(persisted, accepts_expected_evidence)
    # Construct credentials and the native client only after this point.
```

The application owns the offline age limit. Discovery deliberately supplies no
universal time-to-live.

For online renewal, resolve and search again, explicitly choose the same local
service, and build a fresh selection. `renew_unchanged_selection` accepts only
fetch-provenance and global catalog-revision changes:

```python
from registry_client.discovery import renew_unchanged_selection

previous_resolution = persisted["evidenceResolution"]
fresh_resolved = client.resolve_evidence_types({
    "requirementId": previous_resolution["requirementId"],
    "jurisdiction": previous_resolution.get("jurisdiction"),
})
fresh_context = select_evidence_alternative(
    fresh_resolved,
    previous_resolution["evidenceTypeListId"],
)
evidence_type_id = persisted["matchedCapability"]["id"]
fresh_services = client.search_evidence_services({
    "evidenceTypeId": evidence_type_id,
    "jurisdiction": fresh_context.get("jurisdiction"),
})
fresh_matches = [
    item for item in fresh_services["items"]
    if item["serviceId"] == evidence_pins["serviceId"]
]
if len(fresh_matches) != 1:
    raise ValueError(
        "the previously selected service was withdrawn or is ambiguous"
    )
fresh = select_evidence_service(fresh_services, {
    "recordId": fresh_matches[0]["recordId"],
    "evidenceTypeId": evidence_type_id,
    "resolution": fresh_context,
})
renewed = renew_unchanged_selection(persisted, fresh)
accepted = accept_selection(renewed, accepts_expected_evidence)
```

A changed service identity, endpoint, issuer/provider, profile, jurisdiction,
capability, origin, or mapping context raises
`DiscoveryClientError(kind="selection_changed")`. A withdrawn record fails the
fresh selection. Both cases require explicit reselection and a new local
acceptance decision; renewal never switches to another service or Evidence
alternative automatically.

Relay follows the same boundary with `search_relay_services` and
`select_relay_service`. The selection retains both the semantic class and
operation family. Apply exact local Relay pins with `accept_selection`, pass
only `accepted.endpoint_url` to `registry_client.relay.RelayClient`, then use
native Relay metadata to choose the concrete resource and operation. Discovery
never invents route arguments.
