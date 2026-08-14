# registry-discovery-client-py

Synchronous PyO3 binding for the bounded Rust `registry-discovery-client` SDK.
It performs exact service search, Evidence Type resolution, and ambiguity-safe
selection. A returned selection is inert public metadata. Apply local trust
policy before calling its Evidence or Relay endpoint.

Starting with Registry Stack v0.23.0, install the exact client version that
matches the Discovery deployment:

```sh
python -m pip install "registry-discovery-client==<version>"
```

Published v0.23.0 and later distributions carry manylinux wheels requiring
glibc 2.17 or newer for Linux amd64 and Linux arm64, plus a macOS arm64 wheel.

The public methods accept only ordinary built-in JSON values: `None`, `bool`,
signed 64-bit `int`, finite `float`, `str`, `list`, and `dict` with string keys.
They reject custom objects, subclasses, tuples, cycles, and oversized values
before sending a request. Invalid configuration always raises
`DiscoveryClientError(kind="configuration")`; invalid request or selection
values raise `DiscoveryClientError(kind="query")`. Error messages never echo
caller values.

```python
from registry_discovery_client import (
    DiscoveryClient,
    select_evidence_alternative,
    select_evidence_service,
    validate_selection,
)
from registry_evidence_client import EvidenceClient

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
    chosen = adopter_choose_record(services["items"])  # no catalog ranking
    selection = select_evidence_service(services, {
        "recordId": chosen["recordId"],
        "evidenceTypeId": evidence_type_id,
        "resolution": context,
    })

    checked = validate_selection(selection)  # use after loading persisted data
    app_trust.require_evidence(checked)  # local pins, never Discovery data
    evidence = EvidenceClient(
        checked["endpointUrl"],
        trusted_jwks,
        revoked_key_ids,
        token,
    )
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

Relay follows the same boundary with `search_relay_services` and
`select_relay_service`. The selection retains both the semantic class and
operation family. After local trust accepts it, pass `selection["endpointUrl"]`
to `registry_relay_client.RelayClient`, then use native Relay metadata to choose
the concrete resource and operation. Discovery never invents route arguments.
