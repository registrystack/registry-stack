# registry-discovery-client-node

Thin napi-rs binding for the bounded Rust `registry-discovery-client` SDK.
It performs exact service search, Evidence Type resolution, and ambiguity-safe
selection. A returned selection is inert public metadata. The application must
apply its own trust policy before calling the selected Evidence or Relay
endpoint.

Starting with Registry Stack v0.23.0, install the exact client version that
matches the Discovery deployment:

```sh
npm install "@registrystack/discovery-client@<version>"
```

The root package selects the native package for Linux amd64 with glibc, Linux
arm64 with glibc, or macOS arm64. Linux packages require glibc rather than
musl, so Alpine Linux is not supported.

Published npm installations select a separately published native package for
macOS arm64, Linux arm64 glibc, or Linux x64 glibc. The root package contains
the JavaScript API only, so normal installs do not download an unused native
binary.

```js
const {
  DiscoveryClient,
  acceptSelection,
  renewUnchangedSelection,
  selectEvidenceAlternative,
  selectEvidenceService,
  validateSelectionStructure,
} = require('@registrystack/discovery-client');
const { EvidenceClient } = require('@registrystack/evidence-client');

// These exact pins are application configuration. They are not copied from
// Discovery metadata and do not define a Discovery-owned trust-store schema.
const expectedEvidence = Object.freeze({
  serviceKind: 'evidence',
  serviceId: 'urn:example:service:evidence',
  endpointUrl: 'https://evidence.example.invalid/',
  legalIssuerId: 'urn:example:issuer',
  technicalProviderId: 'urn:example:provider',
  conformsTo: ['urn:example:evidence-profile'],
  jurisdictions: ['urn:example:jurisdiction'],
  evidenceTypeIds: ['urn:example:evidence-type'],
  matchedCapability: {
    kind: 'evidence-type',
    id: 'urn:example:evidence-type',
  },
  evidenceResolution: {
    requirementId: 'urn:example:requirement',
    jurisdiction: 'urn:example:jurisdiction',
    mappingRevision: `sha256:${'1'.repeat(64)}`,
    evidenceTypeListId: 'urn:example:evidence-type-list',
    evidenceTypeIds: ['urn:example:evidence-type'],
    mappingId: 'urn:example:mapping',
    mappingAuthorityId: 'urn:example:mapping-authority',
  },
});

function sameOrderedStrings(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function acceptsExpectedEvidence(candidate) {
  const actualResolution = candidate.evidenceResolution;
  const expectedResolution = expectedEvidence.evidenceResolution;
  return candidate.serviceKind === expectedEvidence.serviceKind
    && candidate.serviceId === expectedEvidence.serviceId
    && candidate.endpointUrl === expectedEvidence.endpointUrl
    && candidate.legalIssuerId === expectedEvidence.legalIssuerId
    && candidate.technicalProviderId === expectedEvidence.technicalProviderId
    && sameOrderedStrings(candidate.conformsTo, expectedEvidence.conformsTo)
    && sameOrderedStrings(candidate.jurisdictions, expectedEvidence.jurisdictions)
    && sameOrderedStrings(candidate.evidenceTypeIds, expectedEvidence.evidenceTypeIds)
    && candidate.matchedCapability.kind === expectedEvidence.matchedCapability.kind
    && candidate.matchedCapability.id === expectedEvidence.matchedCapability.id
    && actualResolution !== undefined
    && actualResolution.requirementId === expectedResolution.requirementId
    && actualResolution.jurisdiction === expectedResolution.jurisdiction
    && actualResolution.mappingRevision === expectedResolution.mappingRevision
    && actualResolution.evidenceTypeListId === expectedResolution.evidenceTypeListId
    && sameOrderedStrings(actualResolution.evidenceTypeIds, expectedResolution.evidenceTypeIds)
    && actualResolution.mappingId === expectedResolution.mappingId
    && actualResolution.mappingAuthorityId === expectedResolution.mappingAuthorityId;
}

const client = new DiscoveryClient('https://discovery.example.invalid/');
const resolved = await client.resolveEvidenceTypes({
  requirementId: expectedEvidence.evidenceResolution.requirementId,
  jurisdiction: expectedEvidence.evidenceResolution.jurisdiction,
});
const context = selectEvidenceAlternative(
  resolved,
  expectedEvidence.evidenceResolution.evidenceTypeListId,
); // explicit choice; refuses an absent or duplicate alternative
for (const evidenceTypeId of context.evidenceTypeIds) {
  const services = await client.searchEvidenceServices({
    evidenceTypeId,
    serviceIds: [expectedEvidence.serviceId],
    ...(context.jurisdiction ? { jurisdiction: context.jurisdiction } : {}),
  });
  // The application explicitly chooses a record. Discovery defines no rank.
  const chosen = services.items.find(
    (item) => item.serviceId === expectedEvidence.serviceId,
  );
  if (!chosen) throw new Error('expected Evidence service is unavailable');
  const selection = selectEvidenceService(services, {
    recordId: chosen.recordId,
    evidenceTypeId,
    resolution: context,
  });

  // Structural validation checks closed shape and capability binding only.
  const structurallyValid = validateSelectionStructure(selection);
  const accepted = acceptSelection(structurallyValid, acceptsExpectedEvidence);

  // Create credentials and the native client only after local acceptance.
  const evidence = new EvidenceClient({
    baseUrl: accepted.endpointUrl,
    trustedJwks,
    revokedKeyIds,
    token,
  });
  const acceptedSelection = accepted.selection;
  if (!acceptedSelection.evidenceResolution) throw new Error('missing Evidence resolution');
  const prepared = evidence.prepare({
    ...localEvidencePolicy,
    requirement: acceptedSelection.evidenceResolution.requirementId,
    evidenceType: acceptedSelection.matchedCapability.id,
  });
  const verified = await evidence.requestAndVerify(prepared);
}
```

The sample pins a one-member Evidence alternative. An alternative may be an
AND-list; in that case, configure an expected policy for every
`context.evidenceTypeIds` member and perform the search, explicit choice,
acceptance, and native request for each member.
The context supplies the resolved `requirementId` and selected Evidence Type;
the native definition and local policy still supply purpose, audience,
issuer/provider identity, configuration revision, selectors, and expected
outputs.

Relay follows the same boundary with `searchRelayServices` and
`selectRelayService`. The selection retains both `semanticClassId` and
`operationFamilyId`. Its adopter callback should exact-pin `serviceKind`,
`serviceId`, `endpointUrl`, `operatorId`, `registryAuthorityId`, `conformsTo`,
`jurisdictions`, `matchedCapability`, and `relayCapabilityMatch`. Pass
`acceptSelection(selection, acceptsExpectedRelay).endpointUrl` to
`new RelayClient({ baseUrl, authorization })`, constructing `authorization`
only after acceptance. Use Relay's native metadata to choose the concrete
resource and operation. Discovery never invents Relay route arguments.

## Persisting and renewing a selection

Persist only the plain selection object. `AcceptedServiceSelection` is an
ephemeral handoff and must be recreated under current local policy before each
new native client or credential-bearing session. Loading a saved selection and
calling `validateSelectionStructure` proves only structural validity. It does
not prove that the catalog, mapping, endpoint, authority, or local policy is
current.

Online renewal means re-resolving the requirement, re-searching, explicitly
reselecting the record, checking that its trust-relevant semantics are
unchanged, and applying local acceptance again:

```js
async function renewEvidenceSelection(saved) {
  const previous = validateSelectionStructure(saved);
  if (!previous.evidenceResolution) throw new Error('missing Evidence resolution');

  const resolved = await client.resolveEvidenceTypes({
    requirementId: previous.evidenceResolution.requirementId,
    ...(previous.evidenceResolution.jurisdiction
      ? { jurisdiction: previous.evidenceResolution.jurisdiction }
      : {}),
  });
  const currentContext = selectEvidenceAlternative(
    resolved,
    previous.evidenceResolution.evidenceTypeListId,
  );
  const currentServices = await client.searchEvidenceServices({
    evidenceTypeId: previous.matchedCapability.id,
    serviceIds: [previous.serviceId],
    ...(currentContext.jurisdiction ? { jurisdiction: currentContext.jurisdiction } : {}),
  });
  const current = selectEvidenceService(currentServices, {
    recordId: previous.recordId,
    evidenceTypeId: previous.matchedCapability.id,
    resolution: currentContext,
  });

  // Refuses withdrawal or any trust-relevant semantic change. It never
  // silently chooses a replacement service or Evidence alternative.
  const renewed = renewUnchangedSelection(previous, current);
  return acceptSelection(renewed, acceptsExpectedEvidence);
}
```

An application may deliberately use a saved selection while offline, but it is
then only structurally valid and subject to the application's own maximum-age
and currentness policy. Never treat origin, endpoint, issuer, provider,
authority, or capability claims as trusted solely because Discovery returned
them.

This boundary preserves
[ADR-001](../../products/discovery/DECISIONS.md#adr-001-discovery-is-an-index-not-a-trust-or-invocation-layer):
Discovery remains an index and neither defines adopter trust policy nor proxies
native Evidence or Relay invocation.
