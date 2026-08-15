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
  selectEvidenceAlternative,
  selectEvidenceService,
  validateSelection,
} = require('@registrystack/discovery-client');
const { EvidenceClient } = require('@registrystack/evidence-client');

const client = new DiscoveryClient('https://discovery.example.invalid/');
const resolved = await client.resolveEvidenceTypes({
  requirementId: 'urn:example:requirement',
  jurisdiction: 'urn:example:jurisdiction',
});
const context = selectEvidenceAlternative(resolved); // refuses zero or many alternatives
for (const evidenceTypeId of context.evidenceTypeIds) {
  const services = await client.searchEvidenceServices({
    evidenceTypeId,
    ...(context.jurisdiction ? { jurisdiction: context.jurisdiction } : {}),
  });
  const chosen = await adopterChooseRecord(services.items); // no catalog ranking is implied
  const selection = selectEvidenceService(services, {
    recordId: chosen.recordId,
    evidenceTypeId,
    resolution: context,
  });

  const checked = validateSelection(selection); // use after loading a persisted selection
  appTrust.requireEvidence(checked); // local pins, never Discovery data
  const evidence = new EvidenceClient({
    baseUrl: checked.endpointUrl,
    trustedJwks,
    revokedKeyIds,
    token,
  });
  if (!checked.evidenceResolution) throw new Error('missing Evidence resolution');
  const prepared = evidence.prepare({
    ...localEvidencePolicy,
    requirement: checked.evidenceResolution.requirementId,
    evidenceType: checked.matchedCapability.id,
  });
  const verified = await evidence.requestAndVerify(prepared);
}
```

An Evidence alternative is an AND-list. The loop performs the search, explicit
choice, trust check, and native request for every `context.evidenceTypeIds`
member.
The context supplies the resolved `requirementId` and selected Evidence Type;
the native definition and local policy still supply purpose, audience,
issuer/provider identity, configuration revision, selectors, and expected
outputs.

Relay follows the same boundary with `searchRelayServices` and
`selectRelayService`. The selection retains both `semanticClassId` and
`operationFamilyId`; after `appTrust.requireRelay(selection)`, pass
`selection.endpointUrl` to `new RelayClient({ baseUrl, authorization })` and
use Relay's native metadata to choose the concrete resource and operation.
Discovery never invents Relay route arguments.

Persist the plain selection object if useful, then call `validateSelection`
after loading it. Never treat its origin, endpoint, issuer, or capability
claims as trusted solely because Discovery returned them.
