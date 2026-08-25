'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const test = require('node:test');
const {
  AcceptedServiceSelection,
  DiscoveryClient,
  DiscoveryClientError,
  acceptSelection,
  renewUnchangedSelection,
  selectEvidenceAlternative,
  selectEvidenceService,
  selectRelayService,
  validateSelection,
  validateSelectionStructure,
} = require('../client');

function withDerivedBindingId(value) {
  const identity = {
    conformsTo: value.conformsTo,
    endpointUrl: value.endpointUrl,
    evidenceTypeIds: value.evidenceTypeIds,
    operationFamilyIds: value.operationFamilyIds,
    semanticClassIds: value.semanticClassIds,
    serviceId: value.serviceId,
    serviceKind: value.serviceKind,
  };
  const digest = crypto.createHash('sha256').update(JSON.stringify(identity)).digest('hex');
  return {
    ...value,
    bindingId: `urn:registrystack:discovery:binding:sha256:${digest}`,
  };
}

function withoutEvidenceContext(value) {
  const { evidenceResolution: _resolution, mappingRevision: _mapping, ...remaining } = value;
  return remaining;
}

const digest = `sha256:${'1'.repeat(64)}`;
const service = withDerivedBindingId({
  recordId: 'record-a',
  serviceId: 'urn:example:service:a',
  serviceKind: 'evidence',
  title: 'Evidence service',
  description: 'Issues minimum-disclosure evidence',
  endpointUrl: 'https://provider.example/evidence',
  publisherId: 'urn:example:publisher',
  legalIssuerId: 'urn:example:issuer',
  technicalProviderId: 'urn:example:provider',
  jurisdictions: ['urn:example:jurisdiction'],
  conformsTo: ['urn:example:profile'],
  evidenceTypeIds: ['urn:example:evidence-type'],
  semanticClassIds: [],
  operationFamilyIds: [],
  originId: 'origin-a',
  originUrl: 'https://provider.example/catalog.jsonld',
  originContentDigest: digest,
  originFetchedAt: '2026-08-15T00:00:00Z',
});
const relayService = withDerivedBindingId({
  ...service,
  serviceId: 'urn:example:service:relay',
  serviceKind: 'relay',
  registryAuthorityId: 'urn:example:registry-authority',
  evidenceTypeIds: [],
  semanticClassIds: ['urn:example:registered-business'],
  operationFamilyIds: ['urn:example:consultation-list'],
});

const expectedEvidence = Object.freeze({
  serviceKind: 'evidence',
  serviceId: 'urn:example:service:a',
  endpointUrl: 'https://provider.example/evidence',
  legalIssuerId: 'urn:example:issuer',
  technicalProviderId: 'urn:example:provider',
  jurisdictions: ['urn:example:jurisdiction'],
  conformsTo: ['urn:example:profile'],
  evidenceTypeIds: ['urn:example:evidence-type'],
  matchedCapability: { kind: 'evidence-type', id: 'urn:example:evidence-type' },
  evidenceResolution: {
    requirementId: 'urn:example:requirement',
    mappingRevision: digest,
    evidenceTypeListId: 'urn:example:list',
    evidenceTypeIds: ['urn:example:evidence-type'],
    mappingId: 'urn:example:mapping',
    mappingAuthorityId: 'urn:example:mapping-authority',
  },
});

function evidenceTrustProjection(candidate) {
  return {
    serviceKind: candidate.serviceKind,
    serviceId: candidate.serviceId,
    endpointUrl: candidate.endpointUrl,
    legalIssuerId: candidate.legalIssuerId,
    technicalProviderId: candidate.technicalProviderId,
    jurisdictions: candidate.jurisdictions,
    conformsTo: candidate.conformsTo,
    evidenceTypeIds: candidate.evidenceTypeIds,
    matchedCapability: candidate.matchedCapability,
    evidenceResolution: candidate.evidenceResolution,
  };
}

function acceptsExpectedEvidence(candidate) {
  const resolution = candidate.evidenceResolution;
  const expectedResolution = expectedEvidence.evidenceResolution;
  return resolution !== undefined
    && candidate.serviceKind === expectedEvidence.serviceKind
    && candidate.serviceId === expectedEvidence.serviceId
    && candidate.endpointUrl === expectedEvidence.endpointUrl
    && candidate.legalIssuerId === expectedEvidence.legalIssuerId
    && candidate.technicalProviderId === expectedEvidence.technicalProviderId
    && candidate.jurisdictions.length === expectedEvidence.jurisdictions.length
    && candidate.jurisdictions.every((value, index) => (
      value === expectedEvidence.jurisdictions[index]
    ))
    && candidate.conformsTo.length === expectedEvidence.conformsTo.length
    && candidate.conformsTo.every((value, index) => value === expectedEvidence.conformsTo[index])
    && candidate.evidenceTypeIds.length === expectedEvidence.evidenceTypeIds.length
    && candidate.evidenceTypeIds.every((value, index) => (
      value === expectedEvidence.evidenceTypeIds[index]
    ))
    && candidate.matchedCapability.kind === expectedEvidence.matchedCapability.kind
    && candidate.matchedCapability.id === expectedEvidence.matchedCapability.id
    && resolution.requirementId === expectedResolution.requirementId
    && resolution.mappingRevision === expectedResolution.mappingRevision
    && resolution.evidenceTypeListId === expectedResolution.evidenceTypeListId
    && resolution.evidenceTypeIds.length === expectedResolution.evidenceTypeIds.length
    && resolution.evidenceTypeIds.every((value, index) => (
      value === expectedResolution.evidenceTypeIds[index]
    ))
    && resolution.mappingId === expectedResolution.mappingId
    && resolution.mappingAuthorityId === expectedResolution.mappingAuthorityId;
}

test('search, resolve, and inert exact selection use the Rust client', async () => {
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    if (request.method === 'GET' && request.url.startsWith('/v1/services')) {
      response.end(JSON.stringify({ catalogRevision: digest, items: [service] }));
      return;
    }
    if (request.method === 'POST' && request.url === '/v1/evidence-types/resolve') {
      response.end(JSON.stringify({
        requirementId: 'urn:example:requirement',
        mappingRevision: digest,
        alternatives: [{
          evidenceTypeListId: 'urn:example:list',
          evidenceTypeIds: ['urn:example:evidence-type'],
          mappingId: 'urn:example:mapping',
          mappingAuthorityId: 'urn:example:mapping-authority',
        }],
      }));
      return;
    }
    response.statusCode = 404;
    response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const client = new DiscoveryClient(`http://127.0.0.1:${address.port}/`);

  const found = await client.searchEvidenceServices({
    evidenceTypeId: 'urn:example:evidence-type',
  });
  const resolved = await client.resolveEvidenceTypes({
    requirementId: 'urn:example:requirement',
  });
  const resolution = selectEvidenceAlternative(resolved);
  const selection = client.selectEvidenceService(found, {
    recordId: 'record-a',
    evidenceTypeId: 'urn:example:evidence-type',
    resolution,
  });
  assert.equal(selection.endpointUrl, service.endpointUrl);
  assert.equal(selection.originContentDigest, digest);
  assert.equal(selection.evidenceResolution.requirementId, 'urn:example:requirement');
  assert.deepEqual(
    selectEvidenceService(found, {
      recordId: 'record-a',
      evidenceTypeId: 'urn:example:evidence-type',
      resolution,
    }).matchedCapability,
    { kind: 'evidence-type', id: 'urn:example:evidence-type' },
  );
  assert.equal(validateSelectionStructure(selection).recordId, 'record-a');
  assert.equal(validateSelection(selection).recordId, 'record-a');

  await new Promise((resolve) => server.close(resolve));
  assert.equal(JSON.parse(JSON.stringify(selection)).recordId, 'record-a');
});

test('Relay selection retains the correlated semantic and operation match', () => {
  const selection = selectRelayService(
    { catalogRevision: digest, items: [relayService] },
    {
      recordId: relayService.recordId,
      capabilityMatch: {
        semanticClassId: 'urn:example:registered-business',
        operationFamilyId: 'urn:example:consultation-list',
      },
    },
  );
  assert.deepEqual(selection.relayCapabilityMatch, {
    semanticClassId: 'urn:example:registered-business',
    operationFamilyId: 'urn:example:consultation-list',
  });
  assert.equal(validateSelectionStructure(selection).serviceKind, 'relay');
});

test('adopter acceptance is explicit and precedes credentials or native traffic', () => {
  const resolution = { ...expectedEvidence.evidenceResolution };
  const selection = selectEvidenceService(
    { catalogRevision: digest, items: [service] },
    {
      recordId: service.recordId,
      evidenceTypeId: 'urn:example:evidence-type',
      resolution,
    },
  );
  assert.deepEqual(evidenceTrustProjection(selection), expectedEvidence);
  let tokenConstructions = 0;
  let nativeCalls = 0;
  const invoke = (candidate) => {
    const accepted = acceptSelection(candidate, acceptsExpectedEvidence);
    tokenConstructions += 1;
    nativeCalls += 1;
    return accepted;
  };

  const mutations = [
    (value) => withDerivedBindingId({ ...value, serviceId: 'urn:example:service:other' }),
    (value) => withDerivedBindingId({
      ...value,
      endpointUrl: 'https://other.example/evidence',
    }),
    (value) => ({ ...value, legalIssuerId: 'urn:example:issuer:other' }),
    (value) => withDerivedBindingId({ ...value, conformsTo: ['urn:example:profile:other'] }),
    (value) => ({ ...value, jurisdictions: ['urn:example:jurisdiction:other'] }),
    (value) => ({
      ...value,
      evidenceResolution: {
        ...value.evidenceResolution,
        mappingAuthorityId: 'urn:example:mapping-authority:other',
      },
    }),
    (value) => withoutEvidenceContext(value),
    (value) => withDerivedBindingId({
      ...value,
      evidenceTypeIds: ['urn:example:evidence-type:other'],
      matchedCapability: { kind: 'evidence-type', id: 'urn:example:evidence-type:other' },
      evidenceResolution: {
        ...value.evidenceResolution,
        evidenceTypeIds: ['urn:example:evidence-type:other'],
      },
    }),
  ];
  for (const mutate of mutations) {
    const changed = mutate(selection);
    validateSelectionStructure(changed);
    assert.throws(
      () => invoke(changed),
      (error) => error instanceof DiscoveryClientError
        && error.kind === 'local_acceptance_refused',
    );
  }
  assert.equal(tokenConstructions, 0);
  assert.equal(nativeCalls, 0);

  const accepted = invoke(selection);
  assert.ok(accepted instanceof AcceptedServiceSelection);
  assert.equal(accepted.endpointUrl, expectedEvidence.endpointUrl);
  assert.equal(accepted.selection.recordId, selection.recordId);
  assert.equal(tokenConstructions, 1);
  assert.equal(nativeCalls, 1);
});

test('renewal refreshes provenance but never silently accepts semantic drift', () => {
  const selection = selectEvidenceService(
    { catalogRevision: digest, items: [service] },
    {
      recordId: service.recordId,
      evidenceTypeId: 'urn:example:evidence-type',
      resolution: expectedEvidence.evidenceResolution,
    },
  );
  const refreshedDigest = `sha256:${'2'.repeat(64)}`;
  const current = {
    ...selection,
    originContentDigest: refreshedDigest,
    originFetchedAt: '2026-08-20T00:00:00Z',
    catalogRevision: refreshedDigest,
  };
  assert.equal(
    renewUnchangedSelection(selection, current).originFetchedAt,
    '2026-08-20T00:00:00Z',
  );

  let tokenConstructions = 0;
  let nativeCalls = 0;
  const continueAfterRenewal = (previous, candidate) => {
    const renewed = renewUnchangedSelection(previous, candidate);
    tokenConstructions += 1;
    nativeCalls += 1;
    return renewed;
  };

  const changes = [
    { ...current, registryAuthorityId: 'urn:example:authority:other' },
    { ...current, jurisdictions: ['urn:example:jurisdiction:other'] },
    withDerivedBindingId({
      ...current,
      endpointUrl: 'https://other.example/evidence',
    }),
    withDerivedBindingId({
      ...current,
      conformsTo: ['urn:example:profile:other'],
    }),
    withDerivedBindingId({
      ...current,
      evidenceTypeIds: ['urn:example:evidence-type:other'],
      matchedCapability: { kind: 'evidence-type', id: 'urn:example:evidence-type:other' },
      evidenceResolution: {
        ...current.evidenceResolution,
        evidenceTypeIds: ['urn:example:evidence-type:other'],
      },
    }),
    {
      ...current,
      mappingRevision: refreshedDigest,
      evidenceResolution: {
        ...current.evidenceResolution,
        mappingRevision: refreshedDigest,
      },
    },
    withoutEvidenceContext(current),
  ];
  for (const changed of changes) {
    assert.throws(
      () => continueAfterRenewal(selection, changed),
      (error) => error instanceof DiscoveryClientError && error.kind === 'selection_changed',
    );
  }

  const relayWithTwoOperations = withDerivedBindingId({
    ...relayService,
    operationFamilyIds: [
      'urn:example:consultation-list',
      'urn:example:consultation-search',
    ],
  });
  const relayPrevious = selectRelayService(
    { catalogRevision: digest, items: [relayWithTwoOperations] },
    {
      recordId: relayWithTwoOperations.recordId,
      capabilityMatch: {
        semanticClassId: 'urn:example:registered-business',
        operationFamilyId: 'urn:example:consultation-list',
      },
    },
  );
  const relayCurrent = selectRelayService(
    { catalogRevision: refreshedDigest, items: [relayWithTwoOperations] },
    {
      recordId: relayWithTwoOperations.recordId,
      capabilityMatch: {
        semanticClassId: 'urn:example:registered-business',
        operationFamilyId: 'urn:example:consultation-search',
      },
    },
  );
  assert.throws(
    () => continueAfterRenewal(relayPrevious, relayCurrent),
    (error) => error instanceof DiscoveryClientError && error.kind === 'selection_changed',
  );
  assert.throws(
    () => {
      const reselected = selectEvidenceService(
        { catalogRevision: refreshedDigest, items: [] },
        { recordId: selection.recordId, evidenceTypeId: 'urn:example:evidence-type' },
      );
      tokenConstructions += 1;
      nativeCalls += 1;
      return reselected;
    },
    (error) => error instanceof DiscoveryClientError && error.kind === 'no_matching_service',
  );
  assert.equal(tokenConstructions, 0);
  assert.equal(nativeCalls, 0);
});

test('a supported large response remains selectable', () => {
  const identifiers = (name) => Array.from(
    { length: 128 },
    (_, index) => `urn:example:${name}:${String(index).padStart(3, '0')}`,
  );
  const items = Array.from({ length: 200 }, (_, index) => withDerivedBindingId({
    ...relayService,
    recordId: `record-${String(index).padStart(3, '0')}`,
    serviceId: `urn:example:service:relay:${String(index).padStart(3, '0')}`,
    jurisdictions: identifiers('jurisdiction'),
    conformsTo: identifiers('profile'),
    semanticClassIds: [
      'urn:example:registered-business',
      ...identifiers('semantic').slice(0, 127),
    ],
    operationFamilyIds: [
      'urn:example:consultation-list',
      ...identifiers('operation').slice(0, 127),
    ],
  }));
  assert.ok(JSON.stringify(items).length < 16 * 1024 * 1024);

  const selection = selectRelayService(
    { catalogRevision: digest, items },
    {
      recordId: 'record-000',
      capabilityMatch: {
        semanticClassId: 'urn:example:registered-business',
        operationFamilyId: 'urn:example:consultation-list',
      },
    },
  );
  assert.equal(selection.recordId, 'record-000');
});

test('binding failures expose a stable value-free kind', () => {
  assert.throws(
    () => new DiscoveryClient('http://provider.example.invalid/'),
    (error) => error instanceof DiscoveryClientError && error.kind === 'configuration',
  );

  const cyclic = {};
  cyclic.self = cyclic;
  const client = new DiscoveryClient('https://discovery.example.invalid/');
  assert.throws(
    () => client.selectExact(cyclic, {}),
    (error) => error instanceof DiscoveryClientError && error.kind === 'query',
  );
});

test('object keys count against the bounded JSON bridge', () => {
  const oversizedKey = 'x'.repeat((16 * 1024 * 1024) + 1);
  assert.throws(
    () => validateSelectionStructure({ [oversizedKey]: null }),
    (error) => error instanceof DiscoveryClientError && error.kind === 'query',
  );
});
