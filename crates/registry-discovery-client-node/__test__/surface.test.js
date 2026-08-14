'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const {
  DiscoveryClient,
  DiscoveryClientError,
  selectEvidenceAlternative,
  selectEvidenceService,
  selectRelayService,
  validateSelection,
} = require('../client');

const digest = `sha256:${'1'.repeat(64)}`;
const service = {
  recordId: 'record-a',
  bindingId: 'urn:example:binding:a',
  serviceId: 'urn:example:service:a',
  serviceKind: 'evidence',
  title: 'Evidence service',
  description: 'Issues minimum-disclosure evidence',
  endpointUrl: 'https://provider.example/evidence',
  publisherId: 'urn:example:publisher',
  jurisdictions: ['urn:example:jurisdiction'],
  conformsTo: ['urn:example:profile'],
  evidenceTypeIds: ['urn:example:evidence-type'],
  semanticClassIds: [],
  operationFamilyIds: [],
  originId: 'origin-a',
  originUrl: 'https://provider.example/catalog.jsonld',
  originContentDigest: digest,
  originFetchedAt: '2026-08-15T00:00:00Z',
};
const relayService = {
  ...service,
  bindingId: 'urn:example:binding:relay',
  serviceId: 'urn:example:service:relay',
  serviceKind: 'relay',
  registryAuthorityId: 'urn:example:registry-authority',
  evidenceTypeIds: [],
  semanticClassIds: ['urn:example:registered-business'],
  operationFamilyIds: ['urn:example:consultation-list'],
};

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
  assert.equal(validateSelection(selection).serviceKind, 'relay');
});

test('a supported large response remains selectable', () => {
  const identifiers = (name) => Array.from(
    { length: 128 },
    (_, index) => `urn:example:${name}:${String(index).padStart(3, '0')}`,
  );
  const items = Array.from({ length: 200 }, (_, index) => ({
    ...relayService,
    recordId: `record-${String(index).padStart(3, '0')}`,
    bindingId: `urn:example:binding:relay:${String(index).padStart(3, '0')}`,
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
