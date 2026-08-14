'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const { DiscoveryClient, DiscoveryClientError, selectExact } = require('../client');

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

  const found = await client.searchServices({
    serviceKind: ['evidence'],
    evidenceType: ['urn:example:evidence-type'],
  });
  const resolved = await client.resolveEvidenceTypes({
    requirementId: 'urn:example:requirement',
  });
  const selection = client.selectExact(found, {
    recordId: 'record-a',
    matchedCapability: { kind: 'evidence-type', id: 'urn:example:evidence-type' },
    mappingRevision: resolved.mappingRevision,
  });
  assert.equal(selection.endpointUrl, service.endpointUrl);
  assert.equal(selection.originContentDigest, digest);
  assert.deepEqual(selectExact(found, {
    recordId: 'record-a',
    matchedCapability: { kind: 'evidence-type', id: 'urn:example:evidence-type' },
  }).matchedCapability, { kind: 'evidence-type', id: 'urn:example:evidence-type' });

  await new Promise((resolve) => server.close(resolve));
  assert.equal(JSON.parse(JSON.stringify(selection)).recordId, 'record-a');
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
