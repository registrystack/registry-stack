#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const { DiscoveryClient, DiscoveryClientError, selectExact } = require('@registrystack/discovery-client');

const digest = `sha256:${'1'.repeat(64)}`;
const response = {
  catalogRevision: digest,
  items: [{
    recordId: 'record-a',
    bindingId: 'urn:registrystack:discovery:binding:sha256:3a316636cd4b722c008a02dcf61633c7be64aa85bc9d3c20d932a0a2e8e06129',
    serviceId: 'urn:example:service:a',
    serviceKind: 'evidence',
    title: 'Evidence service',
    description: 'Issues minimum-disclosure evidence',
    endpointUrl: 'https://provider.example/evidence',
    jurisdictions: ['urn:example:jurisdiction'],
    conformsTo: ['urn:example:profile'],
    evidenceTypeIds: ['urn:example:evidence-type'],
    semanticClassIds: [],
    operationFamilyIds: [],
    originId: 'origin-a',
    originUrl: 'https://provider.example/catalog.jsonld',
    originContentDigest: digest,
    originFetchedAt: '2026-08-15T00:00:00Z',
  }],
};
const request = {
  recordId: 'record-a',
  matchedCapability: { kind: 'evidence-type', id: 'urn:example:evidence-type' },
};

// The reserved host makes the smoke fail closed if construction regresses into
// unexpected network I/O. Exact selection itself remains local and inert.
const client = new DiscoveryClient('https://discovery.invalid/');
const selection = client.selectExact(response, request);
assert.strictEqual(selection.endpointUrl, response.items[0].endpointUrl);
assert.deepStrictEqual(selectExact(response, request).matchedCapability, request.matchedCapability);
assert.strictEqual(JSON.parse(JSON.stringify(selection)).recordId, 'record-a');
assert.throws(
  () => new DiscoveryClient('http://discovery.invalid/'),
  (error) => error instanceof DiscoveryClientError && error.kind === 'configuration',
);

console.log('Node Discovery client package smoke passed');
