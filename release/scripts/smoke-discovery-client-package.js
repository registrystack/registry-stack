#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const discovery = require('@registrystack/discovery-client');

const {
  AcceptedServiceSelection,
  DiscoveryClient,
  DiscoveryClientError,
  acceptSelection,
  renewUnchangedSelection,
  selectExact,
  validateSelection,
  validateSelectionStructure,
} = discovery;

for (const name of [
  'AcceptedServiceSelection',
  'DiscoveryClient',
  'DiscoveryClientError',
  'acceptSelection',
  'renewUnchangedSelection',
  'selectExact',
  'validateSelection',
  'validateSelectionStructure',
]) {
  assert.strictEqual(typeof discovery[name], 'function', `the package must export ${name}`);
}

const digest = `sha256:${'1'.repeat(64)}`;
const nextDigest = `sha256:${'2'.repeat(64)}`;
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
    legalIssuerId: 'urn:example:legal-issuer',
    technicalProviderId: 'urn:example:technical-provider',
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

function plainJson(value) {
  return JSON.parse(JSON.stringify(value));
}

// The reserved host makes the smoke fail closed if construction regresses into
// unexpected network I/O. Exact selection itself remains local and inert.
const client = new DiscoveryClient('https://discovery.invalid/');
const selection = client.selectExact(response, request);
assert.strictEqual(selection.endpointUrl, response.items[0].endpointUrl);
assert.deepStrictEqual(selectExact(response, request).matchedCapability, request.matchedCapability);
assert.strictEqual(plainJson(selection).recordId, 'record-a');

const structurallyValid = validateSelectionStructure(selection);
assert.deepStrictEqual(
  validateSelection(selection),
  structurallyValid,
  'the legacy validation name must remain a structural compatibility alias',
);

let localAcceptanceCalls = 0;
const accepted = acceptSelection(structurallyValid, (candidate) => {
  localAcceptanceCalls += 1;
  return candidate.serviceKind === 'evidence'
    && candidate.serviceId === 'urn:example:service:a'
    && candidate.endpointUrl === 'https://provider.example/evidence'
    && candidate.legalIssuerId === 'urn:example:legal-issuer'
    && candidate.technicalProviderId === 'urn:example:technical-provider'
    && candidate.jurisdictions.length === 1
    && candidate.jurisdictions[0] === 'urn:example:jurisdiction'
    && candidate.conformsTo.length === 1
    && candidate.conformsTo[0] === 'urn:example:profile'
    && candidate.matchedCapability.kind === 'evidence-type'
    && candidate.matchedCapability.id === 'urn:example:evidence-type';
});
assert.ok(accepted instanceof AcceptedServiceSelection);
assert.strictEqual(accepted.endpointUrl, response.items[0].endpointUrl);
assert.deepStrictEqual(plainJson(accepted.selection), plainJson(structurallyValid));
assert.strictEqual(localAcceptanceCalls, 1);

const current = {
  ...selection,
  catalogRevision: nextDigest,
  originContentDigest: nextDigest,
  originFetchedAt: '2026-08-25T00:00:00Z',
};
assert.deepStrictEqual(
  plainJson(renewUnchangedSelection(selection, current)),
  plainJson(current),
  'fresh provenance may renew an otherwise unchanged selection',
);
assert.throws(
  () => renewUnchangedSelection(selection, {
    ...current,
    legalIssuerId: 'urn:example:legal-issuer:other',
  }),
  (error) => error instanceof DiscoveryClientError && error.kind === 'selection_changed',
  'trust-relevant changes must require explicit new acceptance',
);

assert.throws(
  () => new DiscoveryClient('http://discovery.invalid/'),
  (error) => error instanceof DiscoveryClientError && error.kind === 'configuration',
);

console.log('Node Discovery client package smoke passed');
