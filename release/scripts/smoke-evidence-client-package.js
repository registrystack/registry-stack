#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const { EvidenceClient, EvidenceClientError } = require('@registrystack/evidence-client');

const trustedJwks = {
  keys: [
    {
      kty: 'EC',
      crv: 'P-256',
      alg: 'ES256',
      kid: '_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo',
      x: '3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4',
      y: 'GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU',
    },
  ],
};
const spec = {
  responseFormat: 'signed-jws',
  requirement: 'urn:example:requirement:v1',
  purpose: 'example-purpose',
  audience: 'urn:example:audience',
  evidenceType: 'urn:example:evidence-type:v1',
  issuedBy: 'urn:example:issuer',
  providedBy: 'urn:example:provider',
  configurationRevision: `sha256:${'0'.repeat(64)}`,
  expectedAssuranceProfile: 'local',
  subjects: [{ role: 'subject', selectorProfile: 'national-id' }],
  expectedOutputs: [{ concept: 'urn:example:concept:status-holds', form: 'boolean' }],
  maximumAssertionLifetimeSeconds: 300,
  clockSkewSeconds: 60,
  subjectExpectations: 'acceptFirstUse',
};

// This reserved host and placeholder token make the smoke fail closed if a
// regression unexpectedly attempts network I/O.
const client = new EvidenceClient({
  baseUrl: 'https://evidence.invalid',
  trustedJwks,
  revokedKeyIds: [],
  token: { static: 'placeholder-not-a-credential' },
});
const prepared = client.prepare(spec);
assert.strictEqual(prepared.requestNonce.length, 43);
assert.strictEqual(prepared.policyDocument.audience, spec.audience);
assert.throws(
  () => client.prepare({ ...spec, configurationRevision: '' }),
  (error) => error instanceof EvidenceClientError && error.kind === 'configuration',
);

console.log('Node client package smoke passed');
