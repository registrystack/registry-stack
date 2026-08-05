'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const { EvidenceClient } = require('..');
const { startStubServer } = require('./helpers/stub-server');

// The golden fixture's key set is public verification material only (no
// private key), so it is safe to reuse here for `fetchJwks`, which never
// needs to sign anything.
const GOLDEN_JWKS = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', 'jwks.json'), 'utf8'),
);

const DEFINITIONS_DOCUMENT = {
  schema: 'registry.evidence-definitions/v1',
  assuranceProfile: 'local',
  configurationRevision: `sha256:${'0'.repeat(64)}`,
  issuedBy: 'urn:example:node-test:issuer',
  providedBy: 'urn:example:node-test:provider',
  definitions: [
    {
      requirement: 'urn:example:node-test:requirement:status:v1',
      kind: 'criterion',
      evidenceType: 'urn:example:node-test:evidence-type:status:v1',
      purpose: 'example-decision',
      referenceFrameworks: ['urn:example:node-test:framework:status:v1'],
      subjects: [
        {
          role: 'subject',
          cardinality: 'one',
          selector: {
            profile: 'record-lookup-v1',
            valueOrigin: 'request',
            fields: [{ type: 'string', name: 'record_reference', minimumBytes: 1, maximumBytes: 200 }],
          },
        },
      ],
      concepts: [{ id: 'urn:example:node-test:concept:status-holds', form: 'boolean' }],
    },
  ],
};

function clientAgainst(stub) {
  return new EvidenceClient({
    baseUrl: stub.baseUrl,
    trustedJwks: GOLDEN_JWKS,
    token: { static: 'discovery-test-token' },
  });
}

test('discover reads a valid definitions document from a stub deployment', async () => {
  const stub = await startStubServer({
    'GET /v1/evidence-definitions': (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(DEFINITIONS_DOCUMENT));
    },
  });
  try {
    const client = clientAgainst(stub);
    const document = await client.discover();
    assert.equal(document.schema, 'registry.evidence-definitions/v1');
    assert.equal(document.definitions.length, 1);
    assert.equal(document.definitions[0].requirement, 'urn:example:node-test:requirement:status:v1');
    assert.equal(stub.requests.length, 1);
  } finally {
    await stub.close();
  }
});

test('fetchJwks reads the deployment key set from a stub deployment', async () => {
  const stub = await startStubServer({
    'GET /.well-known/evidence/jwks.json': (req, res) => {
      res.writeHead(200, { 'content-type': 'application/jwk-set+json' });
      res.end(JSON.stringify(GOLDEN_JWKS));
    },
  });
  try {
    const client = clientAgainst(stub);
    const jwks = await client.fetchJwks();
    assert.deepEqual(jwks, GOLDEN_JWKS);
    assert.equal(stub.requests.length, 1);
  } finally {
    await stub.close();
  }
});
