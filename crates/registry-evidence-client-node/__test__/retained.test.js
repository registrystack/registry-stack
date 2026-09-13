'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const { EvidenceClientError, verifyRetained, verifyRetainedAsOf } = require('..');

function fixture(name) {
  return fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', name));
}

function context() {
  return Buffer.from(JSON.stringify({
    schema: 'registry.evidence-client.retained-verification/v1',
    responseFormat: 'signed-jws',
    trustedJwks: JSON.parse(fixture('jwks.json')),
    verificationPolicy: JSON.parse(fixture('policy.json')),
    subjectExpectation: { mode: 'pinned' },
  }));
}

test('retained bytes verify offline as of the recorded decision and expire for a current decision', () => {
  const retained = context();
  const response = fixture('response.jws.json');
  const verified = verifyRetainedAsOf(retained, response, Date.parse('2026-08-05T00:00:00Z'));
  assert.equal(verified.evidence.requestNonce, 'A'.repeat(43));
  assert.throws(() => verifyRetained(retained, response), (error) => {
    assert.ok(error instanceof EvidenceClientError);
    assert.equal(error.kind, 'verification');
    return true;
  });
});

test('invalid retained context and altered response fail closed', () => {
  const response = fixture('response.jws.json');
  const wrongSchema = JSON.parse(context());
  wrongSchema.schema = 'registry.example/unknown';
  assert.throws(() => verifyRetainedAsOf(
    Buffer.from(JSON.stringify(wrongSchema)), response, Date.parse('2026-08-05T00:00:00Z'),
  ), (error) => error instanceof EvidenceClientError && error.kind === 'configuration');
  assert.throws(() => verifyRetainedAsOf(
    context(), Buffer.from('changed'), Date.parse('2026-08-05T00:00:00Z'),
  ), (error) => error instanceof EvidenceClientError && error.kind === 'verification');
});
