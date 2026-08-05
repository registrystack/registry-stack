'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { EvidenceClient, EvidenceClientError, PreparedEvidenceRequest } = require('..');
// The raw native module, used only to prove the package's exported
// `PreparedEvidenceRequest` is the very same native class (see the identity
// assertion below), not a wrapper or a copy of it.
const native = require('../index.js');
const { startStubServer } = require('./helpers/stub-server');
const {
  generateSigningKey,
  signEvidence,
  requestSpec,
  evidenceFor,
  SUBJECT_BINDING,
} = require('./helpers/live-signing');

/** A stub that signs a fresh, currently valid Evidence answer for whatever
 * nonce the live request actually carried. The golden fixture's fixed nonce
 * cannot serve this: `prepare()` generates a new one on every call, and there
 * is no seam to inject the fixture's nonce into it. */
function evidenceRoute(spec, signingKey) {
  return (req, res, body) => {
    const requestBody = JSON.parse(body.toString('utf8'));
    const evidence = evidenceFor(spec, requestBody.requestNonce);
    const jws = signEvidence(evidence, signingKey);
    res.writeHead(200, { 'content-type': 'application/jose+json' });
    res.end(JSON.stringify(jws));
  };
}

test('a prepared request round-trips through send and verify against a live stub', async () => {
  const signingKey = generateSigningKey('happy-path-key');
  const spec = requestSpec();
  const stub = await startStubServer({ 'POST /v1/evidence': evidenceRoute(spec, signingKey) });

  try {
    const client = new EvidenceClient({
      baseUrl: stub.baseUrl,
      trustedJwks: signingKey.jwks,
      token: { static: 'happy-path-token' },
    });

    const prepared = client.prepare(spec);
    const response = await client.send(prepared);
    const verified = client.verify(prepared, response);

    assert.equal(verified.evidence.requestNonce, prepared.requestNonce);
    assert.deepEqual(verified.pinnedSubjectExpectations, [
      { role: 'subject', binding: SUBJECT_BINDING },
    ]);
    assert.equal(stub.requests.length, 1);
    assert.equal(stub.requests[0].headers.authorization, 'Bearer happy-path-token');
  } finally {
    await stub.close();
  }
});

test('requestAndVerify performs the same round trip in one call', async () => {
  const signingKey = generateSigningKey('happy-path-key-2');
  const spec = requestSpec();
  const stub = await startStubServer({ 'POST /v1/evidence': evidenceRoute(spec, signingKey) });

  try {
    const client = new EvidenceClient({
      baseUrl: stub.baseUrl,
      trustedJwks: signingKey.jwks,
      token: { static: 'happy-path-token' },
    });

    const prepared = client.prepare(spec);
    const verified = await client.requestAndVerify(prepared);

    assert.equal(verified.evidence.requestNonce, prepared.requestNonce);
    assert.deepEqual(verified.pinnedSubjectExpectations, [
      { role: 'subject', binding: SUBJECT_BINDING },
    ]);
    assert.equal(stub.requests.length, 1);
  } finally {
    await stub.close();
  }
});

test('a second send on the same prepared request is refused locally, and the stub sees only one request', async () => {
  const signingKey = generateSigningKey('one-send-guard-key');
  const spec = requestSpec();
  const stub = await startStubServer({ 'POST /v1/evidence': evidenceRoute(spec, signingKey) });

  try {
    const client = new EvidenceClient({
      baseUrl: stub.baseUrl,
      trustedJwks: signingKey.jwks,
      token: { static: 'one-send-guard-token' },
    });

    const prepared = client.prepare(spec);
    // The wrapper module patches `EvidenceClient.prototype` methods in place
    // rather than wrapping arguments or return values, so `prepare()` must
    // still hand back the exact native object: the single-send guard below
    // depends on `send` recognizing the very same `PreparedEvidenceRequest`
    // on its second call, not a copy or a proxy around it.
    assert.ok(prepared instanceof PreparedEvidenceRequest);
    assert.ok(prepared instanceof native.PreparedEvidenceRequest);
    assert.equal(PreparedEvidenceRequest, native.PreparedEvidenceRequest);

    await client.send(prepared);
    assert.equal(stub.requests.length, 1);

    await assert.rejects(client.send(prepared), (error) => {
      assert.ok(error instanceof EvidenceClientError);
      assert.equal(error.kind, 'configuration');
      return true;
    });
    assert.equal(stub.requests.length, 1, 'the stub must not see a second request');
  } finally {
    await stub.close();
  }
});
