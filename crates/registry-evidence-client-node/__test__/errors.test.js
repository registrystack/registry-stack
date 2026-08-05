'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { EvidenceClient, EvidenceClientError } = require('..');
const { startStubServer } = require('./helpers/stub-server');
const { generateSigningKey, signEvidence, requestSpec, evidenceFor } = require('./helpers/live-signing');

const DUMMY_JWKS = {
  keys: [
    {
      kty: 'OKP',
      crv: 'Ed25519',
      kid: 'errors-test-key',
      x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
  ],
};

/** None of these cases reach signature verification: the client maps them to
 * a failure before the response body is ever trusted, so the stub never
 * needs to sign anything real. */
async function clientAndPrepared(stub) {
  const client = new EvidenceClient({
    baseUrl: stub.baseUrl,
    trustedJwks: DUMMY_JWKS,
    token: { static: 'errors-test-token' },
  });
  return { client, prepared: client.prepare(requestSpec()) };
}

function problemBody(status, code, operation) {
  return JSON.stringify({
    type: 'https://registrystack.org/problems/example',
    title: 'Example problem',
    status,
    code,
    operation,
  });
}

async function assertMappedFailure(stub, assertMapping) {
  try {
    const { client, prepared } = await clientAndPrepared(stub);
    await assert.rejects(client.send(prepared), (error) => {
      assert.ok(error instanceof EvidenceClientError);
      assertMapping(error);
      return true;
    });
  } finally {
    await stub.close();
  }
}

test('401 with any code maps to a denied failure', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(401, { 'content-type': 'application/problem+json', 'x-request-id': 'op401test' });
      res.end(problemBody(401, 'authentication_failed', 'op401test'));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'denied');
    assert.equal(mapped.status, 401);
    assert.equal(mapped.code, 'authentication_failed');
    assert.equal(mapped.operation, 'op401test');
    assert.equal(mapped.retryAfterSeconds, undefined);
  });
});

test('403 with any code maps to a denied failure', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(403, { 'content-type': 'application/problem+json', 'x-request-id': 'op403test' });
      res.end(problemBody(403, 'not_authorized', 'op403test'));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'denied');
    assert.equal(mapped.status, 403);
    assert.equal(mapped.code, 'not_authorized');
    assert.equal(mapped.operation, 'op403test');
    assert.equal(mapped.retryAfterSeconds, undefined);
  });
});

test('429 with a Retry-After header maps to a denied failure carrying the wait', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(429, {
        'content-type': 'application/problem+json',
        'x-request-id': 'op429test',
        'retry-after': '30',
      });
      res.end(problemBody(429, 'rate_limited', 'op429test'));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'denied');
    assert.equal(mapped.status, 429);
    assert.equal(mapped.code, 'rate_limited');
    assert.equal(mapped.operation, 'op429test');
    assert.equal(mapped.retryAfterSeconds, 30);
  });
});

test('422 with the not-available code maps to its own failure, with no status field', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(422, {
        'content-type': 'application/problem+json',
        'x-request-id': 'op422test',
      });
      res.end(problemBody(422, 'evidence_not_available', 'op422test'));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'not_available');
    assert.equal(mapped.status, undefined);
    assert.equal(mapped.operation, 'op422test');
  });
});

test('400 with an ordinary contract code maps to a protocol failure', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(400, {
        'content-type': 'application/problem+json',
        'x-request-id': 'op400test',
      });
      res.end(problemBody(400, 'malformed_request', 'op400test'));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'protocol');
    assert.equal(mapped.status, 400);
    assert.equal(mapped.code, 'malformed_request');
    assert.equal(mapped.operation, 'op400test');
    assert.equal(mapped.retryAfterSeconds, undefined);
  });
});

test('a 200 response under the wrong media type is refused as a protocol failure', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'protocol');
    assert.equal(mapped.status, 200);
    assert.equal(mapped.code, undefined);
  });
});

test('a response over maxResponseBytes is refused as a transport failure, not a protocol failure', async () => {
  const oversized = Buffer.alloc(4096, 'a');
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(200, {
        'content-type': 'application/jose+json',
        'content-length': String(oversized.length),
      });
      res.end(oversized);
    },
  });
  try {
    const client = new EvidenceClient({
      baseUrl: stub.baseUrl,
      trustedJwks: DUMMY_JWKS,
      token: { static: 'errors-test-token' },
      maxResponseBytes: 16,
    });
    const prepared = client.prepare(requestSpec());
    await assert.rejects(client.send(prepared), (error) => {
      assert.ok(error instanceof EvidenceClientError);
      assert.equal(error.kind, 'transport');
      assert.equal(error.transportKind, 'response_too_large');
      return true;
    });
  } finally {
    await stub.close();
  }
});

test('verifyAsOf refuses a non-finite or unrepresentable asOfMillis as a configuration failure', async () => {
  const signingKey = generateSigningKey('as-of-millis-key');
  const spec = requestSpec();
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res, body) => {
      const requestBody = JSON.parse(body.toString('utf8'));
      const evidence = evidenceFor(spec, requestBody.requestNonce);
      const jws = signEvidence(evidence, signingKey);
      res.writeHead(200, { 'content-type': 'application/jose+json' });
      res.end(JSON.stringify(jws));
    },
  });

  try {
    const client = new EvidenceClient({
      baseUrl: stub.baseUrl,
      trustedJwks: signingKey.jwks,
      token: { static: 'as-of-millis-token' },
    });
    const prepared = client.prepare(spec);
    const response = await client.send(prepared);

    for (const asOfMillis of [NaN, Infinity, Number.MAX_VALUE]) {
      assert.throws(
        () => client.verifyAsOf(prepared, response, asOfMillis),
        (error) => {
          assert.ok(error instanceof EvidenceClientError);
          assert.equal(error.kind, 'configuration');
          return true;
        },
        `asOfMillis ${asOfMillis} was accepted`,
      );
    }
  } finally {
    await stub.close();
  }
});
