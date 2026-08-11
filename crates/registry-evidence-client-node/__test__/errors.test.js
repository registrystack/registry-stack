'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { EvidenceClient, EvidenceClientError } = require('..');
const { startStubServer } = require('./helpers/stub-server');
const { generateSigningKey, signEvidence, requestSpec, evidenceFor } = require('./helpers/live-signing');

const DUMMY_JWKS = {
  keys: [
    {
      kty: 'EC',
      crv: 'P-256',
      kid: '_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo',
      alg: 'ES256',
      x: '3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4',
      y: 'GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU',
    },
  ],
};
const TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';
const TRACEPARENT = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

/** None of these cases reach signature verification: the client maps them to
 * a failure before the response body is ever trusted, so the stub never
 * needs to sign anything real. */
async function clientAndPrepared(stub) {
  const client = new EvidenceClient({
    baseUrl: stub.baseUrl,
    trustedJwks: DUMMY_JWKS,
    revokedKeyIds: [],
    token: { static: 'errors-test-token' },
  });
  return { client, prepared: client.prepare(requestSpec()) };
}

function problemBody(status, code, traceId) {
  const [title, detail] = {
    'evidence.invalid_request': ['Evidence request is invalid', 'the Evidence request is invalid'],
    'request.selector_invalid': ['Selector is invalid', 'selector does not match an available request profile'],
    'auth.invalid_credential': ['Bearer access token is invalid', 'bearer access token validation failed'],
    'evidence.denied': ['Evidence request is not permitted', 'the Evidence request is not permitted'],
    'format.unsupported': ['Requested format is not supported', 'the requested format is not supported'],
    'evidence.unavailable': ['Evidence could not be produced', 'evidence could not be produced for this request'],
    'evidence.rate_limited': ['Evidence request rate is exhausted', 'the Evidence request rate is exhausted'],
    'source.unavailable': ['Authoritative source is unavailable', 'the authoritative source is unavailable'],
    'service.unavailable': ['Service is unavailable', 'the request could not be served'],
    'resource.not_found': ['Requested resource was not found', 'the requested resource was not found'],
  }[code];
  return JSON.stringify({
    type: `https://id.registrystack.org/problems/registry-evidence/${code.replaceAll('.', '/')}`,
    title,
    status,
    detail,
    code,
    traceId,
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

test('401 with the registered code maps to a denied failure', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(401, { 'content-type': 'application/problem+json', traceparent: TRACEPARENT });
      res.end(problemBody(401, 'auth.invalid_credential', TRACE_ID));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'denied');
    assert.equal(mapped.status, 401);
    assert.equal(mapped.code, 'auth.invalid_credential');
    assert.equal(mapped.traceId, TRACE_ID);
    assert.equal(mapped.retryAfterSeconds, undefined);
  });
});

test('403 with the registered code maps to a denied failure', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(403, { 'content-type': 'application/problem+json', traceparent: TRACEPARENT });
      res.end(problemBody(403, 'evidence.denied', TRACE_ID));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'denied');
    assert.equal(mapped.status, 403);
    assert.equal(mapped.code, 'evidence.denied');
    assert.equal(mapped.traceId, TRACE_ID);
    assert.equal(mapped.retryAfterSeconds, undefined);
  });
});

test('429 with a Retry-After header maps to a denied failure carrying the wait', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(429, {
        'content-type': 'application/problem+json',
        traceparent: TRACEPARENT,
        'retry-after': '30',
      });
      res.end(problemBody(429, 'evidence.rate_limited', TRACE_ID));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'denied');
    assert.equal(mapped.status, 429);
    assert.equal(mapped.code, 'evidence.rate_limited');
    assert.equal(mapped.traceId, TRACE_ID);
    assert.equal(mapped.retryAfterSeconds, 30);
  });
});

test('422 with the not-available code maps to its own failure, with no status field', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(422, {
        'content-type': 'application/problem+json',
        traceparent: TRACEPARENT,
      });
      res.end(problemBody(422, 'evidence.unavailable', TRACE_ID));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'not_available');
    assert.equal(mapped.status, undefined);
    assert.equal(mapped.traceId, TRACE_ID);
  });
});

test('400 with an ordinary contract code maps to a protocol failure', async () => {
  const stub = await startStubServer({
    'POST /v1/evidence': (req, res) => {
      res.writeHead(400, {
        'content-type': 'application/problem+json',
        traceparent: TRACEPARENT,
      });
      res.end(problemBody(400, 'evidence.invalid_request', TRACE_ID));
    },
  });
  await assertMappedFailure(stub, (mapped) => {
    assert.equal(mapped.kind, 'protocol');
    assert.equal(mapped.status, 400);
    assert.equal(mapped.code, 'evidence.invalid_request');
    assert.equal(mapped.traceId, TRACE_ID);
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
      revokedKeyIds: [],
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
      revokedKeyIds: [],
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
