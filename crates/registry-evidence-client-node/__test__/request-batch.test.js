'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const {
  EvidenceClient,
  EvidenceClientError,
  PreparedEvidenceRequestBatch,
  RawEvidenceRequestBatchResponse,
} = require('..');
const native = require('../index.js');
const { startStubServer } = require('./helpers/stub-server');
const {
  evidenceFor,
  generateSigningKey,
  requestSpec,
  signEvidence,
  SUBJECT_BINDING,
} = require('./helpers/live-signing');

const BATCH_MEDIA_TYPE = 'application/vnd.registrystack.evidence.request-batch+json';
const BATCH_SCHEMA = 'registry.evidence-request-batch/v1';

function requestBatchSpec() {
  const {
    responseFormat: _responseFormat,
    subjects,
    subjectExpectations,
    ...common
  } = requestSpec();
  return {
    ...common,
    items: [
      { subjects, subjectExpectations },
      {
        subjects: [
          {
            role: 'subject',
            selectorProfile: 'record-lookup-v1',
            selectorValues: { record_reference: 'R-002' },
          },
        ],
        subjectExpectations,
      },
    ],
  };
}

function envelope(items) {
  return JSON.stringify({
    schema: BATCH_SCHEMA,
    type: 'EvidenceRequestBatchResponse',
    items,
  });
}

function available(spec, nonce, signingKey) {
  return {
    result: 'evidence',
    evidence: signEvidence(evidenceFor(spec, nonce), signingKey),
  };
}

function batchRoute(spec, signingKey, resultForIndex) {
  return (_req, res, body) => {
    const request = JSON.parse(body.toString('utf8'));
    const items = request.items.map((item, index) =>
      resultForIndex(index, item.requestNonce, request),
    );
    res.writeHead(200, {
      'content-type': BATCH_MEDIA_TYPE,
      'x-request-id': 'nodebatchoperation',
    });
    res.end(envelope(items));
  };
}

function clientFor(stub, signingKey) {
  return new EvidenceClient({
    baseUrl: stub.baseUrl,
    trustedJwks: signingKey.jwks,
    revokedKeyIds: [],
    token: { static: 'request-batch-token' },
  });
}

test('request batch specifications reject fields outside their closed surfaces', () => {
  const signingKey = generateSigningKey();
  const client = clientFor({ baseUrl: 'http://127.0.0.1:9' }, signingKey);

  const topLevel = requestBatchSpec();
  topLevel.unknownBatchField = 'must-not-be-ignored';
  assert.throws(() => client.prepareBatch(topLevel), (error) => {
    assert.ok(error instanceof EvidenceClientError);
    assert.equal(error.kind, 'configuration');
    assert.equal(error.message, 'a request batch specification contains an unsupported field');
    return true;
  });

  for (const field of [
    'audience',
    'configurationRevision',
    'expectedAssuranceProfile',
    'expectedOutputs',
    'maximumAssertionLifetimeSeconds',
    'clockSkewSeconds',
    'holderKeys',
    'responseFormat',
    'unknownItemField',
  ]) {
    const spec = requestBatchSpec();
    spec.items[0][field] = 'must-not-be-ignored';
    assert.throws(() => client.prepareBatch(spec), (error) => {
      assert.ok(error instanceof EvidenceClientError);
      assert.equal(error.kind, 'configuration');
      assert.equal(error.message, 'a request batch item contains an unsupported field');
      return true;
    }, `item field ${field} was accepted`);
  }
});

test('a live two-item request batch has the exact wire shape and verifies in order', async () => {
  const signingKey = generateSigningKey();
  const spec = requestBatchSpec();
  const stub = await startStubServer({
    'POST /v1/evidence/batch': batchRoute(spec, signingKey, (_index, nonce) =>
      available(spec, nonce, signingKey),
    ),
  });

  try {
    const client = clientFor(stub, signingKey);
    const prepared = client.prepareBatch(spec);

    assert.ok(prepared instanceof PreparedEvidenceRequestBatch);
    assert.ok(prepared instanceof native.PreparedEvidenceRequestBatch);
    assert.equal(PreparedEvidenceRequestBatch, native.PreparedEvidenceRequestBatch);
    assert.equal(prepared.count, 2);
    assert.equal(prepared.requestNonces.length, 2);
    assert.notEqual(prepared.requestNonces[0], prepared.requestNonces[1]);
    assert.equal(prepared.policyDocuments.length, 2);
    assert.deepEqual(prepared.subjectExpectations, ['acceptFirstUse', 'acceptFirstUse']);

    const raw = await client.sendBatch(prepared);
    assert.ok(raw instanceof RawEvidenceRequestBatchResponse);
    assert.ok(raw instanceof native.RawEvidenceRequestBatchResponse);
    assert.equal(raw.operation, 'nodebatchoperation');
    assert.ok(Buffer.isBuffer(raw.body));

    const verified = client.verifyBatchAsOf(prepared, raw, Date.now());
    assert.equal(verified.operation, 'nodebatchoperation');
    assert.deepEqual(
      verified.items.map((item) => item.status),
      ['available', 'available'],
    );
    assert.deepEqual(
      verified.items.map((item) => item.verified.evidence.requestNonce),
      prepared.requestNonces,
    );
    assert.deepEqual(verified.items[0].verified.pinnedSubjectExpectations, [
      { role: 'subject', binding: SUBJECT_BINDING },
    ]);

    assert.equal(stub.requests.length, 1);
    assert.equal(stub.requests[0].headers.authorization, 'Bearer request-batch-token');
    assert.equal(stub.requests[0].headers.accept, BATCH_MEDIA_TYPE);
    assert.deepEqual(JSON.parse(stub.requests[0].body.toString('utf8')), {
      requirement: spec.requirement,
      purpose: spec.purpose,
      items: [
        {
          requestNonce: prepared.requestNonces[0],
          subjects: [
            {
              role: 'subject',
              selector: {
                profile: 'record-lookup-v1',
                values: { record_reference: 'R-001' },
              },
            },
          ],
        },
        {
          requestNonce: prepared.requestNonces[1],
          subjects: [
            {
              role: 'subject',
              selector: {
                profile: 'record-lookup-v1',
                values: { record_reference: 'R-002' },
              },
            },
          ],
        },
      ],
    });
  } finally {
    await stub.close();
  }
});

test('mixed available and notAvailable results retain their positions', async () => {
  const signingKey = generateSigningKey();
  const spec = requestBatchSpec();
  const stub = await startStubServer({
    'POST /v1/evidence/batch': batchRoute(spec, signingKey, (index, nonce) =>
      index === 0 ? available(spec, nonce, signingKey) : { result: 'evidence_not_available' },
    ),
  });

  try {
    const client = clientFor(stub, signingKey);
    const prepared = client.prepareBatch(spec);
    const raw = await client.sendBatch(prepared);
    const verified = client.verifyBatch(prepared, raw);

    assert.equal(verified.items[0].status, 'available');
    assert.equal(verified.items[0].verified.evidence.requestNonce, prepared.requestNonces[0]);
    assert.deepEqual(verified.items[1], { status: 'notAvailable' });
  } finally {
    await stub.close();
  }
});

test('a prepared request batch can be sent once and the second send stays local', async () => {
  const signingKey = generateSigningKey();
  const spec = requestBatchSpec();
  const stub = await startStubServer({
    'POST /v1/evidence/batch': batchRoute(spec, signingKey, () => ({
      result: 'evidence_not_available',
    })),
  });

  try {
    const client = clientFor(stub, signingKey);
    const prepared = client.prepareBatch(spec);
    await client.sendBatch(prepared);
    assert.equal(stub.requests.length, 1);

    await assert.rejects(client.sendBatch(prepared), (error) => {
      assert.ok(error instanceof EvidenceClientError);
      assert.equal(error.kind, 'configuration');
      return true;
    });
    assert.equal(stub.requests.length, 1);
  } finally {
    await stub.close();
  }
});

test('a swapped available member fails the batch atomically', async () => {
  const signingKey = generateSigningKey();
  const spec = requestBatchSpec();
  const stub = await startStubServer({
    'POST /v1/evidence/batch': batchRoute(spec, signingKey, (index, _nonce, request) =>
      available(spec, request.items[index === 0 ? 1 : 0].requestNonce, signingKey),
    ),
  });

  try {
    const client = clientFor(stub, signingKey);
    const prepared = client.prepareBatch(spec);
    const raw = await client.sendBatch(prepared);

    assert.throws(() => client.verifyBatch(prepared, raw), (error) => {
      assert.ok(error instanceof EvidenceClientError);
      assert.equal(error.kind, 'verification');
      return true;
    });
  } finally {
    await stub.close();
  }
});

test('one invalid signature prevents a partial verified result', async () => {
  const signingKey = generateSigningKey();
  const spec = requestBatchSpec();
  const stub = await startStubServer({
    'POST /v1/evidence/batch': batchRoute(spec, signingKey, (index, nonce) => {
      const item = available(spec, nonce, signingKey);
      if (index === 1) {
        const first = item.evidence.signature[0];
        item.evidence.signature = `${first === 'A' ? 'B' : 'A'}${item.evidence.signature.slice(1)}`;
      }
      return item;
    }),
  });

  try {
    const client = clientFor(stub, signingKey);
    const prepared = client.prepareBatch(spec);
    const raw = await client.sendBatch(prepared);

    assert.throws(() => client.verifyBatch(prepared, raw), (error) => {
      assert.ok(error instanceof EvidenceClientError);
      assert.equal(error.kind, 'verification');
      return true;
    });
  } finally {
    await stub.close();
  }
});

test('requestAndVerifyBatch performs one live exchange', async () => {
  const signingKey = generateSigningKey();
  const spec = requestBatchSpec();
  const stub = await startStubServer({
    'POST /v1/evidence/batch': batchRoute(spec, signingKey, (index, nonce) =>
      index === 0 ? available(spec, nonce, signingKey) : { result: 'evidence_not_available' },
    ),
  });

  try {
    const client = clientFor(stub, signingKey);
    const prepared = client.prepareBatch(spec);
    const verified = await client.requestAndVerifyBatch(prepared);

    assert.deepEqual(
      verified.items.map((item) => item.status),
      ['available', 'notAvailable'],
    );
    assert.equal(stub.requests.length, 1);
  } finally {
    await stub.close();
  }
});
