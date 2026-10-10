'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { inspect: inspectValue } = require('node:util');

const RUN_ID = '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d';
const STATUS = {
  runId: RUN_ID,
  workflowId: 'decision-follow-up',
  workflowVersion: '1',
  definitionDigest: 'sha256:definition',
  bindingDigest: 'sha256:binding',
  step: 'read-record',
  state: 'waiting',
  outcome: null,
  output: null,
  failureCode: null,
  admittedAt: '2026-10-10T01:00:00Z',
  deadlineAt: '2026-10-10T02:00:00Z',
  nextDueAt: '2026-10-10T01:01:00Z',
  uncertain: false,
  restoreReviewRequired: false,
  cancelRequested: false,
};
const INSPECTION = {
  run: STATUS,
  steps: [{
    step: 'read-record',
    state: 'waiting',
    generation: 1,
    attempt: 1,
    nextDueAt: '2026-10-10T01:01:00Z',
    leaseExpiresAt: null,
    commandPrepared: true,
    uncertain: true,
    receiptExpired: false,
    failureCode: null,
  }],
  recovery: {
    retryAllowed: false,
    reason: 'evaluation-uncertain',
    operation: {
      id: 'evaluate-decision',
      version: 1,
      product: 'decision',
      effect: 'evaluation',
      keyRequirement: 'required',
      requiresPreparation: true,
      recovery: 'hold-after-dispatch',
      readReceipt: true,
    },
  },
};

async function serve(context, answer) {
  const requests = [];
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      requests.push({ method: request.method, path: request.url, headers: request.headers, body });
      const { status, document, contentType = 'application/json' } = answer(request);
      response.writeHead(status, { 'content-type': contentType });
      response.end(JSON.stringify(document));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));
  return { baseUrl: `http://127.0.0.1:${server.address().port}/`, requests };
}

test('facade exports the maintained client and mapped error', () => {
  const client = require('../client');
  assert.equal(typeof client.CoordinatorClient, 'function');
  assert.equal(typeof client.CoordinatorClientError, 'function');
});

test('start preserves the caller token, key, and input and sends once', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 200, document: STATUS }));
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl });
  const request = { flow: 'decision-follow-up', input: { record: 'case-42', priority: 2 } };

  assert.deepEqual(
    await client.start('one-call-secret', 'admission 42', request),
    { kind: 'complete', value: STATUS },
  );
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/v1/runs');
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
  assert.equal(requests[0].headers['idempotency-key'], 'admission 42');
  assert.equal(requests[0].headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[0].body), request);
});

test('status, inspect, and reconcile use only the requested run routes', async (context) => {
  const { baseUrl, requests } = await serve(context, (request) => ({
    status: 200,
    document: request.url.endsWith('/inspect') || request.url.endsWith('/reconcile') ? INSPECTION : STATUS,
  }));
  const { CoordinatorClient } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  assert.deepEqual(await client.status('read-secret', RUN_ID), { kind: 'complete', value: STATUS });
  assert.deepEqual(await client.inspect('inspect-secret', RUN_ID), { kind: 'complete', value: INSPECTION });
  assert.deepEqual(
    await client.reconcile('reconcile-secret', RUN_ID, 'operator reviewed the original receipt'),
    { kind: 'complete', value: INSPECTION },
  );
  assert.deepEqual(requests.map(({ method, path }) => [method, path]), [
    ['GET', `/v1/runs/${RUN_ID}`],
    ['GET', `/v1/runs/${RUN_ID}/inspect`],
    ['POST', `/v1/runs/${RUN_ID}/reconcile`],
  ]);
  assert.deepEqual(JSON.parse(requests[2].body), { reason: 'operator reviewed the original receipt' });
});

test('invalid request documents and run identifiers fail before I/O', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500, document: {} }));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  assert.throws(
    () => client.start('secret', 'admission-42', { flow: 'decision-follow-up', input: { unsafe: 9_007_199_254_740_992 } }),
    (error) => error instanceof CoordinatorClientError && error.kind === 'invalid_request',
  );
  await assert.rejects(
    client.status('secret', 'not-a-run-id'),
    (error) => error instanceof CoordinatorClientError && error.kind === 'invalid_request',
  );
  assert.equal(requests.length, 0);
});

test('a service problem is safe and is never retried', async (context) => {
  const problemMessage = 'internal operator detail secret-should-not-escape';
  const { baseUrl, requests } = await serve(context, () => ({
    status: 503,
    document: { code: 'store-unavailable', message: problemMessage, suggestedAction: 'private runbook' },
  }));
  const { CoordinatorClient, CoordinatorClientError } = require('../client');
  const client = new CoordinatorClient({ baseUrl });

  await assert.rejects(
    client.reconcile('reconcile-secret', RUN_ID, 'check original receipt'),
    (error) => {
      assert.ok(error instanceof CoordinatorClientError);
      assert.equal(error.kind, 'problem');
      assert.equal(error.code, 'store-unavailable');
      assert.equal(error.status, 503);
      assert.equal(error.outcomeUnknown, true);
      const displayed = inspectValue(error);
      assert.doesNotMatch(displayed, /secret-should-not-escape|private runbook|reconcile-secret/);
      return true;
    },
  );
  assert.equal(requests.length, 1);
});
