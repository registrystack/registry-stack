'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const ITEM_ID = '00000000-0000-4000-8000-000000000001';
const EVENT_ID = '00000000-0000-4000-8000-000000000002';
const PLAIN_ITEM_ID = '00000000-0000-4000-8000-000000000003';
const CANCELLED_ITEM_ID = '00000000-0000-4000-8000-000000000004';
const POLICY_DIGEST = `sha256:${'a'.repeat(64)}`;
const TRACEPARENT = '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01';

const CONSTRAINTS = {
  batchStatus: {
    oneOf: [
      { const: 'valid', title: 'All rows valid' },
      { const: 'partial', title: 'Some rows rejected' },
    ],
  },
  acceptedCount: { minimum: 0, maximum: 412 },
  correctedReference: { maxLength: 32 },
};
const RESULT = { batchStatus: 'partial', acceptedCount: 400 };

function requesterItem(body) {
  return {
    itemId: ITEM_ID,
    requesterReference: body.requesterReference,
    kind: body.kind,
    version: '1',
    display: body.display,
    resultConstraints: body.resultConstraints,
    state: 'open',
    revision: 1,
    kindPolicyDigest: POLICY_DIGEST,
    createdAt: '2026-09-18T00:00:00Z',
    updatedAt: '2026-09-18T00:00:00Z',
  };
}

function completedTerminal(itemId, result) {
  return {
    itemId,
    eventId: EVENT_ID,
    requesterReference: 'openfn:run:8f2',
    state: 'completed',
    outcome: 'confirmed',
    actorRef: 'actor_01K4W92K7C8V6M2A',
    kindPolicyDigest: POLICY_DIGEST,
    result,
    terminalAt: '2026-09-18T01:00:00Z',
  };
}

function cancelledTerminal() {
  return {
    itemId: CANCELLED_ITEM_ID,
    eventId: EVENT_ID,
    requesterReference: 'openfn:run:8f2',
    state: 'cancelled',
    cancellationReason: 'Withdrawn by the requester',
    kindPolicyDigest: POLICY_DIGEST,
    terminalAt: '2026-09-18T01:00:00Z',
  };
}

function stubServer(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function respondJson(response, status, body) {
  response.writeHead(status, {
    'content-type': 'application/json',
    traceparent: TRACEPARENT,
  });
  response.end(JSON.stringify(body));
}

test('createHostedItem forwards resultConstraints verbatim and maps them back', async (context) => {
  let observed;
  const server = await stubServer((request, response) => {
    let bytes = '';
    request.on('data', (chunk) => { bytes += chunk; });
    request.on('end', () => {
      observed = { path: request.url, body: JSON.parse(bytes) };
      respondJson(response, 201, requesterItem(observed.body));
    });
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  const outcome = await client.createHostedItem('requester-token', 'requester', 'create-with-constraints', {
    kind: 'batch-validation',
    requesterReference: 'openfn:run:8f2',
    display: { summary: 'Review the prepared batch', batchReference: 'B-2026-0912' },
    resultConstraints: CONSTRAINTS,
  });

  assert.equal(observed.path, '/v1/hosted-items');
  assert.deepEqual(observed.body.resultConstraints, CONSTRAINTS);
  assert.equal(outcome.kind, 'complete');
  assert.deepEqual(outcome.value.resultConstraints, CONSTRAINTS);
  assert.equal(outcome.value.state, 'open');
});

test('decideHostedWorkItem sends the structured result and reads it off the terminal result', async (context) => {
  let observed;
  const server = await stubServer((request, response) => {
    let bytes = '';
    request.on('data', (chunk) => { bytes += chunk; });
    request.on('end', () => {
      observed = { path: request.url, headers: request.headers, body: JSON.parse(bytes) };
      respondJson(response, 200, completedTerminal(ITEM_ID, observed.body.result));
    });
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  const outcome = await client.decideHostedWorkItem(
    'staff-token',
    'staff',
    {
      operation: 'confirmed',
      href: `/v1/work-items/${ITEM_ID}/hosted-decisions`,
      ifMatch: '"2"',
    },
    'decide-with-result',
    { outcome: 'confirmed', result: RESULT },
  );

  assert.equal(observed.path, `/v1/work-items/${ITEM_ID}/hosted-decisions`);
  assert.deepEqual(observed.body, { outcome: 'confirmed', result: RESULT });
  assert.equal(observed.headers['if-match'], '"2"');
  assert.equal(observed.headers['idempotency-key'], 'decide-with-result');
  assert.equal(outcome.value.state, 'completed');
  assert.equal(outcome.value.outcome, 'confirmed');
  assert.deepEqual(outcome.value.result, RESULT);
});

test('hostedTerminalItems exposes result exactly on the completed items that carried one', async (context) => {
  const server = await stubServer((request, response) => {
    respondJson(response, 200, {
      items: [
        completedTerminal(ITEM_ID, RESULT),
        completedTerminal(PLAIN_ITEM_ID, undefined),
        cancelledTerminal(),
      ],
      status: 'complete',
    });
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  const page = await client.hostedTerminalItems('requester-token', 'requester', { limit: 25 });

  assert.equal(page.value.status, 'complete');
  assert.equal(page.value.items.length, 3);
  assert.deepEqual(page.value.items[0].result, RESULT);
  assert.equal(page.value.items[1].state, 'completed');
  assert.equal(page.value.items[1].result, undefined, 'a decision without a result returns none');
  assert.equal(page.value.items[2].state, 'cancelled');
  assert.equal(page.value.items[2].result, undefined, 'a cancelled item never carries a result');
});
