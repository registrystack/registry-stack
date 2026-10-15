'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const POLICY_DIGEST =
  'sha256:38ea436942f78766fc2db332c18e3ed545ec4e907d3386ec41b0c2eeb60e7f6c';

test('facade exports the maintained client and mapped error', () => {
  const client = require('../client');
  assert.equal(typeof client.CaseworkClient, 'function');
  assert.equal(typeof client.CaseworkClientError, 'function');
});

test('review result feed preserves distinct identifiers and refuses nil correlation identifiers', async (context) => {
  const nil = '00000000-0000-0000-0000-000000000000';
  const entry = {
    eventId: '00000000-0000-0000-0000-000000000008',
    requestId: '00000000-0000-0000-0000-000000000007',
    resultId: '00000000-0000-0000-0000-000000000099',
    completedAt: '2026-09-19T00:00:00Z',
  };
  const pages = [
    { items: [entry], nextCursor: entry.eventId },
    ...['requestId', 'resultId'].map((field) => ({
      items: [{ ...entry, [field]: nil }], nextCursor: entry.eventId,
    })),
  ];
  const observations = [];
  const server = http.createServer((request, response) => {
    observations.push({ path: request.url, headers: request.headers });
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(JSON.stringify(pages.shift()));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const { CaseworkClient, CaseworkClientError } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/tenant/` });
  const query = { cursor: entry.eventId, limit: 1 };

  const page = await client.reviewResults('one-call-secret', 'requester', query);
  assert.deepEqual(page.value.items, [entry]);
  assert.equal(page.value.nextCursor, entry.eventId);
  for (const field of ['requestId', 'resultId']) {
    await assert.rejects(() => client.reviewResults('one-call-secret', 'requester', query), (error) => {
      assert.ok(error instanceof CaseworkClientError, field);
      assert.equal(error.kind, 'protocol', field);
      assert.equal(error.protocolFailure, 'body', field);
      assert.equal(error.status, 200, field);
      assert.equal(error.traceId, '0123456789abcdef0123456789abcdef', field);
      assert.doesNotMatch(error.message, /one-call-secret|00000000-/);
      return true;
    });
  }
  assert.equal(observations.length, 3);
  assert.equal(pages.length, 0);
  for (const observation of observations) {
    assert.equal(observation.path, `/tenant/v1/review-results?cursor=${entry.eventId}&limit=1`);
    assert.equal(observation.headers['registry-review-profile'], 'requester');
  }
});

test('a configuration value the sanitizer refuses is a configuration error', () => {
  const { CaseworkClient, CaseworkClientError } = require('../client');
  const baseUrl = 'https://casework.example/';
  for (const [label, config] of [
    ['an unsafe integer', { baseUrl, requestTimeoutMilliseconds: Number.MAX_SAFE_INTEGER + 1 }],
    ['a non-finite number', { baseUrl, maxResponseBytes: Infinity }],
    ['an undefined member', { baseUrl, userAgent: undefined }],
    ['a function', { baseUrl, userAgent: () => 'casework-test' }],
    ['a date', { baseUrl, requestTimeoutMilliseconds: new Date(0) }],
    ['a proxy', new Proxy({ baseUrl }, {})],
    ['no configuration', undefined],
  ]) {
    assert.throws(() => new CaseworkClient(config), (error) => {
      assert.ok(error instanceof CaseworkClientError, label);
      assert.equal(error.kind, 'configuration', label);
      assert.equal(error.outcomeUnknown, false, label);
      return true;
    });
  }
});

test('review task discovery validates selectors before I/O', async () => {
  const { CaseworkClient, CaseworkClientError } = require('../client');
  const client = new CaseworkClient({ baseUrl: 'https://casework.example.test/' });
  assert.equal(typeof client.supervisoryReviewTasks, 'function');
  assert.equal(typeof client.ownReviewDecisions, 'function');
  for (const call of [
    () => client.reviewTasks('one-call-secret', 'staff', { ownership: 'someone-elses' }),
    () => client.reviewTasks('one-call-secret', 'staff', { ownership: 'assigned_to_me' }),
    () => client.supervisoryReviewTasks('one-call-secret', 'supervisor', { ownership: 'unclaimed' }),
    ...[{ author: 'colleague' }, { ownership: 'assigned-to-me' }, { cursor: 'not-a-uuid' }, { limit: 0 }, { limit: 101 }].map((query) => () =>
      client.ownReviewDecisions('one-call-secret', 'staff', query)),
    ...['', 'not-a-uuid', 42, {}, []].map((requestId) => () =>
      client.supervisoryReviewTasks('one-call-secret', 'supervisor', { requestId })),
  ]) {
    await assert.rejects(call, (error) => {
      assert.ok(error instanceof CaseworkClientError);
      assert.equal(error.kind, 'invalid-request');
      return true;
    });
  }
});

test('review task context uses the exact route and forwards the optional source profile', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = { path: request.url, headers: request.headers };
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(fixtureStringify({
        taskId: '00000000-0000-0000-0000-000000000000',
        requestId: '10000000-0000-4000-8000-000000000001',
        subject: {
          source: 'professional-licences', type: 'change-request', id: 'correction-42', version: '1',
          digest: `sha256:${'a'.repeat(64)}`,
        },
        requesterReference: 'correction-42',
        policy: { id: 'registry-correction', version: '1', digest: POLICY_DIGEST },
        policyClosure: {
          identity: { id: 'registry-correction', version: '1', digest: POLICY_DIGEST },
          purpose: 'approval', contextStrategy: 'source',
          stages: [{ id: 'review', queue: 'review', decidingProfiles: ['staff'], requiredApprovals: 1, excludeInitiator: false, excludePreviousStageReviewers: false }],
          retention: { terminalDays: 30, accountabilityDays: 30 },
          displaySchema: { type: 'object', additionalProperties: false, properties: {} },
          outcomes: [{ id: 'approved', label: 'Approve', settlement: 'approved', reasonRequired: false, publicReason: 'optional' }],
        },
        context: {
          strategy: 'source', reference: 'correction-42', bindingStatus: 'current',
          projection: {
            binding: {
              sourceRevision: 'revision-42', version: '1', generation: 'generation-42',
              integrity: `sha256:${'a'.repeat(64)}`,
            },
            displayReference: 'Correction 42', display: {},
          },
        },
      }));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  const result = await client.reviewTaskContext(
    'one-call-secret',
    'staff',
    '00000000-0000-0000-0000-000000000000',
    'reviewer',
  );

  assert.equal(result.value.context.projection.displayReference, 'Correction 42');
  assert.equal(observed.path, '/v1/review-tasks/00000000-0000-0000-0000-000000000000/context');
  assert.equal(observed.headers.authorization, 'Bearer one-call-secret');
  assert.equal(observed.headers['registry-casework-profile'], 'staff');
  assert.equal(observed.headers['registry-source-profile'], 'reviewer');
});

test('supervisory review task discovery preserves the bounded row and query', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = { path: request.url, headers: request.headers };
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(fixtureStringify({
        items: [{
          taskId: '00000000-0000-0000-0000-000000000007',
          requestId: '00000000-0000-0000-0000-000000000009',
          queue: 'reviews',
          revision: 3,
          state: 'decided',
          accountabilityEventId: '00000000-0000-0000-0000-000000000011',
        }],
        status: 'complete',
      }));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  const result = await client.supervisoryReviewTasks(
    'one-call-secret',
    'supervisor',
    {
      queue: 'reviews',
      requestId: '00000000-0000-0000-0000-000000000009',
      cursor: '00000000-0000-0000-0000-000000000008',
      limit: 10,
    },
    'reviewer',
  );

  assert.equal(result.value.items[0].accountabilityEventId, '00000000-0000-0000-0000-000000000011');
  assert.equal(observed.path, '/v1/review-tasks/supervision?queue=reviews&requestId=00000000-0000-0000-0000-000000000009&cursor=00000000-0000-0000-0000-000000000008&limit=10');
  assert.equal(observed.headers['registry-casework-profile'], 'supervisor');
  assert.equal(observed.headers['registry-source-profile'], 'reviewer');
  await assert.rejects(client.supervisoryReviewTasks(
    'one-call-secret', 'supervisor',
    { requestId: '00000000-0000-0000-0000-000000000010' },
    'reviewer',
  ), (error) => error.kind === 'protocol' && error.protocolFailure === 'body');
});

test('own decisions preserve the reference and pinned receipt through the native client', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = { path: request.url, headers: request.headers };
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(fixtureStringify({
        items: [{
          taskId: '00000000-0000-0000-0000-000000000007',
          requestId: '00000000-0000-0000-0000-000000000009',
          queue: 'reviews', requesterReference: 'BATCH-0042',
          decisionReceipt: {
            policy: { id: 'registry-correction', version: '1', digest: POLICY_DIGEST },
            decision: 'answer', outcome: 'confirm', outcomeLabel: 'Confirm',
            decidedAt: '2026-10-10T01:00:00Z',
          },
        }], status: 'complete',
      }));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const page = await client.ownReviewDecisions('staff-token', 'staff', { queue: 'reviews', limit: 10 }, 'reviewer');
  assert.deepEqual(Object.keys(page.value.items[0]).sort(), ['decisionReceipt', 'queue', 'requestId', 'requesterReference', 'taskId']);
  assert.equal(page.value.items[0].requesterReference, 'BATCH-0042');
  assert.equal(page.value.items[0].decisionReceipt.outcome, 'confirm');
  assert.equal(page.value.items[0].decisionReceipt.outcomeLabel, 'Confirm');
  assert.equal(observed.path, '/v1/review-tasks/own-decisions?queue=reviews&limit=10');
  assert.equal(observed.headers['registry-casework-profile'], 'staff');
  assert.equal(observed.headers['registry-source-profile'], 'reviewer');
  await assert.rejects(client.ownReviewDecisions('staff-token', 'staff', { queue: 'another' }),
    (error) => error.kind === 'protocol' && error.protocolFailure === 'body');
});

test('review note forwards the optional source profile and idempotency key', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = { path: request.url, headers: request.headers };
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(fixtureStringify({
        eventId: '10000000-0000-4000-8000-000000000001',
        requestId: '00000000-0000-0000-0000-000000000000',
        kind: 'note',
        detail: { audience: 'reviewers', note: 'Review note' },
        occurredAt: '2026-09-20T00:00:00Z',
      }));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  const result = await client.addReviewNote(
    'one-call-secret',
    'staff',
    '00000000-0000-0000-0000-000000000000',
    'note-1',
    { audience: 'reviewers', note: 'Review note' },
    'reviewer',
  );

  assert.equal(result.value.kind, 'note');
  assert.equal(observed.path, '/v1/review-requests/00000000-0000-0000-0000-000000000000/notes');
  assert.equal(observed.headers.authorization, 'Bearer one-call-secret');
  assert.equal(observed.headers['registry-casework-profile'], 'staff');
  assert.equal(observed.headers['registry-source-profile'], 'reviewer');
  assert.equal(observed.headers['idempotency-key'], 'note-1');
});

test('review clocks forward the optional source profile', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = { path: request.url, headers: request.headers };
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end('[]');
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  const result = await client.reviewClocks(
    'one-call-secret',
    'staff',
    '00000000-0000-0000-0000-000000000000',
    'reviewer',
  );

  assert.deepEqual(result.value, []);
  assert.equal(observed.path, '/v1/review-requests/00000000-0000-0000-0000-000000000000/clocks');
  assert.equal(observed.headers.authorization, 'Bearer one-call-secret');
  assert.equal(observed.headers['registry-casework-profile'], 'staff');
  assert.equal(observed.headers['registry-source-profile'], 'reviewer');
});

test('decision forwards the selected source profile with mutation headers', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = request.headers;
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end('{}');
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  await assert.rejects(client.decideReviewTask(
    'one-call-secret', 'staff', '00000000-0000-0000-0000-000000000009',
    9, 'attempt-9', { decision: { type: 'approve', outcome: 'approved' } }, 'reviewer',
  ), (error) => error.kind === 'protocol');

  assert.equal(observed.authorization, 'Bearer one-call-secret');
  assert.equal(observed['registry-casework-profile'], 'staff');
  assert.equal(observed['registry-source-profile'], 'reviewer');
  assert.equal(observed['if-match'], '"9"');
  assert.equal(observed['idempotency-key'], 'attempt-9');
});

test('an undeclared outcome refusal names the outcomes the review policy declares', async (context) => {
  const server = http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      response.writeHead(400, {
        'content-type': 'application/problem+json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
        'registry-casework-validation-path': '$.outcome',
        'registry-casework-validation-reason': 'outcome-not-declared',
        'registry-casework-validation-allowed': 'approved,approved-with-note',
      });
      response.end(JSON.stringify({
        type: 'https://id.registrystack.org/problems/registry-casework/request/invalid',
        title: 'Invalid request',
        status: 400,
        detail: 'The Casework request is invalid.',
        code: 'request.invalid',
        traceId: '0123456789abcdef0123456789abcdef',
      }));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  await assert.rejects(client.decideReviewTask(
    'one-call-secret', 'staff', '00000000-0000-0000-0000-000000000009',
    9, 'attempt-9', { decision: { type: 'approve', outcome: 'accepted' } },
  ), (error) => {
    assert.equal(error.code, 'request.invalid');
    assert.deepEqual(error.validation, {
      path: '$.outcome',
      reason: 'outcome-not-declared',
      allowed: ['approved', 'approved-with-note'],
    });
    return true;
  });
});

test('directory target discovery preserves its exact purpose context without source authority', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = { url: request.url, headers: request.headers };
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(fixtureStringify({
        items: [{ issuer: 'https://id.example', subject: 'cover-officer', displayName: 'Cover Officer' }],
        nextCursor: 'target-next',
        status: 'complete',
      }));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const page = await client.directoryTargets('one-call-secret', 'supervisor', {
    purpose: 'absence-cover',
    personIssuer: 'https://id.example',
    personSubject: 'absent-officer',
    cursor: 'opaque-target-cursor',
    limit: 25,
  });

  const query = new URL(observed.url, 'http://fixture.invalid').searchParams;
  assert.equal(query.get('purpose'), 'absence-cover');
  assert.equal(query.get('personIssuer'), 'https://id.example');
  assert.equal(query.get('personSubject'), 'absent-officer');
  assert.equal(query.get('cursor'), 'opaque-target-cursor');
  assert.equal(query.get('limit'), '25');
  assert.equal(observed.headers['registry-casework-profile'], 'supervisor');
  assert.equal(observed.headers['registry-source-profile'], undefined);
  assert.deepEqual(page.value, {
    items: [{ issuer: 'https://id.example', subject: 'cover-officer', displayName: 'Cover Officer' }],
    nextCursor: 'target-next',
    status: 'complete',
  });
});

test('absence list carries caller pagination and the next cursor', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      observed = { path: request.url, headers: request.headers };
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(fixtureStringify({ directoryRevision: 12, items: [], nextCursor: 'absence-next' }));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const absences = await client.absences(
    'one-call-secret',
    'staff',
    { cursor: 'opaque-absence-cursor', limit: 1000 },
  );

  assert.equal(absences.value.directoryRevision, 12);
  assert.deepEqual(absences.value.items, []);
  assert.equal(absences.value.nextCursor, 'absence-next');
  assert.equal(observed.path, '/v1/directory/absences?cursor=opaque-absence-cursor&limit=1000');
  assert.equal(observed.headers.authorization, 'Bearer one-call-secret');
  assert.equal(observed.headers['registry-casework-profile'], 'staff');
  assert.equal(observed.headers['registry-source-profile'], undefined);
});

test('unknown future problem code stays a problem without recovery metadata', async (context) => {
  const server = problemServer('review.future-safe');
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  await assert.rejects(
    client.description('one-call-secret', 'staff'),
    (error) => {
      assert.equal(error.kind, 'problem');
      assert.equal(error.code, 'review.future-safe');
      assert.equal(error.detail, undefined);
      assert.equal(error.message, 'Registry Casework refused the request');
      assert.equal(error.originalAttemptId, undefined);
      return true;
    },
  );
});

test('native client refuses nested unsafe integers before HTTP and preserves safe numbers', async (context) => {
  const requests = [];
  const server = http.createServer((request, response) => {
    let bytes = '';
    request.on('data', (chunk) => { bytes += chunk; });
    request.on('end', () => {
      requests.push({ path: request.url, body: JSON.parse(bytes) });
      response.writeHead(201, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(fixtureStringify({
        itemId: '00000000-0000-4000-8000-000000000001',
        requesterReference: requests.at(-1).body.requesterReference,
        kind: requests.at(-1).body.kind,
        version: '1',
        display: requests.at(-1).body.display,
        state: 'open',
        revision: 1,
        kindPolicyDigest: `sha256:${'a'.repeat(64)}`,
        createdAt: '2026-09-11T00:00:00Z',
        updatedAt: '2026-09-11T00:00:00Z',
      }));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { CaseworkClient: NativeCaseworkClient } = require('../index');
  const client = new NativeCaseworkClient({
    baseUrl: `http://127.0.0.1:${server.address().port}/`,
  });
  const document = { holidaySet: 'office', revision: Number.MAX_SAFE_INTEGER + 1, dates: [] };
  await assert.rejects(
    client.createHolidayRevision('synthetic-token', 'administrator', 'unsafe-revision', { document }),
    (error) => JSON.parse(error.message).kind === 'invalid-request',
  );
  const digest = `sha256:${'a'.repeat(64)}`;
  const review = {
    policy: { id: 'decision', version: '1', digest },
    subject: { source: 'standalone', type: 'batch', id: 'batch-1', version: '1', digest },
    requesterReference: 'batch-1',
    context: { mode: 'submitted', snapshot: { count: 1 } },
    resultConstraints: [],
  };
  await assert.rejects(
    client.createOrRecoverReviewRequest('synthetic-token', 'requester', 'review-array', review, digest),
    (error) => JSON.parse(error.message).kind === 'invalid-request',
  );
  await assert.rejects(
    client.createOrRecoverReviewRequest(
      'synthetic-token',
      'requester',
      'review-unsafe',
      { ...review, resultConstraints: { maximum: Number.MAX_SAFE_INTEGER + 1 } },
      digest,
    ),
    (error) => JSON.parse(error.message).kind === 'invalid-request',
  );
  assert.equal(requests.length, 0);
});

test('review cancellation sends the full accepted binding', async (context) => {
  let observed;
  const digest = `sha256:${'a'.repeat(64)}`;
  const requestId = '00000000-0000-4000-8000-000000000001';
  const accepted = {
    requestId,
    subject: { source: 'standalone', type: 'batch', id: 'batch-1', version: '1', digest },
    policy: { id: 'decision', version: '1', digest },
    submissionDigest: digest,
  };
  const server = http.createServer((request, response) => {
    let bytes = '';
    request.on('data', (chunk) => { bytes += chunk; });
    request.on('end', () => {
      observed = { path: request.url, body: JSON.parse(bytes) };
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(fixtureStringify({
        outcome: 'cancelled',
        result: {
          resultId: '10000000-0000-4000-8000-000000000001',
          ...accepted,
          status: 'cancelled',
          completedAt: '2026-09-20T00:00:00Z',
          availableUntil: '2026-10-20T00:00:00Z',
        },
      }));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const cancellation = { subject: accepted.subject, reason: 'No longer needed' };
  const result = await client.cancelReviewRequest(
    'synthetic-token', 'requester', accepted, 'cancel-1', cancellation,
  );

  assert.equal(result.value.outcome, 'cancelled');
  assert.equal(observed.path, `/v1/review-requests/${requestId}/cancel`);
  assert.deepEqual(observed.body, cancellation);
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}

function problemServer(code, extraHeaders = {}) {
  return http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      response.writeHead(409, {
        'content-type': 'application/problem+json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
        ...extraHeaders,
      });
      response.end(fixtureStringify({
        type: `https://id.registrystack.org/problems/registry-casework/${code.replaceAll('.', '/')}`,
        title: code,
        status: 409,
        detail: 'Safe detail.',
        code,
        traceId: '0123456789abcdef0123456789abcdef',
      }));
    });
  });
}

// The canonical serializer is exercised by the Rust closure fixture. These
// language fixtures bind the same policy/dependency envelope with synthetic data.
function fixtureStringify(document) {
  if (document?.policyClosure) {
    const closure = document.policyClosure;
    const policy = {
      id: closure.identity.id, version: closure.identity.version,
      purpose: closure.purpose,
      context: closure.contextStrategy === 'source'
        ? { mode: 'current-source', provider: 'registry', contract: { id: 'registry-context', revision: POLICY_DIGEST, schemaDigest: POLICY_DIGEST } }
        : { mode: 'submitted' },
      stages: closure.stages, retention: closure.retention, displaySchema: closure.displaySchema,
      ...(closure.outcomes ? { outcomes: closure.outcomes } : {}),
    };
    const dependencies = { accessProfiles: [], queues: [], teams: [], clocks: [], calendars: [], contextProvider: null, taskTemplates: [], trustedProducers: [], inbox: { defaultPageSize: 25, maximumCandidateScan: 100, maximumSourceReads: 25, maximumConcurrentSourceReads: 4, pageDeadlineMilliseconds: 2000 } };
    const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
    // Outcome labels are presentation and stay out of the behavioral digest.
    const digested = policy.outcomes ? { ...policy, outcomes: policy.outcomes.map(outcome => ({ ...outcome, label: '' })) } : policy;
    const digest = 'sha256:' + require('node:crypto').createHash('sha256').update(JSON.stringify(canonical({ schema: 'registry-casework-review-policy/v1', policy: digested, dependencies }))).digest('hex');
    const { id, version, ...fields } = policy;
    document.policy = { id, version, digest };
    document.policyClosure = { identity: document.policy, ...fields, dependencies };
    document.context.mode = document.context.strategy === 'source' ? 'current-source' : 'submitted';
    delete document.context.strategy;
    if (document.context.projection) document.context.projection.binding = document.subject;
  }
  return JSON.stringify(document);
}
