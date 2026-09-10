'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

test('facade exports the maintained client and mapped error', () => {
  const client = require('../client');
  assert.equal(typeof client.CaseworkClient, 'function');
  assert.equal(typeof client.CaseworkClientError, 'function');
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
  const binding = {
    sourceRevision: 'revision-9',
    version: 'version-9',
    generation: 'generation-9',
  };
  await assert.rejects(client.decideWorkItem(
    'one-call-secret',
    'staff',
    'reviewer',
    {
      operation: 'approve',
      href: '/v1/work-items/00000000-0000-0000-0000-000000000000/decisions',
      ifMatch: '"9"',
    },
    'attempt-9',
    {
      displayedBinding: binding,
      sourceProfileId: 'reviewer',
      operation: 'approve',
    },
  ), (error) => error.kind === 'protocol');

  assert.equal(observed.authorization, 'Bearer one-call-secret');
  assert.equal(observed['registry-casework-profile'], 'staff');
  assert.equal(observed['registry-source-profile'], 'reviewer');
  assert.equal(observed['if-match'], '"9"');
  assert.equal(observed['idempotency-key'], 'attempt-9');
});

test('source history forwards cursor and limit and returns the continuation', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = { path: request.url, headers: request.headers };
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(JSON.stringify({ items: [], nextCursor: 'next-cursor', status: 'complete' }));
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
  const page = await client.workItemHistory(
    'one-call-secret',
    'staff',
    'reviewer',
    '00000000-0000-0000-0000-000000000000',
    { cursor: 'opaque-cursor', limit: 25 },
  );

  assert.equal(page.value.nextCursor, 'next-cursor');
  assert.equal(
    observed.path,
    '/v1/work-items/00000000-0000-0000-0000-000000000000/history?cursor=opaque-cursor&limit=25',
  );
  assert.equal(observed.headers['registry-source-profile'], 'reviewer');
});

test('source inbox forwards one complete exact subject selector', async (context) => {
  let observed;
  const server = http.createServer((request, response) => {
    observed = { url: request.url, headers: request.headers };
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(JSON.stringify({ items: [], servedQueues: ['appeals', 'review'], status: 'complete' }));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const page = await client.listWorkItems('one-call-secret', 'staff', 'reviewer', {
    view: 'my_teams',
    sourceId: 'source-one',
    subjectKind: 'resident-record',
    subjectId: 'human-reference-42',
    limit: 25,
  });

  const query = new URL(observed.url, 'http://fixture.invalid').searchParams;
  assert.equal(query.get('sourceId'), 'source-one');
  assert.equal(query.get('subjectKind'), 'resident-record');
  assert.equal(query.get('subjectId'), 'human-reference-42');
  assert.equal(observed.headers['registry-source-profile'], 'reviewer');
  assert.deepEqual(page.value.servedQueues, ['appeals', 'review']);
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
      response.end(JSON.stringify({
        items: [{ issuer: 'https://id.example', subject: 'cover-officer' }],
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
    purpose: 'absence_cover',
    personIssuer: 'https://id.example',
    personSubject: 'absent-officer',
    cursor: 'opaque-target-cursor',
    limit: 25,
  });

  const query = new URL(observed.url, 'http://fixture.invalid').searchParams;
  assert.equal(query.get('purpose'), 'absence_cover');
  assert.equal(query.get('personIssuer'), 'https://id.example');
  assert.equal(query.get('personSubject'), 'absent-officer');
  assert.equal(query.get('cursor'), 'opaque-target-cursor');
  assert.equal(query.get('limit'), '25');
  assert.equal(observed.headers['registry-casework-profile'], 'supervisor');
  assert.equal(observed.headers['registry-source-profile'], undefined);
  assert.deepEqual(page.value, {
    items: [{ issuer: 'https://id.example', subject: 'cover-officer' }],
    nextCursor: 'target-next',
    status: 'complete',
  });
});

test('absence list carries the current directory revision for a following write', async (context) => {
  const server = http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(JSON.stringify({ directoryRevision: 12, items: [] }));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const absences = await client.absences('one-call-secret', 'staff');

  assert.equal(absences.value.directoryRevision, 12);
  assert.deepEqual(absences.value.items, []);
});

test('native client preserves the optional held timestamp', async (context) => {
  const itemId = '00000000-0000-4000-8000-000000000001';
  const heldSince = '2026-09-11T03:04:05Z';
  const server = http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      response.writeHead(200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(JSON.stringify({
        itemId,
        subject: { sourceId: 'source-one', kind: 'case', id: 'case-one' },
        occurrenceKind: 'review',
        binding: { sourceRevision: 'revision-1', version: 'version-1', generation: 'generation-1' },
        bindingReference: 'binding-one',
        state: 'claimed',
        queueId: 'review',
        holder: { issuer: 'https://id.example', subject: 'officer-one' },
        heldSince,
        revision: 2,
        firstObservedAt: '2026-09-11T03:00:00Z',
        updatedAt: heldSince,
        actions: [],
      }));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const outcome = await client.getWorkItem('one-call-secret', 'staff', 'reviewer', itemId);

  assert.equal(outcome.value.heldSince, heldSince);
});

test('recovery-pending problem preserves the original attempt reference', async (context) => {
  const originalAttemptId = '10000000-0000-4000-8000-000000000001';
  const server = problemServer('work-item.recovery-pending', {
    'registry-casework-attempt': originalAttemptId,
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient, CaseworkClientError } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  await assert.rejects(
    client.description('one-call-secret', 'staff'),
    (error) => {
      assert.ok(error instanceof CaseworkClientError);
      assert.equal(error.kind, 'problem');
      assert.equal(error.status, 409);
      assert.equal(error.code, 'work-item.recovery-pending');
      assert.equal(
        error.detail,
        'We could not confirm the result of your last action. Recover the original attempt; do not decide again.',
      );
      assert.equal(error.message, error.detail);
      assert.equal(error.originalAttemptId, originalAttemptId);
      return true;
    },
  );
});

test('unknown future problem code stays a problem without recovery metadata', async (context) => {
  const server = problemServer('work-item.future-safe');
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));

  const { port } = server.address();
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${port}/` });
  await assert.rejects(
    client.description('one-call-secret', 'staff'),
    (error) => {
      assert.equal(error.kind, 'problem');
      assert.equal(error.code, 'work-item.future-safe');
      assert.equal(error.detail, undefined);
      assert.equal(error.message, 'Registry Casework refused the request');
      assert.equal(error.originalAttemptId, undefined);
      return true;
    },
  );
});

test('absence creation and reviewed caseload selection preserve exact mutation context', async (context) => {
  const observed = [];
  const itemId = '10000000-0000-4000-8000-000000000001';
  const server = http.createServer((request, response) => {
    let bytes = '';
    request.on('data', (chunk) => { bytes += chunk; });
    request.on('end', () => {
      const body = JSON.parse(bytes);
      observed.push({ path: request.url, headers: request.headers, body });
      const creating = request.url === '/v1/directory/absences';
      const updatingTeam = request.url === '/v1/directory/teams/review-team';
      response.writeHead(creating ? 201 : 200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(JSON.stringify(creating
        ? { ...body, absenceId: itemId, revision: 3 }
        : updatingTeam ? { revision: 4, teams: [] } : [{ itemId, result: 'moved', revision: 8 }]));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const person = { issuer: 'https://idp.example', subject: 'officer' };
  const cover = { issuer: 'https://idp.example', subject: 'cover' };
  const absence = { person, cover, from: '2026-09-14T00:00:00Z', until: '2026-09-19T00:00:00Z' };
  const created = await client.createAbsence('synthetic-token', 'administrator', 2, 'absence-2', absence);
  assert.equal(created.value.revision, 3);
  const request = {
    movement: { from: person, to: cover, reason: 'Cover the absence' },
    items: [{ itemId, expectedRevision: 7 }],
  };
  const moved = await client.applyCaseloadMove('synthetic-token', 'supervisor', 'move-7', request, 'reviewer');
  assert.equal(moved.value[0].result, 'moved');
  assert.equal(moved.value[0].revision, 8);
  assert.equal(observed.length, 2, 'each mutation is sent once');
  assert.equal(observed[0].headers['if-match'], '"2"');
  assert.equal(observed[0].headers['idempotency-key'], 'absence-2');
  assert.equal(observed[0].headers['registry-source-profile'], undefined);
  assert.equal(observed[1].path, '/v1/directory/caseload/apply');
  assert.equal(observed[1].headers['registry-casework-profile'], 'supervisor');
  assert.equal(observed[1].headers['registry-source-profile'], 'reviewer');
  assert.equal(observed[1].headers['idempotency-key'], 'move-7');
  assert.equal(observed[1].headers['if-match'], undefined, 'the reviewed items each carry their own revision');
  assert.deepEqual(observed[1].body, request);
  await assert.rejects(client.applyCaseloadMove('synthetic-token', 'supervisor', 'duplicate', {
    ...request, items: [request.items[0], request.items[0]],
  }), (error) => error.kind === 'invalid_request');
  assert.equal(observed.length, 2, 'ambiguous selections never reach the service');
  const team = { staff: [person], supervisors: [cover], servedQueues: ['review'] };
  assert.equal((await client.updateDirectoryTeam('synthetic-token', 'administrator', 'review-team', 3, 'team-update', team)).value.revision, 4);
  assert.equal(observed.length, 3);
  assert.equal(observed[2].headers['if-match'], '"3"');
  assert.equal(observed[2].headers['idempotency-key'], 'team-update');
  assert.equal(observed[2].headers['registry-source-profile'], undefined);
  assert.deepEqual(observed[2].body, team);

});

test('clock views and recompute expiry preserve source authority and explicit recovery', async (context) => {
  const observed = [];
  const previewId = '10000000-0000-4000-8000-000000000002';
  const server = http.createServer((request, response) => {
    let bytes = '';
    request.on('data', (chunk) => { bytes += chunk; });
    request.on('end', () => {
      const body = bytes ? JSON.parse(bytes) : undefined;
      observed.push({ path: request.url, headers: request.headers, body });
      const expired = request.url.endsWith('/recompute/apply');
      const creating = request.url === '/v1/directory/holidays';
      const readingClocks = request.url.endsWith('/clocks');
      response.writeHead(expired ? 410 : creating ? 201 : 200, {
        'content-type': expired ? 'application/problem+json' : 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(JSON.stringify(expired ? {
        type: 'https://id.registrystack.org/problems/registry-casework/clock/recompute-preview-expired',
        code: 'clock.recompute-preview-expired', title: 'Clock recompute preview expired',
        status: 410, detail: 'Create a new recompute preview and review it before applying.',
        traceId: '0123456789abcdef0123456789abcdef',
      } : creating ? body.document : readingClocks ? [{
        clockOccurrenceId: previewId,
        subject: { sourceId: 'source-one', kind: 'case', id: 'case-one' },
        clockId: 'decision-due', state: 'running',
        policyDigest: `sha256:${'1'.repeat(64)}`,
        calculationGeneration: 1, recomputeGeneration: 0,
        nextEffect: { kind: 'reminder', id: 'at-risk', at: '2026-09-12T00:00:00Z' },
        upcomingEffects: [
          { kind: 'reminder', id: 'at-risk', at: '2026-09-12T00:00:00Z' },
          { kind: 'reassign', id: 'escalate', at: '2026-09-14T00:00:00Z', because: 'Deadline reached', queueId: 'appeals' },
        ],
      }] : []));
    });
  });
  await listen(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  const clocks = (await client.workItemClocks('synthetic-token', 'staff', 'reviewer', previewId)).value;
  assert.equal(clocks[0].nextEffect.id, 'at-risk');
  assert.deepEqual(clocks[0].upcomingEffects.map((effect) => effect.id), ['at-risk', 'escalate']);
  const document = { holidaySet: 'office', revision: 7, dates: ['2026-09-07'] };
  assert.deepEqual((await client.createHolidayRevision('synthetic-token', 'administrator', 'holiday-7', { document })).value, document);
  await assert.rejects(client.applyClockRecompute('synthetic-token', 'administrator', 'apply-reviewed-preview', { previewId }), (error) => {
    assert.equal(error.code, 'clock.recompute-preview-expired');
    assert.equal(error.status, 410);
    assert.equal(error.detail, 'Create a new recompute preview and review it before applying.');
    return true;
  });
  assert.equal(observed.length, 3, 'an expired preview is never retried automatically');
  assert.equal(observed[0].headers['registry-source-profile'], 'reviewer');
  assert.equal(observed[1].headers['registry-source-profile'], undefined);
  assert.equal(observed[2].headers['idempotency-key'], 'apply-reviewed-preview');
  assert.deepEqual(observed[2].body, { previewId });
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
      response.end(JSON.stringify({
        type: `https://id.registrystack.org/problems/registry-casework/${code.replaceAll('.', '/')}`,
        title: code === 'work-item.recovery-pending'
          ? 'Work item recovery pending'
          : code,
        status: 409,
        detail: code === 'work-item.recovery-pending'
          ? 'We could not confirm the result of your last action. Recover the original attempt; do not decide again.'
          : 'Safe detail.',
        code,
        traceId: '0123456789abcdef0123456789abcdef',
      }));
    });
  });
}
