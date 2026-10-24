'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { inspect } = require('node:util');

const TRACEPARENT = '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01';
const TRACE_ID = '0123456789abcdef0123456789abcdef';
const PROBLEM_BASE = 'https://id.registrystack.org/problems/registry-scheduling/';
const HOLD_ID = '0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0e';
const APPOINTMENT_ID = '0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0f';

const REFERENCE = { product: 'casework', recordType: 'review-task', identifier: 'case:1234' };

const ADMISSION = {
  offering: 'registry-update-30',
  start: '2026-10-05T09:00:00Z',
  durationMinutes: 1500,
  resource: 'clerk-2',
  party: { recipients: 1, attendees: 1 },
  policyRevision: 3,
  capabilities: [],
  prerequisites: [],
  externalReferences: [REFERENCE],
};

// The Rust client serializes every optional admission member it does not
// skip, so the wire body names the omitted ones as null.
const ADMISSION_ON_THE_WIRE = { ...ADMISSION, channel: null, duplicateKey: null, windowRevision: null };

const HOLD = {
  holdId: HOLD_ID,
  offering: 'registry-update-30',
  start: '2026-10-05T09:00:00Z',
  end: '2026-10-05T09:30:00Z',
  resource: 'clerk-1',
  units: 1,
  expiresAt: '2026-10-05T08:15:00Z',
  policyRevision: 3,
  externalReferences: [REFERENCE],
};

const APPOINTMENT = {
  appointmentId: APPOINTMENT_ID,
  offering: 'registry-update-30',
  start: '2026-10-05T09:00:00Z',
  end: '2026-10-05T09:30:00Z',
  resource: 'clerk-1',
  units: 1,
  channel: null,
  revision: 1,
  state: 'confirmed',
  policyRevision: 3,
  createdAt: '2026-10-04T08:00:00Z',
  cancelledAt: null,
  externalReferences: [REFERENCE],
};

const CANCELLED = {
  ...APPOINTMENT,
  revision: 2,
  state: 'cancelled',
  cancelledAt: '2026-10-04T09:00:00Z',
};

const ATTENDANCE_REQUEST = {
  observedAppointmentRevision: 7,
  observedRevision: 0,
  state: 'arrived',
  observedAt: '2026-10-05T09:05:00Z',
};
const ATTENDANCE = {
  appointmentId: APPOINTMENT_ID,
  appointmentRevision: 7,
  revision: 3,
  state: 'arrived',
  observedAt: ATTENDANCE_REQUEST.observedAt,
  recordedAt: '2026-10-05T09:06:00Z',
};

test('attendance records the observed visit and correction revision under the caller key', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 200, contentType: 'application/json', document: ATTENDANCE }));
  const { SchedulingClient } = require('../client');
  const result = await new SchedulingClient({ baseUrl }).recordAttendance('token', APPOINTMENT_ID, 'observation-1', ATTENDANCE_REQUEST);
  assert.deepEqual(result.value, ATTENDANCE);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'PUT');
  assert.equal(requests[0].path, `/v1/appointments/${APPOINTMENT_ID}/attendance`);
  assert.equal(requests[0].headers['idempotency-key'], 'observation-1');
  assert.deepEqual(JSON.parse(requests[0].body), ATTENDANCE_REQUEST);
});

test('attendance refuses unknown fields, invalid states and unsafe revisions before I/O', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 200, contentType: 'application/json', document: ATTENDANCE }));
  const { SchedulingClient } = require('../client');
  const client = new SchedulingClient({ baseUrl });
  for (const request of [
    { ...ATTENDANCE_REQUEST, attendees: ['person-1'] },
    { ...ATTENDANCE_REQUEST, state: 'withdrawn' },
    { ...ATTENDANCE_REQUEST, observedRevision: Number.MAX_SAFE_INTEGER + 1 },
  ]) {
    await assert.rejects(async () => client.recordAttendance('token', APPOINTMENT_ID, 'observation-1', request), error => error.kind === 'invalid-request');
  }
  assert.equal(requests.length, 0);
});

test('appointment detail preserves its minimized attendance observation', async (context) => {
  const document = { ...APPOINTMENT, revision: 7, attendance: ATTENDANCE };
  const { baseUrl } = await serve(context, () => ({ status: 200, contentType: 'application/json', document }));
  const { SchedulingClient } = require('../client');
  assert.deepEqual((await new SchedulingClient({ baseUrl }).getAppointment('token', APPOINTMENT_ID)).value, document);
});

test('arrival catalogue publishes every window an offering serves', async (context) => {
  const windows = [
    { id: 'day-one', revision: 1, start: '2026-10-05T09:00:00Z', end: '2026-10-05T11:00:00Z', units: 12 },
    { id: 'day-two', revision: 2, start: '2026-10-12T09:00:00Z', end: '2026-10-12T11:00:00Z', units: 8 },
  ];
  const offering = { id: 'distribution', service: 'service', label: 'Distribution', mode: 'arrival-window', location: 'hall', leadTimeMinutes: 1, horizonDays: 30, cancellationCutoffMinutes: 0, durationMinutes: null, bufferBeforeMinutes: null, bufferAfterMinutes: null, startIncrementMinutes: null, maxRecipients: null, window: null, windows, reminders: [], requiresCapabilities: [], prerequisites: [] };
  const page = { items: [offering], nextCursor: null };
  const { baseUrl } = await serve(context, () => ({ status: 200, contentType: 'application/json', document: page }));
  const { SchedulingClient } = require('../client');
  assert.deepEqual((await new SchedulingClient({ baseUrl }).listOfferings('token')).value, page);
});

async function serve(context, answer) {
  const requests = [];
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      const url = new URL(request.url, 'http://127.0.0.1');
      requests.push({
        method: request.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
        headers: request.headers,
        body,
      });
      const { status, contentType, document } = answer(request, url);
      const headers = { traceparent: TRACEPARENT };
      if (contentType) headers['content-type'] = contentType;
      response.writeHead(status, headers);
      response.end(document === undefined ? '' : JSON.stringify(document));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));
  return { baseUrl: `http://127.0.0.1:${server.address().port}/`, requests };
}

function answered(status, document) {
  return { status, contentType: 'application/json', document };
}

function problem(code, status, title, detail) {
  return {
    status,
    contentType: 'application/problem+json',
    document: {
      type: `${PROBLEM_BASE}${code.replace('.', '/')}`,
      title,
      status,
      detail,
      code,
      traceId: TRACE_ID,
    },
  };
}

async function client(context, answer) {
  const served = await serve(context, answer);
  const { SchedulingClient } = require('../client');
  return { ...served, client: new SchedulingClient({ baseUrl: served.baseUrl }) };
}

async function refusedBeforeAnyRequest(context, calls) {
  const { client: scheduling, requests } = await client(context, () => ({ status: 500 }));
  const { SchedulingClientError } = require('../client');
  for (const call of calls) {
    await assert.rejects(Promise.resolve().then(() => call(scheduling)), (error) => {
      assert.ok(error instanceof SchedulingClientError, `${error}`);
      assert.equal(error.kind, 'invalid-request');
      return true;
    });
  }
  assert.equal(requests.length, 0);
}

test('facade exports the maintained client and mapped error', () => {
  const exported = require('../client');
  assert.equal(typeof exported.SchedulingClient, 'function');
  assert.equal(typeof exported.SchedulingClientError, 'function');
});

test('getScheduling answers the deployment and policy with the answered trace', async (context) => {
  const service = { schedulingId: 'scheduling-1', policyRevision: 3, policyDigest: 'sha256:abc' };
  const { client: scheduling, requests } = await client(context, () => answered(200, service));

  assert.deepEqual(
    await scheduling.getScheduling('one-call-secret'),
    { kind: 'complete', value: service, traceId: TRACE_ID },
  );
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'GET');
  assert.equal(requests[0].path, '/v1/scheduling');
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
  assert.equal(requests[0].headers.accept, 'application/json');
});

test('catalogue listings carry the caller cursor and answer the page', async (context) => {
  const pages = {
    '/v1/services': { items: [{ id: 'registry-update', label: 'Registry update' }], nextCursor: 'next-1' },
    '/v1/offerings': {
      items: [{
        id: 'registry-update-30',
        service: 'registry-update',
        label: 'Registry update, 30 minutes',
        mode: 'exact-time',
        location: 'office-1',
        pool: 'clerks',
        leadTimeMinutes: 60,
        horizonDays: 30,
        cancellationCutoffMinutes: 120,
        durationMinutes: 30,
        durationSelection: { minimumMinutes: 15, maximumMinutes: 60, incrementMinutes: 15 },
        openingCoverage: 'occupied-interval',
        allowResourceSelection: true,
        bufferBeforeMinutes: null,
        bufferAfterMinutes: 5,
        startIncrementMinutes: 30,
        maxRecipients: 1,
        window: null,
        reminders: [{ minutesBefore: 1440 }],
        requiresCapabilities: [],
        prerequisites: [],
      }],
      nextCursor: null,
    },
    '/v1/resources': {
      items: [{ resourceId: 'clerk-1', pool: 'clerks', capabilities: ['registry'], available: true }],
      nextCursor: null,
    },
    '/v1/locations': { items: [{ locationId: 'office-1', timezone: 'Africa/Nairobi' }], nextCursor: null },
  };
  const { client: scheduling, requests } = await client(context, (_, url) => answered(200, pages[url.pathname]));

  assert.deepEqual(await scheduling.listServices('one-call-secret'), {
    kind: 'complete', value: pages['/v1/services'], traceId: TRACE_ID,
  });
  assert.deepEqual((await scheduling.listOfferings('one-call-secret', 'cursor-2')).value, pages['/v1/offerings']);
  assert.deepEqual((await scheduling.listResources('one-call-secret', null)).value, pages['/v1/resources']);
  assert.deepEqual((await scheduling.listLocations('one-call-secret', undefined)).value, pages['/v1/locations']);
  assert.deepEqual(
    requests.map(({ method, path, query }) => [method, path, query]),
    [
      ['GET', '/v1/services', {}],
      ['GET', '/v1/offerings', { cursor: 'cursor-2' }],
      ['GET', '/v1/resources', {}],
      ['GET', '/v1/locations', {}],
    ],
  );
});

test('availability carries the offering, interval and page bounds and answers both entry kinds', async (context) => {
  const page = {
    items: [
      { kind: 'slot', start: '2026-10-05T09:00:00Z', end: '2026-10-05T09:30:00Z', free: 2 },
      {
        kind: 'window',
        window: 'morning',
        start: '2026-10-05T08:00:00Z',
        end: '2026-10-05T12:00:00Z',
        remaining: 7,
        channelRemaining: null,
      },
    ],
    nextCursor: 'next-1',
  };
  const { client: scheduling, requests } = await client(context, () => answered(200, page));

  const outcome = await scheduling.availability('one-call-secret', 'registry-update-30', {
    start: '2026-10-05T08:00:00Z',
    end: '2026-10-05T12:00:00+00:00',
    cursor: 'cursor-1',
    limit: 25,
    durationMinutes: 1500,
    resource: 'clerk-2',
  });

  assert.deepEqual(outcome, { kind: 'complete', value: page, traceId: TRACE_ID });
  assert.equal(requests[0].method, 'GET');
  assert.equal(requests[0].path, '/v1/availability');
  assert.deepEqual(requests[0].query, {
    offering: 'registry-update-30',
    start: '2026-10-05T08:00:00Z',
    end: '2026-10-05T12:00:00Z',
    cursor: 'cursor-1',
    limit: '25',
    durationMinutes: '1500',
    resource: 'clerk-2',
  });

  await scheduling.availability('one-call-secret', 'registry-update-30');
  assert.deepEqual(requests[1].query, { offering: 'registry-update-30' });
});

test('availability refuses a selector, instant, or page bound outside its grammar before any request', async (context) => {
  await refusedBeforeAnyRequest(context, [
    (scheduling) => scheduling.availability('one-call-secret', 'Registry_Update'),
    (scheduling) => scheduling.availability('one-call-secret', 'registry/update'),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { start: 'tomorrow' }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { end: '2026-10-05' }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { cursor: '' }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { limit: 0 }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { limit: -1 }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { limit: 2.5 }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { durationMinutes: 0 }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { durationMinutes: 10081 }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { durationMinutes: -1 }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { durationMinutes: 1.5 }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { durationMinutes: true }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { resource: 'clerk/2' }),
    (scheduling) => scheduling.availability('one-call-secret', 'registry-update-30', { offering: 'other' }),
  ]);
});

test('explain carries the offering and start and answers the explanation', async (context) => {
  const explanation = {
    offering: 'registry-update-30',
    start: '2026-10-05T09:00:00Z',
    publicCode: 'capacity.exhausted',
    explanation: 'Every clerk is booked.',
  };
  const { client: scheduling, requests } = await client(context, () => answered(200, explanation));

  const outcome = await scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05T12:00:00+03:00');

  assert.deepEqual(outcome, { kind: 'complete', value: explanation, traceId: TRACE_ID });
  assert.equal(requests[0].path, '/v1/availability/explain');
  assert.deepEqual(requests[0].query, { offering: 'registry-update-30', start: '2026-10-05T09:00:00Z' });
  await scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05T12:00:00+03:00', {
    durationMinutes: 45,
    resource: 'clerk-2',
  });
  assert.deepEqual(requests[1].query, {
    offering: 'registry-update-30',
    start: '2026-10-05T09:00:00Z',
    durationMinutes: '45',
    resource: 'clerk-2',
  });
});

test('explain refuses an instant that is not RFC 3339 before any request', async (context) => {
  await refusedBeforeAnyRequest(context, [
    (scheduling) => scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05 09:00'),
    (scheduling) => scheduling.explain('one-call-secret', 'registry-update-30', ''),
    (scheduling) => scheduling.explain('one-call-secret', 'Registry', '2026-10-05T09:00:00Z'),
    (scheduling) => scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05T09:00:00Z', { durationMinutes: 0 }),
    (scheduling) => scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05T09:00:00Z', { durationMinutes: 10081 }),
    (scheduling) => scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05T09:00:00Z', { durationMinutes: -1 }),
    (scheduling) => scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05T09:00:00Z', { durationMinutes: 1.5 }),
    (scheduling) => scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05T09:00:00Z', { durationMinutes: true }),
    (scheduling) => scheduling.explain('one-call-secret', 'registry-update-30', '2026-10-05T09:00:00Z', { resource: 'clerk/2' }),
  ]);
});

test('createHold carries the caller idempotency key and answers the hold', async (context) => {
  const { client: scheduling, requests } = await client(context, () => answered(201, HOLD));

  const outcome = await scheduling.createHold('one-call-secret', 'hold-2026-10-05-0001', ADMISSION);

  assert.deepEqual(outcome, { kind: 'complete', value: HOLD, traceId: TRACE_ID });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/v1/holds');
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
  assert.equal(requests[0].headers['idempotency-key'], 'hold-2026-10-05-0001');
  assert.equal(requests[0].headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[0].body), ADMISSION_ON_THE_WIRE);
});

test('mutations refuse a key outside the header grammar before any request', async (context) => {
  const calls = [];
  for (const key of ['', 'two words', 'café', 'k'.repeat(129)]) {
    calls.push((scheduling) => scheduling.createHold('one-call-secret', key, ADMISSION));
    calls.push((scheduling) => scheduling.createAppointment('one-call-secret', key, { hold: HOLD_ID }));
    calls.push((scheduling) => scheduling.rescheduleAppointment(
      'one-call-secret', APPOINTMENT_ID, key, { observedRevision: 1, admission: ADMISSION },
    ));
    calls.push((scheduling) => scheduling.cancelAppointment(
      'one-call-secret', APPOINTMENT_ID, key, { observedRevision: 1 },
    ));
  }
  await refusedBeforeAnyRequest(context, calls);
});

test('resource holds preserve manager and party references without invented people counts', async (context) => {
  const partyReferences = [{ role: 'organization', reference: REFERENCE }];
  const answer = { ...HOLD, manager: 'schedulingManager', partyReferences };
  const { client: scheduling, requests } = await client(context, () => answered(201, answer));
  const request = { ...ADMISSION, manager: 'schedulingManager', partyReferences };
  delete request.party;
  const outcome = await scheduling.createHold('synthetic-token', 'room-hold', request);
  assert.deepEqual(outcome.value, answer);
  assert.deepEqual(JSON.parse(requests[0].body), {
    ...request, channel: null, duplicateKey: null, windowRevision: null,
  });
  assert.equal(Object.hasOwn(JSON.parse(requests[0].body), 'party'), false);
});

test('capacity preview sends only a physical bundle and no mutation key', async (context) => {
  const request = { offering: 'room', start: ADMISSION.start, additionalAllocations: [{ offering: 'chairs', units: 30 }] };
  const answer = { offering: 'room', start: ADMISSION.start, end: HOLD.end, capacityAvailable: true };
  const { client: scheduling, requests } = await client(context, () => answered(200, answer));
  assert.deepEqual((await scheduling.previewAvailability('synthetic-token', request)).value, answer);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/v1/availability/preview');
  assert.equal(requests[0].headers['idempotency-key'], undefined);
  assert.deepEqual(JSON.parse(requests[0].body), request);
});

test('capacity preview refuses identity assertions and unbounded physical inputs before I/O', async (context) => {
  const request = { offering: 'room', start: ADMISSION.start };
  await refusedBeforeAnyRequest(context, [
    (scheduling) => scheduling.previewAvailability('synthetic-token', { ...request, manager: 'schedulingManager' }),
    (scheduling) => scheduling.previewAvailability('synthetic-token', { ...request, resourceUnits: 0 }),
    (scheduling) => scheduling.previewAvailability('synthetic-token', { ...request, additionalAllocations: Array.from({ length: 16 }, () => ({ offering: 'chairs' })) }),
  ]);
});

function busySnapshot() {
  return {
    expectedRevision: 0, observedAt: '2026-10-05T08:00:00Z',
    freshUntil: '2026-10-05T09:00:00Z', status: 'fresh',
    coverage: { start: '2026-10-05T00:00:00Z', end: '2026-10-06T00:00:00Z', resources: ['room-a'] },
    records: [{ externalUid: 'event-1', externalRevision: 'v1', resource: 'room-a', start: '2026-10-05T10:00:00Z', end: '2026-10-05T11:00:00Z' }],
  };
}

test('source busy preview and apply select one profile and preserve CAS and minimized impacts', async (context) => {
  const request = busySnapshot();
  const common = { sourceId: 'calendar-a', requestDigest: 'sha256:abc', added: 1, changed: 0, deleted: 0, retainedOutsideAuthority: 0, retainedAcrossCoverageBoundary: 0, impacts: { total: 1, detailsAvailable: false, truncated: true } };
  const preview = { ...common, expectedRevision: 0, currentRevision: 0 };
  const applied = { ...common, kind: 'applied', revision: 1 };
  const { client: scheduling, requests } = await client(context, (_, url) => answered(200, url.pathname.endsWith('/preview') ? preview : applied));
  assert.deepEqual((await scheduling.previewSourceBusy('synthetic-token', 'calendar-main', request)).value, preview);
  assert.deepEqual((await scheduling.applySourceBusy('synthetic-token', 'calendar-main', request)).value, applied);
  assert.deepEqual(requests.map(({ path }) => path), ['/v1/source-busy/preview', '/v1/source-busy/apply']);
  for (const sent of requests) {
    assert.equal(sent.method, 'POST');
    assert.deepEqual(sent.query, { profile: 'calendar-main' });
    assert.equal(sent.headers['idempotency-key'], undefined);
    assert.deepEqual(JSON.parse(sent.body), request);
  }
});

test('source busy rejects unbounded, inconsistent and descriptive data before I/O', async (context) => {
  const request = busySnapshot();
  await refusedBeforeAnyRequest(context, [
    (scheduling) => scheduling.previewSourceBusy('synthetic-token', '../other', request),
    (scheduling) => scheduling.applySourceBusy('synthetic-token', 'calendar-main', { ...request, sourceId: 'other-source' }),
    (scheduling) => scheduling.applySourceBusy('synthetic-token', 'calendar-main', { ...request, records: [{ ...request.records[0], attendees: ['private'] }] }),
    (scheduling) => scheduling.applySourceBusy('synthetic-token', 'calendar-main', { ...request, records: Array.from({ length: 4097 }, () => request.records[0]) }),
    (scheduling) => scheduling.applySourceBusy('synthetic-token', 'calendar-main', { ...request, coverage: { ...request.coverage, resources: [] } }),
    (scheduling) => scheduling.applySourceBusy('synthetic-token', 'calendar-main', { ...request, status: 'unavailable' }),
  ]);
});

test('source busy apply leaves an uncertain outcome for explicit same-body recovery without resending', async (context) => {
  const { client: scheduling, requests } = await client(context, () => ({ status: 503 }));
  await assert.rejects(scheduling.applySourceBusy('synthetic-token', 'calendar-main', busySnapshot()), (error) => {
    assert.equal(error.outcomeUnknown, true);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('counted bundle holds retain every concrete allocation', async (context) => {
  const allocations = [
    { requirement: { kind: 'primary' }, offering: ADMISSION.offering, resource: 'clerk-2', units: 2, occupiedStart: HOLD.start, occupiedEnd: HOLD.end },
    { requirement: { kind: 'additional', index: 0 }, offering: 'chairs', resource: 'chairs-a', units: 30, occupiedStart: HOLD.start, occupiedEnd: HOLD.end },
  ];
  const answer = { ...HOLD, units: 2, allocations };
  const { client: scheduling, requests } = await client(context, () => answered(201, answer));
  const request = { ...ADMISSION, resourceUnits: 2, additionalAllocations: [{ offering: 'chairs', resource: 'chairs-a', units: 30 }] };
  delete request.party;
  const outcome = await scheduling.createHold('synthetic-token', 'bundle-hold', request);
  assert.deepEqual(outcome.value, answer);
  assert.deepEqual(JSON.parse(requests[0].body), {
    ...request, channel: null, duplicateKey: null, windowRevision: null,
  });
});

test('createHold refuses an undeclared admission member or an unsafe integer before any request', async (context) => {
  const { client: scheduling, requests } = await client(context, () => ({ status: 500 }));
  const { SchedulingClientError } = require('../client');

  await assert.rejects(
    scheduling.createHold('one-call-secret', 'key-1', { ...ADMISSION, priority: 'high' }),
    (error) => error instanceof SchedulingClientError && error.kind === 'invalid-request',
  );
  await assert.rejects(
    scheduling.createHold('one-call-secret', 'key-1', { ...ADMISSION, policyRevision: -1 }),
    (error) => error instanceof SchedulingClientError && error.kind === 'invalid-request',
  );
  // The facade refuses an unsafe integer synchronously, as Messaging's does.
  assert.throws(
    () => scheduling.createHold('one-call-secret', 'key-1', { ...ADMISSION, policyRevision: Number.MAX_SAFE_INTEGER + 1 }),
    (error) => error instanceof SchedulingClientError && error.kind === 'invalid-request',
  );
  const { SchedulingClient: NativeSchedulingClient } = require('../index');
  const native = new NativeSchedulingClient({ baseUrl: 'http://127.0.0.1:9/' });
  await assert.rejects(
    native.createHold('one-call-secret', 'key-1', { ...ADMISSION, policyRevision: Number.MAX_SAFE_INTEGER + 1 }),
    (error) => JSON.parse(error.message).kind === 'invalid-request',
  );
  assert.equal(requests.length, 0);
});

test('releaseHold deletes the hold and completes without a value', async (context) => {
  const { client: scheduling, requests } = await client(context, () => ({ status: 204 }));

  assert.deepEqual(
    await scheduling.releaseHold('one-call-secret', HOLD_ID),
    { kind: 'complete', value: null, traceId: TRACE_ID },
  );
  assert.equal(requests[0].method, 'DELETE');
  assert.equal(requests[0].path, `/v1/holds/${HOLD_ID}`);
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
  assert.equal(requests[0].headers['idempotency-key'], undefined);
});

test('route identifiers stay one path segment and are refused otherwise before any request', async (context) => {
  const calls = [];
  for (const identifier of ['', '../ready', 'appt/1', 'appt%2F1', 'space id', 'x'.repeat(129)]) {
    calls.push((scheduling) => scheduling.releaseHold('one-call-secret', identifier));
    calls.push((scheduling) => scheduling.getAppointment('one-call-secret', identifier));
    calls.push((scheduling) => scheduling.appointmentHistory('one-call-secret', identifier));
    calls.push((scheduling) => scheduling.cancelAppointment('one-call-secret', identifier, 'key-1', { observedRevision: 1 }));
  }
  await refusedBeforeAnyRequest(context, calls);
});

test('createAppointment confirms a hold and answers the appointment', async (context) => {
  const { client: scheduling, requests } = await client(context, () => answered(201, APPOINTMENT));

  const outcome = await scheduling.createAppointment('one-call-secret', 'confirm-1', { hold: HOLD_ID });

  assert.deepEqual(outcome, { kind: 'complete', value: APPOINTMENT, traceId: TRACE_ID });
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/v1/appointments');
  assert.equal(requests[0].headers['idempotency-key'], 'confirm-1');
  assert.deepEqual(JSON.parse(requests[0].body), { hold: HOLD_ID, admission: null });
});

test('createAppointment books directly from an admission', async (context) => {
  const { client: scheduling, requests } = await client(context, () => answered(201, APPOINTMENT));

  await scheduling.createAppointment('one-call-secret', 'direct-1', { admission: ADMISSION });

  assert.deepEqual(JSON.parse(requests[0].body), { hold: null, admission: ADMISSION_ON_THE_WIRE });
});

test('getAppointment and appointmentHistory read the appointment the runtime serves', async (context) => {
  const history = {
    items: [{
      eventId: 'event-1',
      kind: 'appointment.confirmed',
      revision: 1,
      occurredAt: '2026-10-04T08:00:00Z',
      actor: null,
      detail: { channel: null, units: 1 },
    }],
    nextCursor: null,
  };
  const { client: scheduling, requests } = await client(context, (_, url) => (
    url.pathname.endsWith('/history') ? answered(200, history) : answered(200, APPOINTMENT)
  ));

  assert.deepEqual(
    await scheduling.getAppointment('one-call-secret', APPOINTMENT_ID),
    { kind: 'complete', value: APPOINTMENT, traceId: TRACE_ID },
  );
  assert.deepEqual((await scheduling.appointmentHistory('one-call-secret', APPOINTMENT_ID, 'cursor-1')).value, history);
  assert.deepEqual(
    requests.map(({ method, path, query }) => [method, path, query]),
    [
      ['GET', `/v1/appointments/${APPOINTMENT_ID}`, {}],
      ['GET', `/v1/appointments/${APPOINTMENT_ID}/history`, { cursor: 'cursor-1' }],
    ],
  );
});

test('listAppointments selects by external reference and carries the page bounds', async (context) => {
  const page = { items: [APPOINTMENT], nextCursor: null };
  const { client: scheduling, requests } = await client(context, () => answered(200, page));

  const outcome = await scheduling.listAppointments('one-call-secret', REFERENCE, { cursor: 'cursor-1', limit: 10 });

  assert.deepEqual(outcome, { kind: 'complete', value: page, traceId: TRACE_ID });
  assert.equal(requests[0].path, '/v1/appointments');
  assert.deepEqual(requests[0].query, {
    externalReferenceProduct: 'casework',
    externalReferenceRecordType: 'review-task',
    externalReferenceIdentifier: 'case:1234',
    cursor: 'cursor-1',
    limit: '10',
  });
});

test('listOperationalAppointments carries one role-bounded work-list query', async (context) => {
  const page = {
    items: [{
      appointmentId: APPOINTMENT_ID,
      revision: 2,
      service: 'registry-update',
      location: 'office-1',
      offering: 'registry-update-30',
      state: 'confirmed',
      displayedStart: '2026-10-05T09:00:00Z',
      displayedEnd: '2026-10-06T10:00:00Z',
      resource: 'clerk-2',
      units: 1,
    }],
    nextCursor: 'next',
  };
  const { client: scheduling, requests } = await client(context, () => answered(200, page));
  const query = {
    service: 'registry-update',
    location: 'office-1',
    start: '2026-10-05T09:00:00Z',
    end: '2026-10-07T09:00:00Z',
    timeBasis: 'occupied',
    offering: 'registry-update-30',
    state: 'confirmed',
    resource: 'clerk-2',
    externalReference: REFERENCE,
    profile: 'desk',
    cursor: 'next',
    limit: 25,
  };
  assert.deepEqual(await scheduling.listOperationalAppointments('one-call-secret', query), {
    kind: 'complete', value: page, traceId: TRACE_ID,
  });
  assert.deepEqual(requests[0].query, {
    service: 'registry-update',
    location: 'office-1',
    start: '2026-10-05T09:00:00Z',
    end: '2026-10-07T09:00:00Z',
    timeBasis: 'occupied',
    offering: 'registry-update-30',
    state: 'confirmed',
    resource: 'clerk-2',
    externalReferenceProduct: 'casework',
    externalReferenceRecordType: 'review-task',
    externalReferenceIdentifier: 'case:1234',
    profile: 'desk',
    cursor: 'next',
    limit: '25',
  });
});

test('listOperationalAppointments refuses an invalid role query before any request', async (context) => {
  const query = {
    service: 'registry-update',
    location: 'office-1',
    start: '2026-10-05T09:00:00Z',
    end: '2026-10-07T09:00:00Z',
    timeBasis: 'occupied',
  };
  await refusedBeforeAnyRequest(context, [
    (scheduling) => scheduling.listOperationalAppointments('one-call-secret', { ...query, resource: 'clerk/2' }),
    (scheduling) => scheduling.listOperationalAppointments('one-call-secret', { ...query, end: query.start }),
    (scheduling) => scheduling.listOperationalAppointments('one-call-secret', { ...query, limit: 0 }),
    (scheduling) => scheduling.listOperationalAppointments('one-call-secret', { ...query, extra: 'x' }),
  ]);
});

test('listAppointments refuses a reference or page bound outside its grammar before any request', async (context) => {
  await refusedBeforeAnyRequest(context, [
    (scheduling) => scheduling.listAppointments('one-call-secret', { ...REFERENCE, product: 'Casework' }),
    (scheduling) => scheduling.listAppointments('one-call-secret', { ...REFERENCE, identifier: ' ' }),
    (scheduling) => scheduling.listAppointments('one-call-secret', { ...REFERENCE, extra: 'x' }),
    (scheduling) => scheduling.listAppointments('one-call-secret', REFERENCE, { limit: 0 }),
    (scheduling) => scheduling.listAppointments('one-call-secret', REFERENCE, { cursor: 'x'.repeat(4097) }),
  ]);
});

test('rescheduleAppointment and cancelAppointment carry the observed revision and the caller key', async (context) => {
  const { client: scheduling, requests } = await client(context, (_, url) => (
    url.pathname.endsWith('/cancel') ? answered(200, CANCELLED) : answered(200, APPOINTMENT)
  ));

  const moved = await scheduling.rescheduleAppointment(
    'one-call-secret', APPOINTMENT_ID, 'move-1', { observedRevision: 1, admission: ADMISSION },
  );
  const cancelled = await scheduling.cancelAppointment(
    'one-call-secret', APPOINTMENT_ID, 'cancel-1', { observedRevision: 2, reason: 'moved away' },
  );

  assert.deepEqual(moved, { kind: 'complete', value: APPOINTMENT, traceId: TRACE_ID });
  assert.deepEqual(cancelled, { kind: 'complete', value: CANCELLED, traceId: TRACE_ID });
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, `/v1/appointments/${APPOINTMENT_ID}/reschedule`);
  assert.equal(requests[0].headers['idempotency-key'], 'move-1');
  assert.deepEqual(JSON.parse(requests[0].body), { observedRevision: 1, admission: ADMISSION_ON_THE_WIRE });
  assert.equal(requests[1].method, 'POST');
  assert.equal(requests[1].path, `/v1/appointments/${APPOINTMENT_ID}/cancel`);
  assert.equal(requests[1].headers['idempotency-key'], 'cancel-1');
  assert.deepEqual(JSON.parse(requests[1].body), { observedRevision: 2, reason: 'moved away' });
});

test('a capacity refusal is the mapped problem with its pinned title and detail', async (context) => {
  const { client: scheduling } = await client(context, () => problem(
    'capacity.exhausted',
    409,
    'Capacity exhausted',
    'The supply is fully committed for the requested interval. Choose another time.',
  ));
  const { SchedulingClientError } = require('../client');

  await assert.rejects(scheduling.createHold('one-call-secret', 'key-1', ADMISSION), (error) => {
    assert.ok(error instanceof SchedulingClientError);
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 409);
    assert.equal(error.code, 'capacity.exhausted');
    assert.equal(error.title, 'Capacity exhausted');
    assert.equal(error.detail, 'The supply is fully committed for the requested interval. Choose another time.');
    assert.equal(error.message, error.detail);
    assert.equal(error.traceId, TRACE_ID);
    assert.equal('retryAfterSeconds' in error, false);
    return true;
  });
});

test('a stale revision is the mapped precondition problem', async (context) => {
  const { client: scheduling } = await client(context, () => problem(
    'precondition.failed',
    412,
    'Precondition failed',
    'The appointment changed since you loaded it. Reload and try again.',
  ));

  await assert.rejects(
    scheduling.cancelAppointment('one-call-secret', APPOINTMENT_ID, 'cancel-1', { observedRevision: 1 }),
    (error) => {
      assert.equal(error.kind, 'problem');
      assert.equal(error.status, 412);
      assert.equal(error.code, 'precondition.failed');
      return true;
    },
  );
});

test('a code outside the closed vocabulary is a protocol failure, not a problem', async (context) => {
  const { client: scheduling } = await client(context, () => problem('capacity.future', 409, 'Future', 'Future.'));

  await assert.rejects(scheduling.getAppointment('one-call-secret', APPOINTMENT_ID), (error) => {
    assert.equal(error.kind, 'protocol');
    assert.equal(error.status, 409);
    assert.equal(error.protocolFailure, 'problem');
    assert.equal(error.code, undefined);
    return true;
  });
});

test('an answered integer outside the JavaScript safe range is a protocol failure', async (context) => {
  const server = http.createServer((request, response) => {
    response.writeHead(200, { traceparent: TRACEPARENT, 'content-type': 'application/json' });
    response.end('{"schedulingId":"scheduling-1","policyRevision":9007199254740993,"policyDigest":"sha256:abc"}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const { SchedulingClient } = require('../client');
  const scheduling = new SchedulingClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });

  await assert.rejects(scheduling.getScheduling('one-call-secret'), (error) => {
    assert.equal(error.kind, 'protocol');
    return true;
  });
});

test('an unreachable service is a transport failure', async () => {
  const server = http.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  const { SchedulingClient } = require('../client');
  const scheduling = new SchedulingClient({ baseUrl: `http://127.0.0.1:${port}/`, connectTimeoutMilliseconds: 1000 });

  await assert.rejects(scheduling.getScheduling('one-call-secret'), (error) => {
    assert.equal(error.kind, 'transport');
    assert.equal(typeof error.transportKind, 'string');
    return true;
  });
});

test('an invalid configuration is a configuration error', () => {
  const { SchedulingClient, SchedulingClientError } = require('../client');
  for (const config of [{ baseUrl: 'not a url' }, { baseUrl: 'https://scheduling.example/', maximumResponseBytes: 0 }]) {
    assert.throws(() => new SchedulingClient(config), (error) => {
      assert.ok(error instanceof SchedulingClientError);
      assert.equal(error.kind, 'configuration');
      return true;
    });
  }
});

test('a configuration member outside the declared set is a configuration error', () => {
  const { SchedulingClient, SchedulingClientError } = require('../client');
  const baseUrl = 'https://scheduling.example/';
  assert.ok(new SchedulingClient({
    baseUrl,
    attemptTimeoutMilliseconds: 1500,
    connectTimeoutMilliseconds: 1500,
    maximumResponseBytes: 1500,
    userAgent: 'scheduling-test',
    maximumMutationRetries: 1,
  }));
  for (const member of ['maxMutationRetries', 'maximumMutationRetry', 'requestTimeoutMilliseconds', 'attemptTimeoutMs', 'maxResponseBytes', 'authorization']) {
    for (const value of [0, null]) {
      assert.throws(() => new SchedulingClient({ baseUrl, [member]: value }), (error) => {
        assert.ok(error instanceof SchedulingClientError, member);
        assert.equal(error.kind, 'configuration', member);
        assert.equal(error.outcomeUnknown, false);
        return true;
      });
    }
  }
});

test('null is not an omission for non-nullable JavaScript configuration', () => {
  const { SchedulingClient, SchedulingClientError } = require('../client');
  for (const member of [
    'attemptTimeoutMilliseconds',
    'connectTimeoutMilliseconds',
    'maximumResponseBytes',
    'userAgent',
    'trustedRootCertificates',
    'maximumMutationRetries',
  ]) {
    assert.throws(
      () => new SchedulingClient({ baseUrl: 'https://scheduling.example/', [member]: null }),
      (error) => {
        assert.ok(error instanceof SchedulingClientError, member);
        assert.equal(error.kind, 'configuration', member);
        assert.equal(error.outcomeUnknown, false, member);
        return true;
      },
    );
  }
});

test('a timeout or response bound that is not a whole number in range is a configuration error', () => {
  const { SchedulingClient, SchedulingClientError } = require('../client');
  const baseUrl = 'https://scheduling.example/';
  // A 32-bit conversion would read -1 as 4294967295, 1.5 as 1, 2 ** 32 as 0,
  // and 2 ** 32 + 1024 as 1024, so each value is checked whole.
  const accepted = {
    attemptTimeoutMilliseconds: [1500, 2 ** 32],
    connectTimeoutMilliseconds: [1500, 2 ** 32],
    maximumResponseBytes: [1500],
  };
  const refused = {
    attemptTimeoutMilliseconds: [true, false, -1, 1.5, '1500'],
    connectTimeoutMilliseconds: [true, false, -1, 1.5, '1500'],
    maximumResponseBytes: [true, false, -1, 1.5, 2 ** 32, 2 ** 32 + 1024, '1500'],
  };
  for (const [field, values] of Object.entries(accepted)) {
    for (const value of values) {
      assert.ok(new SchedulingClient({ baseUrl, [field]: value }), `${field} ${value}`);
    }
  }
  for (const [field, values] of Object.entries(refused)) {
    for (const value of values) {
      assert.throws(() => new SchedulingClient({ baseUrl, [field]: value }), (error) => {
        assert.ok(error instanceof SchedulingClientError, `${field} ${value}`);
        assert.equal(error.kind, 'configuration', `${field} ${value}`);
        assert.equal(error.outcomeUnknown, false);
        return true;
      });
    }
  }
});

test('a configuration value the sanitizer refuses is a configuration error', () => {
  const { SchedulingClient, SchedulingClientError } = require('../client');
  const baseUrl = 'https://scheduling.example/';
  for (const [label, config] of [
    ['an unsafe integer', { baseUrl, attemptTimeoutMilliseconds: Number.MAX_SAFE_INTEGER + 1 }],
    ['a non-finite number', { baseUrl, maximumResponseBytes: Infinity }],
    ['a binary trust bundle', { baseUrl, trustedRootCertificates: Buffer.from('not PEM text') }],
    ['an undefined member', { baseUrl, userAgent: undefined }],
    ['a function', { baseUrl, userAgent: () => 'scheduling-test' }],
    ['a date', { baseUrl, attemptTimeoutMilliseconds: new Date(0) }],
    ['a proxy', new Proxy({ baseUrl }, {})],
    ['no configuration', undefined],
  ]) {
    assert.throws(() => new SchedulingClient(config), (error) => {
      assert.ok(error instanceof SchedulingClientError, label);
      assert.equal(error.kind, 'configuration', label);
      assert.equal(error.outcomeUnknown, false, label);
      return true;
    });
  }
});

test('bearer tokens never reach error text, fields, or inspection', async (context) => {
  const secret = 'bad token with spaces canary';
  const answeredToken = 'answered-token-canary';
  const { client: scheduling } = await client(context, () => problem(
    'authentication.refused',
    401,
    'Authentication refused',
    'The bearer credential is missing, invalid, or expired. Sign in again.',
  ));

  const failures = [];
  await scheduling.getScheduling(secret).catch((error) => failures.push(error));
  await scheduling.createHold(answeredToken, 'key-1', ADMISSION).catch((error) => failures.push(error));
  await scheduling.getAppointment(answeredToken, APPOINTMENT_ID).catch((error) => failures.push(error));
  await scheduling.releaseHold(answeredToken, HOLD_ID).catch((error) => failures.push(error));
  await scheduling.listAppointments(answeredToken, REFERENCE).catch((error) => failures.push(error));
  await scheduling.cancelAppointment(secret, APPOINTMENT_ID, 'key-1', { observedRevision: 1 })
    .catch((error) => failures.push(error));

  assert.equal(failures.length, 6);
  assert.equal(failures[0].kind, 'invalid-request');
  assert.equal(failures[1].kind, 'problem');
  assert.equal(failures[1].code, 'authentication.refused');
  for (const error of failures) {
    const rendered = [
      error.message,
      error.stack,
      inspect(error, { depth: 8, showHidden: true }),
      JSON.stringify(error),
    ].join('\n');
    assert.doesNotMatch(rendered, /canary/);
  }
  assert.doesNotMatch(inspect(scheduling, { depth: 8, showHidden: true }), /canary/);
});

const UNAVAILABLE = problem(
  'service.unavailable',
  503,
  'Scheduling service unavailable',
  'Scheduling storage is unavailable. Try again after the service recovers.',
);

function scripted(answers) {
  let next = 0;
  return () => answers[next++] ?? { status: 418 };
}

async function retrying(context, answers, config) {
  const served = await serve(context, scripted(answers));
  const { SchedulingClient } = require('../client');
  return { ...served, client: new SchedulingClient({ baseUrl: served.baseUrl, ...config }) };
}

test('a hold answered 503 is resent once under the same key and succeeds', async (context) => {
  const { client: scheduling, requests } = await retrying(context, [UNAVAILABLE, answered(201, HOLD)], {});

  const outcome = await scheduling.createHold('one-call-secret', 'hold-2026-10-05-0001', ADMISSION);

  assert.deepEqual(outcome, { kind: 'complete', value: HOLD, traceId: TRACE_ID });
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.method, 'POST');
    assert.equal(request.path, '/v1/holds');
    assert.equal(request.headers['idempotency-key'], 'hold-2026-10-05-0001');
    assert.equal(request.body, requests[0].body);
  }
  assert.equal(JSON.parse(requests[0].body).durationMinutes, 1500);
  assert.equal(JSON.parse(requests[0].body).resource, 'clerk-2');
});

test('a retry ceiling of zero sends a hold once and reports the outcome unknown', async (context) => {
  const { client: scheduling, requests } = await retrying(
    context,
    [UNAVAILABLE, answered(201, HOLD)],
    { maximumMutationRetries: 0 },
  );
  const { SchedulingClientError } = require('../client');

  await assert.rejects(scheduling.createHold('one-call-secret', 'key-1', ADMISSION), (error) => {
    assert.ok(error instanceof SchedulingClientError);
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 503);
    assert.equal(error.code, 'service.unavailable');
    assert.equal(error.outcomeUnknown, true);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a 4xx refusal of a hold is never resent and reports the outcome known', async (context) => {
  const { client: scheduling, requests } = await retrying(context, [
    problem(
      'capacity.exhausted',
      409,
      'Capacity exhausted',
      'The supply is fully committed for the requested interval. Choose another time.',
    ),
    answered(201, HOLD),
  ], { maximumMutationRetries: 2 });

  await assert.rejects(scheduling.createHold('one-call-secret', 'key-1', ADMISSION), (error) => {
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 409);
    assert.equal(error.outcomeUnknown, false);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a retry ceiling outside zero to two is a configuration error', () => {
  const { SchedulingClient, SchedulingClientError } = require('../client');
  for (const maximumMutationRetries of [0, 1, 2]) {
    assert.ok(new SchedulingClient({ baseUrl: 'https://scheduling.example/', maximumMutationRetries }));
  }
  for (const maximumMutationRetries of [true, false, 3, 255, 256, -1, 1.5, '1']) {
    assert.throws(() => new SchedulingClient({ baseUrl: 'https://scheduling.example/', maximumMutationRetries }), (error) => {
      assert.ok(error instanceof SchedulingClientError, `${maximumMutationRetries}`);
      assert.equal(error.kind, 'configuration', `${maximumMutationRetries}`);
      assert.equal(error.outcomeUnknown, false);
      return true;
    });
  }
});

test('original receipt observation preserves the caller body, key and current token', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({
    status: 200, contentType: 'application/json', document: APPOINTMENT,
  }));
  const { SchedulingClient } = require('../client');
  const client = new SchedulingClient({ baseUrl: `${baseUrl}tenant/` });
  const original = { admission: ADMISSION };
  const result = await client.appointmentReceipt('current-token', 'original-key', original);
  assert.deepEqual(result, { kind: 'complete', value: APPOINTMENT, traceId: TRACE_ID });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/tenant/v1/appointments/receipt');
  assert.equal(requests[0].headers.authorization, 'Bearer current-token');
  assert.equal(requests[0].headers['idempotency-key'], 'original-key');
  assert.deepEqual(JSON.parse(requests[0].body), { hold: null, admission: ADMISSION_ON_THE_WIRE });
});

for (const [code, status, title, detail] of [
  ['receipt.unresolved', 409, 'Original receipt unresolved', 'No retained success receipt matches this caller, key, and original request. The original outcome remains unknown; this is not evidence that no effect occurred.'],
  ['operation.not-authorized', 403, 'Operation not authorized', 'Server-controlled-detail-canary'],
  ['service.unavailable', 503, 'Service unavailable', 'Server-controlled-detail-canary'],
]) {
  test(`receipt observation maps ${code} without retry or exposing caller values`, async (context) => {
    const { baseUrl, requests } = await serve(context, () => problem(code, status, title, detail));
    const { SchedulingClient, SchedulingClientError } = require('../client');
    const client = new SchedulingClient({ baseUrl, maximumMutationRetries: 2 });
    await assert.rejects(client.appointmentReceipt('token-canary', 'key-canary', { admission: ADMISSION }), (error) => {
      assert.ok(error instanceof SchedulingClientError);
      assert.equal(error.kind, 'problem');
      assert.equal(error.code, code);
      assert.equal(error.status, status);
      assert.equal(error.traceId, TRACE_ID);
      assert.equal(error.outcomeUnknown, status >= 500);
      const rendered = inspect(error);
      for (const canary of ['token-canary', 'key-canary', 'Server-controlled-detail-canary']) {
        assert.equal(rendered.includes(canary), false);
      }
      return true;
    });
    assert.equal(requests.length, 1);
    assert.equal(requests[0].path, '/v1/appointments/receipt');
  });
}

test('receipt observation refuses an invalid key or request before any exchange', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500 }));
  const { SchedulingClient } = require('../client');
  const client = new SchedulingClient({ baseUrl });
  await assert.rejects(client.appointmentReceipt('token', 'two words', { admission: ADMISSION }), (error) => error.kind === 'invalid-request');
  await assert.rejects(client.appointmentReceipt('token', 'key', { admission: ADMISSION, extra: true }), (error) => error.kind === 'invalid-request');
  assert.equal(requests.length, 0);
});
