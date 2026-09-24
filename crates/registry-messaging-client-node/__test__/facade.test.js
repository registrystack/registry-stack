'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { inspect } = require('node:util');

const TRACEPARENT = '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01';
const TRACE_ID = '0123456789abcdef0123456789abcdef';
const MESSAGE_ID = '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d';
const PROBLEM_BASE = 'https://id.registrystack.org/problems/registry-messaging/';

const LINKS = {
  self: `/v1/messages/${MESSAGE_ID}`,
  cancel: `/v1/messages/${MESSAGE_ID}/cancel`,
};

const SUBMISSION = {
  senderProfile: 'reminders-sms',
  to: { phone: '+15550100' },
  template: { id: 'appointment-reminder', version: '1' },
  locale: 'en',
  data: { time: '10:00' },
  correlationId: 'case-42',
};

const CANCELLED_VIEW = {
  id: MESSAGE_ID,
  status: 'cancelled',
  dispatch: 'cancelled',
  report: 'none',
  channel: 'sms',
  senderProfile: 'reminders-sms',
  to: { phone: '+15550100' },
  acceptedAt: '2026-09-25T10:00:00Z',
  expiresAt: '2026-09-26T10:00:00Z',
  updatedAt: '2026-09-25T10:00:01Z',
  attempts: [],
  links: LINKS,
};

const PREVIEW_REQUEST = { locale: 'en', data: { time: '10:00' } };

const PREVIEW = {
  template: { id: 'appointment-reminder', version: '1' },
  locale: 'en',
  channel: 'sms',
  packageDigest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
  parts: { text: 'Your appointment is at 10:00.' },
  sms: { encoding: 'gsm7', units: 29, segments: 1 },
};

async function serve(context, answer) {
  const requests = [];
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      requests.push({ method: request.method, path: request.url, headers: request.headers, body });
      const { status, contentType, document } = answer(request);
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

test('facade exports the maintained client and mapped error', () => {
  const client = require('../client');
  assert.equal(typeof client.MessagingClient, 'function');
  assert.equal(typeof client.MessagingClientError, 'function');
});

test('health and ready complete with the answered trace and no value', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 200 }));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  assert.deepEqual(await client.health(), { kind: 'complete', value: null, traceId: TRACE_ID });
  assert.deepEqual(await client.ready(), { kind: 'complete', value: null, traceId: TRACE_ID });
  assert.deepEqual(requests.map(({ path }) => path), ['/health', '/ready']);
  assert.equal(requests[0].headers.authorization, undefined);
});

test('submit carries the caller idempotency key and answers the receipt', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({
    status: 202,
    contentType: 'application/json',
    document: { id: MESSAGE_ID, status: 'queued', links: LINKS },
  }));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  const receipt = await client.submit('one-call-secret', 'reminder-2026-09-25-0001', SUBMISSION);

  assert.equal(receipt.kind, 'complete');
  assert.equal(receipt.traceId, TRACE_ID);
  assert.deepEqual(receipt.value, { id: MESSAGE_ID, status: 'queued', links: LINKS });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/v1/messages');
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
  assert.equal(requests[0].headers['idempotency-key'], 'reminder-2026-09-25-0001');
  assert.equal(requests[0].headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[0].body), SUBMISSION);
});

test('submit refuses a key outside the header grammar before any request', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500 }));
  const { MessagingClient, MessagingClientError } = require('../client');
  const client = new MessagingClient({ baseUrl });

  for (const key of ['', 'two words', 'café', 'k'.repeat(129)]) {
    await assert.rejects(client.submit('one-call-secret', key, SUBMISSION), (error) => {
      assert.ok(error instanceof MessagingClientError);
      assert.equal(error.kind, 'invalid_request');
      return true;
    });
  }
  assert.equal(requests.length, 0);
});

test('submit refuses an unknown submission member before any request', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500 }));
  const { MessagingClient, MessagingClientError } = require('../client');
  const client = new MessagingClient({ baseUrl });

  await assert.rejects(
    client.submit('one-call-secret', 'key-1', { ...SUBMISSION, priority: 'high' }),
    (error) => error.kind === 'invalid_request',
  );
  // The facade refuses an unsafe integer synchronously, as Casework's does.
  assert.throws(
    () => client.submit('one-call-secret', 'key-1', { ...SUBMISSION, data: { count: Number.MAX_SAFE_INTEGER + 1 } }),
    (error) => error instanceof MessagingClientError && error.kind === 'invalid_request',
  );
  const { MessagingClient: NativeMessagingClient } = require('../index');
  const native = new NativeMessagingClient({ baseUrl });
  await assert.rejects(
    native.submit('one-call-secret', 'key-1', { ...SUBMISSION, data: { count: Number.MAX_SAFE_INTEGER + 1 } }),
    (error) => JSON.parse(error.message).kind === 'invalid_request',
  );
  assert.equal(requests.length, 0);
});

test('message reads the view the runtime serves', async (context) => {
  const view = {
    id: MESSAGE_ID,
    status: 'delivered',
    dispatch: 'submitted',
    report: 'delivered',
    reportedAt: '2026-09-25T10:00:02Z',
    channel: 'sms',
    senderProfile: 'reminders-sms',
    to: { phone: '+15550100' },
    template: { id: 'appointment-reminder', version: '1' },
    correlationId: 'case-42',
    acceptedAt: '2026-09-25T10:00:00Z',
    expiresAt: '2026-09-26T10:00:00Z',
    updatedAt: '2026-09-25T10:00:01Z',
    attempts: [{
      generation: 1,
      attempt: 1,
      outcome: 'accepted',
      startedAt: '2026-09-25T10:00:00Z',
      finishedAt: '2026-09-25T10:00:01Z',
      providerReference: true,
    }],
    links: LINKS,
  };
  const { baseUrl, requests } = await serve(context, () => ({
    status: 200,
    contentType: 'application/json',
    document: view,
  }));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  const outcome = await client.message('one-call-secret', MESSAGE_ID);

  assert.deepEqual(outcome, { kind: 'complete', value: view, traceId: TRACE_ID });
  assert.equal(requests[0].method, 'GET');
  assert.equal(requests[0].path, `/v1/messages/${MESSAGE_ID}`);
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
});

test('message refuses an identifier outside the lowercase UUID form before any request', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500 }));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  await assert.rejects(
    client.message('one-call-secret', MESSAGE_ID.toUpperCase()),
    (error) => error.kind === 'invalid_request',
  );
  assert.equal(requests.length, 0);
});

test('cancel posts to the cancel route and answers the cancelled view', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({
    status: 200,
    contentType: 'application/json',
    document: CANCELLED_VIEW,
  }));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  const outcome = await client.cancel('one-call-secret', MESSAGE_ID);

  assert.deepEqual(outcome, { kind: 'complete', value: CANCELLED_VIEW, traceId: TRACE_ID });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, `/v1/messages/${MESSAGE_ID}/cancel`);
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
  assert.equal(requests[0].headers['idempotency-key'], undefined);
  assert.equal(requests[0].body, '');
});

test('cancel refuses an identifier outside the lowercase UUID form before any request', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500 }));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  for (const id of ['', '../ready', MESSAGE_ID.toUpperCase()]) {
    await assert.rejects(client.cancel('one-call-secret', id), (error) => error.kind === 'invalid_request');
  }
  assert.equal(requests.length, 0);
});

test('a cancellation that lost the race is the mapped conflict', async (context) => {
  for (const [code, title, detail] of [
    ['message.dispatch-started', 'Message dispatch started', 'Dispatch already started.'],
    ['message.terminal', 'Message already final', 'The message is already final.'],
  ]) {
    const { baseUrl } = await serve(context, () => problem(code, 409, title, detail));
    const { MessagingClient } = require('../client');
    const client = new MessagingClient({ baseUrl });

    await assert.rejects(client.cancel('one-call-secret', MESSAGE_ID), (error) => {
      assert.equal(error.kind, 'problem');
      assert.equal(error.status, 409);
      assert.equal(error.code, code);
      assert.equal(error.traceId, TRACE_ID);
      return true;
    });
  }
});

test('preview posts the locale and data and answers the rendered parts', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({
    status: 200,
    contentType: 'application/json',
    document: PREVIEW,
  }));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  const outcome = await client.preview('one-call-secret', 'appointment-reminder', '1', PREVIEW_REQUEST);

  assert.deepEqual(outcome, { kind: 'complete', value: PREVIEW, traceId: TRACE_ID });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].path, '/v1/templates/appointment-reminder/versions/1/preview');
  assert.equal(requests[0].headers.authorization, 'Bearer one-call-secret');
  assert.equal(requests[0].headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(requests[0].body), PREVIEW_REQUEST);
});

test('preview refuses a template name outside the package grammar before any request', async (context) => {
  const { baseUrl, requests } = await serve(context, () => ({ status: 500 }));
  const { MessagingClient, MessagingClientError } = require('../client');
  const client = new MessagingClient({ baseUrl });

  for (const [templateId, version] of [['', '1'], ['../ready', '1'], ['Reminder', '1'], ['reminder', '1/preview']]) {
    await assert.rejects(
      client.preview('one-call-secret', templateId, version, PREVIEW_REQUEST),
      (error) => error.kind === 'invalid_request',
    );
  }
  await assert.rejects(
    client.preview('one-call-secret', 'reminder', '1', { ...PREVIEW_REQUEST, channel: 'sms' }),
    (error) => error.kind === 'invalid_request',
  );
  assert.throws(
    () => client.preview('one-call-secret', 'reminder', '1', { locale: 'en', data: { count: Number.MAX_SAFE_INTEGER + 1 } }),
    (error) => error instanceof MessagingClientError && error.kind === 'invalid_request',
  );
  assert.equal(requests.length, 0);
});

test('a template refusal is the mapped problem', async (context) => {
  const { baseUrl } = await serve(context, () => problem(
    'template.data-invalid',
    422,
    'Template data invalid',
    'The data does not match the template schema.',
  ));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  await assert.rejects(client.preview('one-call-secret', 'appointment-reminder', '1', PREVIEW_REQUEST), (error) => {
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 422);
    assert.equal(error.code, 'template.data-invalid');
    assert.equal(error.traceId, TRACE_ID);
    return true;
  });
});

test('a reused idempotency key is the mapped problem with its pinned detail', async (context) => {
  const { baseUrl } = await serve(context, () => problem(
    'idempotency.key-reused',
    409,
    'Idempotency key reused',
    'This idempotency key was used for a different request.',
  ));
  const { MessagingClient, MessagingClientError } = require('../client');
  const client = new MessagingClient({ baseUrl });

  await assert.rejects(client.submit('one-call-secret', 'key-1', SUBMISSION), (error) => {
    assert.ok(error instanceof MessagingClientError);
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 409);
    assert.equal(error.code, 'idempotency.key-reused');
    assert.equal(error.title, 'Idempotency key reused');
    assert.equal(error.detail, 'This idempotency key was used for a different request.');
    assert.equal(error.message, error.detail);
    assert.equal(error.traceId, TRACE_ID);
    return true;
  });
});

test('a message the caller may not see is the mapped not-visible problem', async (context) => {
  const { baseUrl } = await serve(context, () => problem(
    'message.not-visible',
    404,
    'Message not visible',
    'No message with this identifier is visible to the caller.',
  ));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  await assert.rejects(client.message('one-call-secret', MESSAGE_ID), (error) => {
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 404);
    assert.equal(error.code, 'message.not-visible');
    return true;
  });
});

test('a code outside the closed vocabulary is a protocol failure, not a problem', async (context) => {
  const { baseUrl } = await serve(context, () => problem('message.future', 409, 'Future', 'Future.'));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  await assert.rejects(client.message('one-call-secret', MESSAGE_ID), (error) => {
    assert.equal(error.kind, 'protocol');
    assert.equal(error.status, 409);
    assert.equal(error.protocolFailure, 'problem');
    assert.equal(error.code, undefined);
    return true;
  });
});

test('an unreachable service is a transport failure', async () => {
  const server = http.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl: `http://127.0.0.1:${port}/`, connectTimeoutMilliseconds: 1000 });

  await assert.rejects(client.health(), (error) => {
    assert.equal(error.kind, 'transport');
    assert.equal(typeof error.transportKind, 'string');
    return true;
  });
});

test('an invalid configuration is a configuration error', () => {
  const { MessagingClient, MessagingClientError } = require('../client');
  assert.throws(() => new MessagingClient({ baseUrl: 'not a url' }), (error) => {
    assert.ok(error instanceof MessagingClientError);
    assert.equal(error.kind, 'configuration');
    return true;
  });
});

test('bearer tokens never reach error text, fields, or inspection', async (context) => {
  const secret = 'bad token with spaces canary';
  const answered = 'answered-token-canary';
  const { baseUrl } = await serve(context, () => problem(
    'authentication.refused',
    401,
    'Authentication refused',
    'The bearer credential is missing, invalid, or expired. Sign in again.',
  ));
  const { MessagingClient } = require('../client');
  const client = new MessagingClient({ baseUrl });

  const failures = [];
  await client.message(secret, MESSAGE_ID).catch((error) => failures.push(error));
  await client.submit(answered, 'key-1', SUBMISSION).catch((error) => failures.push(error));
  await client.message(answered, MESSAGE_ID).catch((error) => failures.push(error));
  await client.cancel(answered, MESSAGE_ID).catch((error) => failures.push(error));
  await client.preview(answered, 'appointment-reminder', '1', PREVIEW_REQUEST).catch((error) => failures.push(error));
  await client.cancel(secret, MESSAGE_ID).catch((error) => failures.push(error));

  assert.equal(failures.length, 6);
  assert.equal(failures[0].kind, 'invalid_request');
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
  assert.doesNotMatch(inspect(client, { depth: 8, showHidden: true }), /canary/);
});
