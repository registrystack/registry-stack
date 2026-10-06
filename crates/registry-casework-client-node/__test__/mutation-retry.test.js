'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const TRACEPARENT = '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01';
const TRACE_ID = '0123456789abcdef0123456789abcdef';
const ABSENCE = {
  person: { issuer: 'https://issuer.example', subject: 'staff-1' },
  cover: { issuer: 'https://issuer.example', subject: 'staff-2' },
  from: '2026-10-05T00:00:00Z',
  until: '2026-10-06T00:00:00Z',
};
const RECORD = { ...ABSENCE, absenceId: '00000000-0000-0000-0000-000000000005', revision: 3 };

function problem(code, status, title, detail) {
  return {
    status,
    contentType: 'application/problem+json',
    document: {
      type: `https://id.registrystack.org/problems/registry-casework/${code.replaceAll('.', '/')}`,
      title,
      status,
      detail,
      code,
      traceId: TRACE_ID,
    },
  };
}

const UNAVAILABLE = problem(
  'service.unavailable',
  503,
  'Casework service unavailable',
  'Casework storage is unavailable. Try again after the service recovers.',
);
const PRECONDITION_FAILED = problem(
  'precondition.failed',
  412,
  'Precondition failed',
  'The item or directory changed since you loaded it. Reload and try again.',
);
const CREATED = { status: 201, contentType: 'application/json', document: RECORD };

async function retrying(context, answers, config) {
  const requests = [];
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      requests.push({ method: request.method, path: request.url, headers: request.headers, body });
      const answer = answers.shift() ?? { status: 418, contentType: 'application/json', document: {} };
      response.writeHead(answer.status, { 'content-type': answer.contentType, traceparent: TRACEPARENT });
      response.end(JSON.stringify(answer.document));
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const { CaseworkClient } = require('../client');
  const baseUrl = `http://127.0.0.1:${server.address().port}/`;
  return { requests, client: new CaseworkClient({ baseUrl, ...config }) };
}

test('an absence answered 503 is resent once under the same key and succeeds', async (context) => {
  const { client, requests } = await retrying(context, [UNAVAILABLE, CREATED], {});

  const outcome = await client.createAbsence('one-call-secret', 'administrator', 2, 'absence-1', ABSENCE);

  assert.deepEqual(outcome.value, RECORD);
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.method, 'POST');
    assert.equal(request.path, '/v1/directory/absences');
    assert.equal(request.headers['idempotency-key'], 'absence-1');
    assert.equal(request.headers['if-match'], '"2"');
    assert.equal(request.body, requests[0].body);
  }
});

test('a retry ceiling of zero sends an absence once and reports the outcome unknown', async (context) => {
  const { client, requests } = await retrying(context, [UNAVAILABLE, CREATED], { maxMutationRetries: 0 });
  const { CaseworkClientError } = require('../client');

  await assert.rejects(client.createAbsence('one-call-secret', 'administrator', 2, 'absence-1', ABSENCE), (error) => {
    assert.ok(error instanceof CaseworkClientError);
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 503);
    assert.equal(error.code, 'service.unavailable');
    assert.equal(error.outcomeUnknown, true);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a 4xx refusal of an absence is never resent and reports the outcome known', async (context) => {
  const { client, requests } = await retrying(context, [PRECONDITION_FAILED, CREATED], { maxMutationRetries: 2 });

  await assert.rejects(client.createAbsence('one-call-secret', 'administrator', 2, 'absence-1', ABSENCE), (error) => {
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 412);
    assert.equal(error.code, 'precondition.failed');
    assert.equal(error.outcomeUnknown, false);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a request refused before any exchange reports the outcome known', async (context) => {
  const { client, requests } = await retrying(context, [], {});

  await assert.rejects(client.createAbsence('one-call-secret', 'administrator', 2, 'two words', ABSENCE), (error) => {
    assert.equal(error.kind, 'invalid_request');
    assert.equal(error.outcomeUnknown, false);
    return true;
  });
  assert.equal(requests.length, 0);
});

test('a retry ceiling outside zero to two is a configuration error', () => {
  const { CaseworkClient, CaseworkClientError } = require('../client');
  for (const maxMutationRetries of [0, 1, 2]) {
    assert.ok(new CaseworkClient({ baseUrl: 'https://casework.example/', maxMutationRetries }));
  }
  for (const maxMutationRetries of [3, 255, 256, -1, 1.5, '1']) {
    assert.throws(() => new CaseworkClient({ baseUrl: 'https://casework.example/', maxMutationRetries }), (error) => {
      assert.ok(error instanceof CaseworkClientError, `${maxMutationRetries}`);
      assert.equal(error.kind, 'configuration', `${maxMutationRetries}`);
      assert.equal(error.outcomeUnknown, false);
      return true;
    });
  }
});
