'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { after, before, test } = require('node:test');

const { BaseRegistryClient } = require('..');

const TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';
const TRACEPARENT = `00-${TRACE_ID}-00f067aa0ba902b7-01`;
const RECORD_ID = '00000000-0000-4000-8000-000000000001';
// A package declares its own refusal catalogue, so the code and the label both
// stand in for one declared entry rather than for fixed client-side text.
const REFUSAL_CODE = 'blank-name';
const REFUSAL_LABEL = 'At least one name part is required.';

const refusal = (extra) => ({
  type: 'https://id.registrystack.org/problems/registry-breg/action/refused',
  title: 'Unprocessable Entity',
  status: 422,
  detail: REFUSAL_LABEL,
  code: 'action.refused',
  traceId: TRACE_ID,
  refusalCode: REFUSAL_CODE,
  ...extra,
});

let server;
let baseUrl;
let document;

before(async () => {
  server = http.createServer((request, response) => {
    response.statusCode = document.status;
    response.setHeader('traceparent', TRACEPARENT);
    response.setHeader('content-type', 'application/problem+json');
    response.setHeader('cache-control', 'no-store');
    response.end(JSON.stringify(document));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

async function answer(problem) {
  document = problem;
  const client = new BaseRegistryClient({ baseUrl });
  return client.getRecord('people', RECORD_ID).then(
    () => assert.fail('a refused action must not resolve'),
    (error) => error,
  );
}

test('a declared refusal reaches the caller with its reason', async () => {
  for (const problem of [
    refusal({}),
    refusal({ fieldPath: '/input/givenName' }),
    refusal({ detail: 'A declared label.', refusalCode: 'declared.reason_9' }),
  ]) {
    const error = await answer(problem);
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 422);
    assert.equal(error.code, 'action.refused');
    assert.equal(error.refusalCode, problem.refusalCode);
    assert.equal(error.traceId, TRACE_ID);
    assert.equal(error.planRefusal, undefined);
  }
});

test('a refusal outside the published bounds fails closed with no reason', async () => {
  const silent = refusal({});
  delete silent.refusalCode;
  for (const problem of [
    silent,
    refusal({ refusalCode: '' }),
    refusal({ refusalCode: 'r'.repeat(129) }),
    refusal({ refusalCode: 'blank\u0007name' }),
    refusal({ fieldPath: '/input/given-name' }),
    refusal({ fieldPath: '/evidence/status' }),
    refusal({ detail: 'label '.repeat(64) }),
    {
      type: 'https://id.registrystack.org/problems/registry-breg/mutation/conflict',
      title: 'Conflict',
      status: 409,
      detail: 'The mutation conflicts with current state.',
      code: 'mutation.conflict',
      traceId: TRACE_ID,
      refusalCode: REFUSAL_CODE,
    },
  ]) {
    const error = await answer(problem);
    assert.equal(error.kind, 'protocol');
    assert.equal(error.code, 'problem');
    assert.equal(error.refusalCode, undefined);
  }
});
