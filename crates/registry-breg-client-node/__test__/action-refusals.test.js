'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { after, before, test } = require('node:test');
const { format, inspect } = require('node:util');

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

const guardFailure = (extra) => ({
  type: 'https://id.registrystack.org/problems/registry-breg/action/guard_failed',
  title: 'Precondition Failed',
  status: 412,
  detail: 'The action guard was not satisfied.',
  code: 'action.guard_failed',
  traceId: TRACE_ID,
  guardReason: 'legal_name_unchanged',
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
    assert.equal(error.fieldPath, problem.fieldPath);
    assert.equal(error.traceId, TRACE_ID);
    assert.equal('planRefusal' in error, false);
  }
});

test('a failed guard exposes only its bounded authored copy key', async () => {
  for (const reason of ['a', 'legal_name_unchanged', `a${'b'.repeat(63)}`]) {
    const error = await answer(guardFailure({guardReason: reason}));
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 412);
    assert.equal(error.code, 'action.guard_failed');
    assert.equal(error.guardReason, reason);
    assert.equal(error.refusalCode, undefined);
    assert.equal(error.reasonCode, undefined);
    assert.equal(Object.prototype.propertyIsEnumerable.call(error, 'guardReason'), false);
    for (const render of [inspect, format, JSON.stringify]) {
      if (reason.length > 1) assert.equal(render(error).includes(reason), false);
    }
  }
  for (const problem of [
    guardFailure({guardReason: ''}),
    guardFailure({guardReason: 'Uppercase'}),
    guardFailure({guardReason: 'has.dot'}),
    guardFailure({guardReason: `a${'b'.repeat(64)}`}),
    guardFailure({guardReason: null}),
    refusal({guardReason: 'misplaced'}),
    guardFailure({refusalCode: REFUSAL_CODE}),
    guardFailure({reasonCode: 'source-data-error'}),
  ]) {
    const error = await answer(problem);
    assert.equal(error.kind, 'protocol');
    assert.equal(error.guardReason, undefined);
    assert.equal(error.refusalCode, undefined);
    assert.equal(error.reasonCode, undefined);
  }
});

test('the typed idempotency key reuse problem uses the current wire code', async () => {
  const current = await answer({
    type: 'https://id.registrystack.org/problems/registry-breg/idempotency/key-reused',
    title: 'Conflict', status: 409,
    detail: 'The idempotency key is bound to another request.',
    code: 'idempotency.key-reused', traceId: TRACE_ID,
  });
  assert.equal(current.kind, 'problem');
  assert.equal(current.code, 'idempotency.key-reused');
  assert.equal(current.status, 409);
  assert.equal(current.outcomeUnknown, false);

  const retired = await answer({
    type: 'https://id.registrystack.org/problems/registry-breg/idempotency/conflict',
    title: 'Conflict', status: 409,
    detail: 'The idempotency key is bound to another request.',
    code: 'idempotency.conflict', traceId: TRACE_ID,
  });
  assert.equal(retired.kind, 'problem');
  assert.equal(retired.code, undefined);
});

test('row-local constraints expose bounded identifiers without default rendering', async () => {
  const base = {
    type: 'https://id.registrystack.org/problems/registry-breg/mutation/conflict',
    title: 'Conflict', status: 409, detail: 'The mutation conflicts with current state.',
    code: 'mutation.conflict', traceId: TRACE_ID,
  };
  const constraints = [
    { recordType: 'item', constraintId: 'valid-period', constraintKind: 'compare', left: 'valid-from', right: 'valid-to' },
    { recordType: 'item', constraintId: 'quantity-range', constraintKind: 'int-range', field: 'quantity' },
    { recordType: 'item', constraintId: 'allowed-status', constraintKind: 'vocabulary', field: 'status' },
  ];
  for (const constraint of constraints) {
    const error = await answer({ ...base, ...constraint });
    assert.equal(error.kind, 'problem');
    assert.equal(error.code, 'mutation.conflict');
    assert.equal(error.outcomeUnknown, false);
    assert.deepEqual(error.constraint, constraint);
    assert.equal(Object.prototype.propertyIsEnumerable.call(error, 'constraint'), false);
    for (const render of [inspect, format, JSON.stringify]) {
      assert.equal(render(error).includes(constraint.constraintId), false);
    }
  }
  assert.equal((await answer(base)).constraint, undefined);
  for (const malformed of [
    { ...constraints[0], right: null },
    { ...constraints[0], constraintKind: 'unique' },
    { ...constraints[1], field: 'x'.repeat(129) },
    { ...constraints[2], field: 'value\ncanary' },
  ]) {
    const error = await answer({ ...base, ...malformed });
    assert.equal(error.kind, 'protocol');
    assert.equal(error.constraint, undefined);
  }
});

test('located problems keep field paths out of default Node rendering', async () => {
  for (const problem of [
    refusal({ fieldPath: '/input/givenName' }),
    {
      type: 'https://id.registrystack.org/problems/registry-breg/request/invalid',
      title: 'Bad Request',
      status: 400,
      detail: 'The request is invalid.',
      code: 'request.invalid',
      traceId: TRACE_ID,
      fieldPath: '/data/legalName',
    },
    {
      type: 'https://id.registrystack.org/problems/registry-breg/query/invalid',
      title: 'Bad Request',
      status: 400,
      detail: 'The query request is invalid.',
      code: 'query.invalid',
      traceId: TRACE_ID,
      fieldPath: '$select',
    },
  ]) {
    const error = await answer(problem);
    assert.equal(error.fieldPath, problem.fieldPath);
    assert.equal(Object.prototype.propertyIsEnumerable.call(error, 'fieldPath'), false);
    assert.equal(inspect(error).includes(problem.fieldPath), false);
    assert.equal(format(error).includes(problem.fieldPath), false);
    assert.equal(JSON.stringify(error).includes(problem.fieldPath), false);
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
    assert.equal(error.fieldPath, undefined);
  }
});
