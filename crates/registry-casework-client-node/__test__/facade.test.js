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
