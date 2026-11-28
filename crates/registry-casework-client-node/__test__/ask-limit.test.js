'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { CaseworkClient } = require('../client');

test('the ask limit exposes its safe problem detail and is never retried', async () => {
  let attempts = 0;
  const detail = 'This review request has reached its limit of 50 asks. Continue the review without opening another ask.';
  const server = http.createServer(async (request, response) => {
    for await (const chunk of request) { assert.ok(chunk.length); }
    attempts += 1;
    response.writeHead(409, {
      'content-type': 'application/problem+json',
      traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
    });
    response.end(JSON.stringify({
      type: 'https://id.registrystack.org/problems/registry-casework/review/ask-limit-reached',
      title: 'Review ask limit reached', status: 409, detail,
      code: 'review.ask-limit-reached', traceId: '0123456789abcdef0123456789abcdef',
    }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new CaseworkClient({baseUrl: `http://127.0.0.1:${server.address().port}/`});
    await assert.rejects(
      client.askApplicant('synthetic-token', 'staff', '00000000-0000-4000-8000-000000000001', 2, 'ask-51', {text: 'Why?', wants: []}),
      error => {
        assert.equal(error.kind, 'problem');
        assert.equal(error.code, 'review.ask-limit-reached');
        assert.equal(error.detail, detail);
        return true;
      },
    );
    assert.equal(attempts, 1);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
