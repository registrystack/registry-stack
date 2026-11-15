'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

test('loaded native addon transmits separate source authority only for the explicit invocation', async context => {
  const observed = [];
  const server = http.createServer((request, response) => {
    observed.push(request.headers);
    request.resume();
    request.on('end', () => {
      response.writeHead(200, { 'content-type': 'application/json', traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01' });
      response.end(JSON.stringify({ items: [], nextCursor: null, status: 'complete' }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise(resolve => server.close(resolve)));
  const { CaseworkClient } = require('../client');
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/` });
  assert.equal(client.humanSourceCredentialContract(), 'registry.casework.human-source-credential.v1');
  const credential = { sourceProfile: 'source-reader', token: 'source-call-canary' };
  await client.reviewTasks('casework-call-canary', 'staff', {}, undefined, credential);
  await client.reviewTasks('casework-call-canary', 'staff');
  assert.equal(observed.length, 2);
  assert.equal(observed[0].authorization, 'Bearer casework-call-canary');
  assert.equal(observed[0]['registry-source-authorization'], 'Bearer source-call-canary');
  assert.equal(observed[0]['registry-source-profile'], 'source-reader');
  assert.equal(observed[1]['registry-source-authorization'], undefined);
  assert.equal(observed[1]['registry-source-profile'], undefined);
  await assert.rejects(client.reviewTasks('casework-call-canary', 'staff', {}, 'different-source', credential));
  assert.equal(observed.length, 2);
});
