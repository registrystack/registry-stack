// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';

import { exchange } from './payment-native-support.mjs';

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}

test('exchange rejects a substituted route that escapes loopback before fetch', async () => {
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async () => {
    fetches += 1;
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    for (const destination of [
      'http://127.0.0.1:4321@203.0.113.1/probe',
      'http://localhost:4321/probe',
      'https://127.0.0.1:4321/probe',
      'http://synthetic-user@127.0.0.1:4321/probe',
    ]) {
      await assert.rejects(
        exchange('POST', destination, {
          token: 'synthetic-token', body: { mode: 'synthetic' }, key: 'synthetic-key',
        }),
        /numeric loopback HTTP request/,
      );
    }
    assert.equal(fetches, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('exchange preserves valid loopback path, query, headers and body', async (t) => {
  let received;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received = { method: request.method, url: request.url, headers: request.headers,
      body: JSON.parse(Buffer.concat(chunks).toString()) };
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ accepted: true }));
  });
  const origin = await listen(server);
  t.after(() => close(server));

  const response = await exchange('POST', `${origin}/v1/collections?mode=synthetic`, {
    token: 'synthetic-token', body: { amount: '25.00' }, key: 'synthetic-key',
  });

  assert.deepEqual(response, { status: 200, body: { accepted: true } });
  assert.equal(received.method, 'POST');
  assert.equal(received.url, '/v1/collections?mode=synthetic');
  assert.equal(received.headers.authorization, 'Bearer synthetic-token');
  assert.equal(received.headers['idempotency-key'], 'synthetic-key');
  assert.equal(received.headers['content-type'], 'application/json');
  assert.deepEqual(received.body, { amount: '25.00' });
});

test('exchange leaves redirects unfollowed', async (t) => {
  let followed = 0;
  const server = http.createServer((request, response) => {
    if (request.url === '/redirect') {
      response.writeHead(302, { Location: '/followed' });
      response.end();
      return;
    }
    followed += 1;
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{}');
  });
  const origin = await listen(server);
  t.after(() => close(server));

  assert.deepEqual(await exchange('GET', `${origin}/redirect`, { expected: [302] }), { status: 302, body: null });
  assert.equal(followed, 0);
});
