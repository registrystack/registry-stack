'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient, BaseRegistryClientError } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const traceId = '4bf92f3577b34da6a3ce929d0e0e4736';
const published = '{"dataset":"enrolments","version":1}';
const titles = { 409: 'Conflict', 500: 'Internal Server Error', 503: 'Service Unavailable' };

function problem(code, status, detail, extension = {}) {
  return {
    status,
    contentType: 'application/problem+json',
    body: JSON.stringify({
      type: `https://id.registrystack.org/problems/registry-breg/${code.replaceAll('.', '/')}`,
      title: titles[status], status, detail, code, traceId, ...extension,
    }),
  };
}

const unavailable = problem('service.unavailable', 503, 'The Registry mutation service is unavailable.');
const publication = {
  status: 201,
  contentType: 'application/json',
  body: published,
  headers: {
    vary: 'authorization, accept',
    'repr-digest': `sha-256=:${createHash('sha256').update(published).digest('base64')}:`,
  },
};

// Answer each request with the next scripted answer, in request order.
async function serve(context, answers) {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({ method: request.method, url: request.url, headers: request.headers, body });
    const answer = answers[requests.length - 1] ?? { status: 418, contentType: 'text/plain', body: '' };
    response.statusCode = answer.status;
    response.setHeader('content-type', answer.contentType);
    response.setHeader('traceparent', traceparent);
    response.setHeader('cache-control', 'no-store');
    for (const [name, value] of Object.entries(answer.headers ?? {})) response.setHeader(name, value);
    response.end(answer.body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise(resolve => server.close(resolve)));
  return { baseUrl: `http://127.0.0.1:${server.address().port}`, requests };
}

function publish(client, key = 'publish-2026-09-0001') {
  return client.statisticsPublish('enrolments', '2026-09', 'final', 'publisher', key);
}

test('a publication answered 503 is resent once under the same key and succeeds', async (context) => {
  const { baseUrl, requests } = await serve(context, [unavailable, publication]);
  const client = new BaseRegistryClient({ baseUrl });

  const outcome = await publish(client);

  assert.match(outcome.reprDigest, /^sha-256=:/);
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.method, 'POST');
    assert.equal(request.url, '/v1/statistics/enrolments/releases/2026-09/versions?accessProfile=publisher');
    assert.equal(request.headers['idempotency-key'], 'publish-2026-09-0001');
    assert.equal(request.body, requests[0].body);
  }
});

test('a retry ceiling of zero sends a publication once and reports the outcome unknown', async (context) => {
  const { baseUrl, requests } = await serve(context, [unavailable, publication]);
  const client = new BaseRegistryClient({ baseUrl, maxMutationRetries: 0 });

  await assert.rejects(publish(client), (error) => {
    assert.ok(error instanceof BaseRegistryClientError);
    assert.equal(error.kind, 'problem');
    assert.equal(error.status, 503);
    assert.equal(error.code, 'service.unavailable');
    assert.equal(error.outcomeUnknown, true);
    return true;
  });
  assert.equal(requests.length, 1);
});

test('a refusal or a failure before commit is never resent and reports the outcome known', async (context) => {
  for (const refusal of [
    problem('statistical_dataset.version_conflict', 409, 'The statistical dataset computation was superseded or its package changed.'),
    problem('statistical_dataset.domain_violation', 500, 'A statistical dataset contains a code outside its declared domain.', {
      fieldPath: 'statisticalDatasets[id=enrolments].dimensions[id=category]',
    }),
  ]) {
    const { baseUrl, requests } = await serve(context, [refusal, publication]);
    const client = new BaseRegistryClient({ baseUrl, maxMutationRetries: 2 });

    await assert.rejects(publish(client), (error) => {
      assert.equal(error.kind, 'problem');
      assert.equal(error.status, refusal.status);
      assert.equal(error.outcomeUnknown, false);
      return true;
    });
    assert.equal(requests.length, 1);
  }
});

test('a retry ceiling outside zero to two is a configuration error', () => {
  for (const maxMutationRetries of [0, 1, 2]) {
    assert.ok(new BaseRegistryClient({ baseUrl: 'https://registry.example/', maxMutationRetries }));
  }
  for (const maxMutationRetries of [3, 255, 256, -1, 1.5, '1']) {
    assert.throws(() => new BaseRegistryClient({ baseUrl: 'https://registry.example/', maxMutationRetries }), (error) => {
      assert.ok(error instanceof BaseRegistryClientError, `${maxMutationRetries}`);
      assert.equal(error.kind, 'configuration', `${maxMutationRetries}`);
      assert.equal(error.outcomeUnknown, false);
      return true;
    });
  }
});

test('a request refused before any exchange reports the outcome known', async () => {
  const client = new BaseRegistryClient({ baseUrl: 'http://127.0.0.1:1' });
  await assert.rejects(
    client.statisticsPublish('enrolments', '2025-99', 'final', 'publisher', 'invalid-period-key'),
    (error) => {
      assert.equal(error.kind, 'invalid_request');
      assert.equal(error.outcomeUnknown, false);
      return true;
    },
  );
});
