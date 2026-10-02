'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

test('statistics methods preserve route, representation, status and caller key', async () => {
  const requests = [];
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => {
      requests.push({
        method: request.method,
        url: request.url,
        accept: request.headers.accept,
        key: request.headers['idempotency-key'],
        body: Buffer.concat(chunks).toString('utf8'),
      });
      response.statusCode = request.method === 'POST' && request.url.endsWith('/versions?accessProfile=publisher') ? 201 : 200;
      response.setHeader('content-type', request.headers.accept);
      response.setHeader('traceparent', traceparent);
      if (request.method === 'POST') {
        response.setHeader('cache-control', 'no-store');
        response.setHeader('vary', 'authorization, accept');
      }
      response.end(request.headers.accept === 'text/csv' ? 'period,periodStart,periodEnd,value,status\r\n' : '{"ok":true}');
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
    assert.equal((await client.statisticsLive('enrolments', '2025-01', '2025-02', 'analyst', 'csv')).mediaType, 'text/csv');
    await client.statisticsReleases('enrolments', 10, 'cursor', 'reader');
    await client.statisticsLatestRelease('enrolments', '2025-01', 'final', 'reader', 'json');
    await client.statisticsReleaseVersion('enrolments', '2025-01', 7, 'reader', 'csv');
    await client.statisticsReleaseSeries('enrolments', '2025-01', '2025-02', 'any', 'reader', 'json');
    await client.statisticsPublish('enrolments', '2025-01', 'final', 'publisher', 'caller-owned-key');
    await client.statisticsWithdraw('enrolments', '2025-01', 7, 'disclosure-risk', 'publisher', 'caller-owned-key');
    assert.equal(requests[0].url, '/v1/statistics/enrolments:live?from=2025-01&to=2025-02&accessProfile=analyst');
    assert.equal(requests[3].accept, 'text/csv');
    assert.equal(requests[5].body, '{"status":"final"}');
    assert.equal(requests[5].key, 'caller-owned-key');
    assert.equal(requests[6].body, '{"reason":"disclosure-risk"}');
    const count = requests.length;
    await assert.rejects(client.statisticsReleaseVersion('enrolments', '2025-01', 0), error => error.kind === 'invalid_request');
    assert.equal(requests.length, count);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
