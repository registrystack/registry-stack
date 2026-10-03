'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const traceId = '4bf92f3577b34da6a3ce929d0e0e4736';

function problem(code, status, detail, extension = {}) {
  const titles = { 404: 'Not Found', 409: 'Conflict', 410: 'Gone', 422: 'Unprocessable Entity', 500: 'Internal Server Error' };
  return JSON.stringify({
    type: `https://id.registrystack.org/problems/registry-breg/${code.replaceAll('.', '/')}`,
    title: titles[status], status, detail, code, traceId, ...extension,
  });
}

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
      const failures = [
        ['/statistics/missing:live', 404, 'resource.not_found', 'The requested resource was not found.', {}],
        ['/statistics/release-refused/', 422, 'statistical_dataset.release_refused', 'The statistical dataset release operation is not eligible.', { refusalCode: 'period-not-ended' }],
        ['/statistics/version-conflict/', 409, 'statistical_dataset.version_conflict', 'The statistical dataset computation was superseded or its package changed.', {}],
        ['/statistics/version-withdrawn/', 410, 'statistical_dataset.version_withdrawn', 'The statistical dataset version was withdrawn.', { reasonCode: 'source-data-error' }],
        ['/statistics/domain-violation:live', 500, 'statistical_dataset.domain_violation', 'A statistical dataset contains a code outside its declared domain.', { fieldPath: 'statisticalDatasets[id=domain-violation].dimensions[id=category]' }],
      ];
      const failure = failures.find(([path]) => request.url.includes(path));
      if (failure) {
        const [, status, code, detail, extension] = failure;
        response.statusCode = status;
        response.setHeader('content-type', 'application/problem+json');
        response.setHeader('cache-control', 'no-store');
        response.setHeader('traceparent', traceparent);
        response.end(problem(code, status, detail, extension));
        return;
      }
      response.statusCode = request.method === 'POST' && request.url.endsWith('/versions?accessProfile=publisher') ? 201 : 200;
      response.setHeader('content-type', request.headers.accept === 'text/csv' ? 'text/csv; charset=utf-8' : request.headers.accept);
      response.setHeader('traceparent', traceparent);
      if (!request.url.includes('/cache-control-missing')) {
        response.setHeader('cache-control', request.url.includes('/cache-control-wrong') ? 'private' : 'no-store');
      }
      if (!request.url.includes('/vary-missing')) {
        response.setHeader('vary', request.url.includes('/vary-wrong') ? 'accept' : 'authorization, accept');
      }
      const body = request.headers.accept === 'text/csv' ? 'period,periodStart,periodEnd,value,status\r\n' : '{"ok":true}';
      if (!request.url.includes('/digest-missing/')
          && (request.method === 'POST' || !request.url.includes('/releases?'))) {
        const representedBody = request.url.includes('/digest-mismatch/') ? '{"wrong":true}' : body;
        response.setHeader('repr-digest', `sha-256=:${createHash('sha256').update(representedBody).digest('base64')}:`);
      }
      response.end(body);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
    const live = await client.statisticsLive('enrolments', '2025-01', '2025-02', 'analyst', 'csv');
    assert.equal(live.mediaType, 'text/csv; charset=utf-8');
    assert.match(live.reprDigest, /^sha-256=:/);
    await client.statisticsLive('enrolments', '2025-01');
    await client.statisticsLive('enrolments', null, '2025-02');
    await client.statisticsReleases('enrolments', 10, 'cursor', 'reader');
    await client.statisticsLatestRelease('enrolments', '2025-01', 'final', 'reader', 'json');
    await client.statisticsReleaseVersion('enrolments', '2025-01', 7, 'reader', 'csv');
    await client.statisticsReleaseSeries('enrolments', '2025-01', '2025-02', 'any', 'reader', 'json');
    const publish = await client.statisticsPublish('enrolments', '2025-01', 'final', 'publisher', 'caller-owned-key');
    const withdraw = await client.statisticsWithdraw('enrolments', '2025-01', 7, 'disclosure-risk', 'publisher', 'caller-owned-key');
    assert.match(publish.reprDigest, /^sha-256=:/);
    assert.match(withdraw.reprDigest, /^sha-256=:/);
    assert.equal(requests[0].url, '/v1/statistics/enrolments:live?from=2025-01&to=2025-02&accessProfile=analyst');
    assert.equal(requests[1].url, '/v1/statistics/enrolments:live?from=2025-01');
    assert.equal(requests[2].url, '/v1/statistics/enrolments:live?to=2025-02');
    assert.equal(requests[5].accept, 'text/csv');
    assert.equal(requests[7].body, '{"status":"final"}');
    assert.equal(requests[7].key, 'caller-owned-key');
    assert.equal(requests[8].body, '{"reason":"disclosure-risk"}');
    const count = requests.length;
    await assert.rejects(client.statisticsReleaseVersion('enrolments', '2025-01', 0), error => error.kind === 'invalid_request');
    assert.equal(requests.length, count);

    await client.statisticsLive('enrolments', '0001', '9998');
    await client.statisticsLatestRelease('enrolments', '9999-Q3', 'any');
    await client.statisticsReleaseVersion('enrolments', '9999-11', 1);
    await client.statisticsReleaseSeries('enrolments', '2024-02-29', '9999-12-30', 'any');
    const afterCanonicalPeriods = requests.length;
    await assert.rejects(
      client.statisticsPublish('enrolments', '2025-99', 'final', 'publisher', 'invalid-period-key'),
      error => error.kind === 'invalid_request',
    );
    await assert.rejects(
      client.statisticsWithdraw('enrolments', '----', 1, 'source-data-error', 'publisher', 'invalid-period-key'),
      error => error.kind === 'invalid_request',
    );
    assert.equal(requests.length, afterCanonicalPeriods);

    for (const read of [
      () => client.statisticsLive('cache-control-missing'),
      () => client.statisticsLive('vary-wrong', null, null, null, 'csv'),
      () => client.statisticsReleases('vary-missing', 10),
      () => client.statisticsReleases('cache-control-wrong', 10),
    ]) {
      await assert.rejects(read(), error => error.kind === 'protocol' && error.code === 'cache_policy');
    }

    const maximumCursor = 'c'.repeat(10_978);
    await client.statisticsReleases('d'.repeat(64), 10, maximumCursor, 'p'.repeat(64));
    const afterMaximumCursor = requests.length;
    await assert.rejects(
      client.statisticsReleases('d'.repeat(64), 10, `${maximumCursor}c`, 'p'.repeat(64)),
      error => error.kind === 'invalid_request',
    );
    assert.equal(requests.length, afterMaximumCursor);

    await assert.rejects(
      client.statisticsPublish('digest-missing', '2025-01', 'final', 'publisher', 'digest-missing-key'),
      error => error.kind === 'protocol' && error.code === 'representation_digest',
    );
    await assert.rejects(
      client.statisticsWithdraw('digest-mismatch', '2025-01', 7, 'source-data-error', 'publisher', 'digest-mismatch-key'),
      error => error.kind === 'protocol' && error.code === 'representation_digest',
    );

    await assert.rejects(client.statisticsLive('missing'), error => error.kind === 'not_found' && error.code === 'resource.not_found');
    await assert.rejects(
      client.statisticsPublish('release-refused', '2025-01', 'final', 'publisher', 'refusal-key'),
      error => error.code === 'statistical_dataset.release_refused' && error.refusalCode === 'period-not-ended',
    );
    await assert.rejects(
      client.statisticsPublish('version-conflict', '2025-01', 'final', 'publisher', 'conflict-key'),
      error => error.code === 'statistical_dataset.version_conflict',
    );
    await assert.rejects(
      client.statisticsReleaseVersion('version-withdrawn', '2025-01', 7, 'reader'),
      error => error.code === 'statistical_dataset.version_withdrawn'
        && error.reasonCode === 'source-data-error' && error.refusalCode === undefined,
    );
    await assert.rejects(
      client.statisticsLive('domain-violation', null, null, 'reader'),
      error => error.code === 'statistical_dataset.domain_violation'
        && error.fieldPath === 'statisticalDatasets[id=domain-violation].dimensions[id=category]'
        && Object.prototype.propertyIsEnumerable.call(error, 'fieldPath') === false
        && String(error).includes('domain-violation') === false
        && JSON.stringify(error).includes('domain-violation') === false,
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
