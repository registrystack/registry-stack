'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const fixture = require('../../registry-breg-client/tests/fixtures/review-reasons.json');

test('review reasons preserve text on explicit retry and refuse invalid inputs before HTTP', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({body, headers: request.headers});
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    if (request.url.startsWith('/v1/registry')) return response.end(JSON.stringify(fixture.metadata));
    if (request.method === 'GET') {
      response.setHeader('link', '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/item>; rel="describedby"');
      response.setHeader('etag', '"breg-record-000000000008"');
      return response.end(JSON.stringify(fixture.records.reject_request));
    }
    const operation = Object.keys(fixture.records).find(name => fixture.records[name].data.request.actions[0].href === request.url);
    response.end(JSON.stringify(fixture.receipts[operation]));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}`});
    const metadata = await client.registryContract('writer');
    const authority = metadata.selectLifecycle('item', 'writer');
    const record = await client.getRecord('items', fixture.records.reject_request.data.recordIdentifier, {accessProfile:'writer'});
    assert.deepEqual(record.value.data.request.decisions, fixture.records.reject_request.data.request.decisions);
    assert.deepEqual(record.value.data.request.history, fixture.records.reject_request.data.request.history);
    for (const operation of Object.keys(fixture.records)) {
      const [action] = client.lifecycleActions(authority, fixture.records[operation]);
      const before = requests.length;
      if (['approve_request', 'apply_request'].includes(operation)) {
        assert.throws(() => action.withReason('not permitted'), error => error.kind === 'invalid_request');
      } else {
        for (const invalid of [null, 1, {}, '📝'.repeat(4097), '\0', '\ud800']) {
          assert.throws(() => action.withReason(invalid), error => error.kind === 'invalid_request');
        }
        assert.equal(action.withReason('📝'.repeat(4096)).body.reason, '📝'.repeat(4096));
        assert.equal(action.withReason('').body.reason, '');
        assert.ok(!Object.hasOwn(action.body, 'reason'));
        assert.equal(requests.length, before);
        const reason = '  Please correct the values.\nเหตุผล 📝  ';
        const decision = action.withReason(reason);
        assert.equal(JSON.parse(decision.bodyJson).reason, reason);
        await client.executeLifecycleAction(decision, `decision-${operation}`);
        await client.executeLifecycleAction(decision, `decision-${operation}`);
        assert.equal(JSON.parse(requests.at(-1).body).reason, reason);
        assert.equal(requests.at(-1).body, requests.at(-2).body);
        assert.equal(requests.at(-1).headers['idempotency-key'], requests.at(-2).headers['idempotency-key']);
        assert.equal(requests.at(-1).headers['if-match'], requests.at(-2).headers['if-match']);
      }
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
