'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fixture = require('../../registry-casework-client/tests/fixtures/submission-digest.json');
const { submissionDigest, CaseworkClientError } = require('../client');

function reordered(value) {
  if (Array.isArray(value)) return value.map(reordered);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).reverse().map(([key, member]) => [key, reordered(member)]));
  }
  return value;
}

test('submission digest matches Rust for Unicode and reordered object keys', () => {
  const { producer, sourceNamespace, request, expectedSubmissionDigest } = fixture;
  assert.equal(submissionDigest(producer, sourceNamespace, request), expectedSubmissionDigest);
  assert.equal(submissionDigest(producer, sourceNamespace, reordered(request)), expectedSubmissionDigest);
  assert.notEqual(submissionDigest('another-producer', sourceNamespace, request), expectedSubmissionDigest);
  assert.notEqual(submissionDigest(producer, 'another-namespace', request), expectedSubmissionDigest);
});

test('submission digest refuses invalid inputs locally with value-free errors', () => {
  const { producer, sourceNamespace, request } = fixture;
  const cyclic = {}; cyclic.self = cyclic;
  for (const [caller, namespace, body] of [
    ['', sourceNamespace, request], [producer, '', request],
    [producer, sourceNamespace, { ...request, policy: { ...request.policy, digest: 'private-bad-digest' } }],
    [producer, sourceNamespace, { ...request, policy: { id: request.policy.id, version: request.policy.version } }],
    [producer, sourceNamespace, { ...request, policy: { id: request.policy.id, digest: request.policy.digest } }],
    [producer, sourceNamespace, { ...request, unknown: 'private-value' }],
    [producer, sourceNamespace, { ...request, context: { mode: 'submitted', snapshot: { count: 9007199254740992 } } }],
    [producer, sourceNamespace, cyclic],
    [producer, sourceNamespace, new Proxy(request, {})],
  ]) {
    assert.throws(() => submissionDigest(caller, namespace, body), (error) => {
      assert.ok(error instanceof CaseworkClientError);
      assert.equal(error.kind, 'invalid-request');
      assert.equal(error.outcomeUnknown, false);
      assert.doesNotMatch(error.message, /private|9007199254740992/);
      return true;
    });
  }
});

for (const pinned of [false, true]) {
test(`computed digest composes with ${pinned ? 'pinned' : 'current'} policy admission and response-loss recovery`, async (context) => {
  const http = require('node:http');
  const { CaseworkClient } = require('../client');
  const { producer, sourceNamespace } = fixture;
  const request = { ...fixture.request, policy: pinned ? fixture.request.policy : { id: fixture.request.policy.id } };
  const digest = submissionDigest(producer, sourceNamespace, request);
  const accepted = { requestId: '00000000-0000-4000-8000-000000000001', subject: request.subject, policy: fixture.request.policy, submissionDigest: digest };
  const seen = [];
  const server = http.createServer((incoming, response) => {
    let body = '';
    incoming.on('data', (chunk) => { body += chunk; });
    incoming.on('end', () => {
      seen.push({ path: incoming.url, key: incoming.headers['idempotency-key'], body });
      response.writeHead(seen.length === 1 ? 201 : 200, {
        'content-type': 'application/json',
        traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',
      });
      response.end(JSON.stringify(accepted));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const client = new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/tenant/` });
  const submit = (expected) => client.createOrRecoverReviewRequest('synthetic-token', 'requester', 'retained-submission-key', request, expected);
  assert.deepEqual((await submit(digest)).value, accepted);
  assert.deepEqual((await submit(digest)).value, accepted);
  await assert.rejects(() => submit(`sha256:${'c'.repeat(64)}`), (error) => error instanceof CaseworkClientError && error.kind === 'protocol');
  assert.equal(seen.length, 3, 'admission never silently retries');
  assert.equal(seen[0].path, '/tenant/v1/review-requests');
  assert.equal(seen[0].key, 'retained-submission-key');
  assert.deepEqual(JSON.parse(seen[0].body), request);
  assert.deepEqual(seen[1], seen[0]);
});

}
