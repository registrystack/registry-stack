'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { CaseworkClient } = require('../client');
const id = '00000000-0000-4000-8000-000000000001';
const previewId = '00000000-0000-4000-8000-000000000009';
const subject = { source: 'registry', type: 'proposal', id: 'proposal-7', version: '3', digest: `sha256:${'a'.repeat(64)}` };
const task = { taskId: id, requestId: previewId, subject, requesterReference: 'REF-7', displayReference: 'REF-7', createdAt: '2026-10-14T00:00:00Z', deadlineAt: '2026-10-20T00:00:00Z', stageId: 'review', stageIndex: 0, queue: 'review', revision: 3, eligibleProfiles: ['staff'], state: { held: { holder: { issuer: 'https://issuer.example', subject: 'staff-1' } } } };
async function fixture(t, select) {
  const requests = [];
  const server = http.createServer((request, response) => {
    let bytes = '';
    request.on('data', chunk => { bytes += chunk; });
    request.on('end', () => {
      requests.push({ path: request.url, headers: request.headers, body: bytes ? JSON.parse(bytes) : null });
      response.writeHead(200, { 'content-type': 'application/json', traceparent: '00-0123456789abcdef0123456789abcdef-0123456789abcdef-01' });
      response.end(JSON.stringify(select(request.url)));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { requests, client: new CaseworkClient({ baseUrl: `http://127.0.0.1:${server.address().port}/tenant` }) };
}
test('next and holdings preserve exact binding/reference selectors and disclosed metadata', async t => {
  const { client, requests } = await fixture(t, path => path.includes('/next?') ? task : { items: [task], status: 'complete' });
  const query = { queue: 'review', ownership: 'assigned-to-me', subjectSource: subject.source, subjectType: subject.type, subjectId: subject.id, subjectVersion: subject.version, subjectDigest: subject.digest, reference: 'REF-7', sort: 'reference', limit: 25 };
  assert.deepEqual((await client.nextReviewTask('staff-token', 'staff', query)).value, task);
  assert.deepEqual((await client.reviewTaskHoldings('staff-token', 'staff', query)).value.items, [task]);
  for (const request of requests) {
    const url = new URL(request.path, 'http://fixture');
    assert.equal(url.searchParams.get('subjectDigest'), subject.digest);
    assert.equal(url.searchParams.get('reference'), 'REF-7');
    assert.equal(url.searchParams.get('sort'), 'reference');
    assert.equal(request.headers['registry-casework-profile'], 'staff');
    assert.equal(request.headers['registry-source-profile'], undefined);
  }
});
test('caseload and clock application send only the reviewed preview ID and caller key', async t => {
  const selected = { taskId: id, revision: 3 };
  const clock = { ...selected, deadlineAt: task.deadlineAt };
  const { client, requests } = await fixture(t, path => path.includes('caseload')
    ? path.endsWith('preview') ? { previewId, directoryRevision: 4, tasks: [selected], expiresAt: '2026-10-14T01:00:00Z' } : { moved: [selected] }
    : path.endsWith('preview') ? { previewId, directoryRevision: 4, tasks: [clock], expiresAt: '2026-10-14T01:00:00Z' } : { tasks: [clock] });
  const movement = { from: { issuer: 'https://issuer.example', subject: 'staff-1' }, to: { issuer: 'https://issuer.example', subject: 'staff-2' }, reason: 'Cover' };
  const preview = await client.previewCaseloadMove('staff-token', 'staff', movement);
  assert.deepEqual((await client.applyCaseloadMove('staff-token', 'staff', 'move-7', { previewId: preview.value.previewId })).value, { moved: [selected] });
  const recompute = await client.previewClockRecompute('staff-token', 'staff', { taskIds: [id] });
  assert.deepEqual((await client.applyClockRecompute('staff-token', 'staff', 'clock-7', { previewId: recompute.value.previewId })).value, { tasks: [clock] });
  assert.deepEqual(requests[1].body, { previewId });
  assert.equal(requests[1].headers['idempotency-key'], 'move-7');
  assert.deepEqual(requests[2].body, { taskIds: [id] });
  assert.equal(requests[3].headers['idempotency-key'], 'clock-7');
});
test('partial selectors, duplicate clock tasks, and invalid preview IDs fail before HTTP', async t => {
  const { client, requests } = await fixture(t, () => null);
  for (const call of [
    () => client.reviewTasks('staff-token', 'staff', { subjectId: 'private-canary' }),
    () => client.nextReviewTask('staff-token', 'staff', { limit: 101 }),
    () => client.reviewTaskHoldings('staff-token', 'staff', { sort: 'private-canary' }),
    () => client.previewClockRecompute('staff-token', 'staff', { taskIds: [id, id] }),
    () => client.decideReviewTask('staff-token', 'staff', id, 1, 'decision', { decision: { type: 'answer', outcome: 'answered', result: [] } }),
    () => client.saveReviewTaskDraft('staff-token', 'staff', id, 1, 'draft', { body: { 'private-canary': 'x'.repeat(17 * 1024) } }),
    () => client.applyCaseloadMove('staff-token', 'staff', 'move', { previewId: '00000000-0000-0000-0000-000000000000' }),
  ]) await assert.rejects(call, error => error.kind === 'invalid-request' && !error.message.includes('private-canary'));
  assert.equal(requests.length, 0);
});
test('staffing responses cannot substitute another subject or reference', async t => {
  const { client } = await fixture(t, () => task);
  await assert.rejects(() => client.nextReviewTask('staff-token', 'staff', { subjectSource: subject.source, subjectType: subject.type, subjectId: 'another', subjectVersion: subject.version, subjectDigest: subject.digest }), error => error.kind === 'protocol');
  await assert.rejects(() => client.nextReviewTask('staff-token', 'staff', { reference: 'another' }), error => error.kind === 'protocol');
});
