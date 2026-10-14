'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient, BRegPreparedProposal } = require('..');

const revision = `sha256:${'a'.repeat(64)}`;
const id = '00000000-0000-4000-8000-000000000001';
const metadata = {
  id: 'proposal-client', version: '1', revision, metadataVersion: '1', recordTypes: [], operations: [],
  proposals: {method: 'GET', path: '/v1/proposals', accessProfiles: ['author'],
    get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['author']}},
  actions: [{id: 'correct', apiName: 'correct', revision, display: {}, execution: {mode: 'proposal'},
    route: '/v1/actions/correct/proposals', inputMode: 'fixed', inputs: [], referenceInputs: [], requiredConditionKeys: [], resultEffects: [],
    access: {selectedProfile: 'author'}, routes: {start: {method: 'POST', path: '/v1/actions/correct/proposals', operationId: 'actions.correct.start',
      requiresIdempotencyKey: true, inputSchema: 'action-correct-invoke-input', responseSchema: 'action-correct-invoke-response'}},
    bounds: {maximumTargets: 16, maximumFieldMutations: 128, maximumSnapshotBytes: 2097152}}],
};
const proposal = {id, actionId: 'correct', actionRevision: revision, submissionVersion: 0, revision: 1, state: 'draft', links: {
  self: {method: 'GET', path: `/v1/proposals/${id}`, accessProfile: 'author', operation: 'get'},
  submit: {method: 'POST', path: `/v1/proposals/${id}/submit`, accessProfile: 'author', operation: 'submit', ifMatch: '"draft-condition"'},
}};

test('proposal handles preserve base path, selected profile and exact prepared evidence', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({url: request.url, body, headers: request.headers});
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    if (request.url.startsWith('/tenant/v1/registry')) return response.end(JSON.stringify(metadata));
    if (request.url.startsWith('/tenant/v1/proposals?')) return response.end(JSON.stringify({items: [proposal]}));
    response.end(JSON.stringify(proposal));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    const contract = await client.registryContract('author');
    const getBinding = contract.selectProposalGet('author');
    const located = await client.getProposal(getBinding, id);
    assert.equal(located.identifier, id);
    assert.equal(requests.at(-1).url, `/tenant/v1/proposals/${id}?accessProfile=author`);
    const getCount = requests.length;
    for (const invalid of ['../secret', id.toUpperCase(), '00000000-0000-0000-0000-00000000000A']) {
      if (invalid === id) continue;
      await assert.rejects(client.getProposal(getBinding, invalid), error => error.kind === 'invalid-request');
    }
    assert.equal(requests.length, getCount);
    const binding = contract.selectAction('correct', 'author');
    const draft = await client.startProposal(binding, '{}', 'start-once');
    assert.equal(draft.identifier, id);
    assert.equal(JSON.parse(draft.documentJson).submissionVersion, 0);
    const attempt = client.prepareProposal(draft, 'submit', '{}', 'submit-once');
    const saved = attempt.toBytes();
    const restored = BRegPreparedProposal.fromBytes(saved);
    const before = requests.length;
    await assert.rejects(client.executeProposal(restored), error => error.kind === 'invalid-request');
    assert.equal(requests.length, before);
    const current = await client.readProposal(draft);
    const recovered = client.recoverProposal(current, restored);
    assert.deepEqual(recovered.toBytes(), saved);
    await client.executeProposal(recovered);
    const sent = requests.at(-1);
    assert.equal(sent.url, `/tenant/v1/proposals/${id}/submit?accessProfile=author`);
    assert.equal(sent.body, '{}');
    assert.equal(sent.headers['if-match'], '"draft-condition"');
    assert.equal(sent.headers['idempotency-key'], 'submit-once');
    const page = await client.listProposals(contract.selectProposals('author'), '{"action":"correct","top":1}');
    assert.equal(page.items[0].identifier, id);
    assert.equal(page.nextCursor, undefined);
    assert.throws(() => client.prepareProposal(draft, 'submit', '{"input":{}}', 'invalid-body'), error => error.kind === 'invalid-request');
    const foreign = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/other/`});
    await assert.rejects(foreign.getProposal(getBinding, id), error => error.kind === 'invalid-request');
    await assert.rejects(foreign.readProposal(draft), error => error.kind === 'invalid-request');
  } finally { await new Promise(resolve => server.close(resolve)); }
});
