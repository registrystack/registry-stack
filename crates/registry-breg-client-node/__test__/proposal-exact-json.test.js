'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient, BRegPreparedProposal } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const id = '00000000-0000-4000-8000-000000000001';
const revision = `sha256:${'a'.repeat(64)}`;
const metadata = {id: 'proposal-json', version: '1', revision, metadataVersion: '2', recordTypes: [], operations: [],
  proposals: {method: 'GET', path: '/v1/proposals', accessProfiles: ['author'],
    actions: [{actionId: 'correct', accessProfile: 'author', operations: ['get', 'list'], readableInputs: [], readableContextFields: []}],
    get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['author']}}};
const proposal = {id, actionId: 'correct', actionRevision: revision, submissionVersion: 1, revision: 1, state: 'draft', links: {
  self: {method: 'GET', path: `/v1/proposals/${id}`, accessProfile: 'author', operation: 'get'},
  edit: {method: 'POST', path: `/v1/proposals/${id}/edit`, accessProfile: 'author', operation: 'edit', ifMatch: '"draft-condition"'},
}};
const inputJson = '{"nullable":null,"nested":{"wide":9223372036854775807,"decimal":"0.7500","values":[9223372036854775807,null,{"amount":"0.7500"}]}}';

test('exact Proposal JSON methods preserve nested values and recovery authority through native HTTP', async () => {
  const requests = [];
  let current = JSON.stringify(proposal).replace('"links":', `"input":${inputJson},"links":`);
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({url: request.url, body, headers: request.headers});
    response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store', vary: 'authorization, accept',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
    if (request.url.startsWith('/tenant/v1/registry')) return response.end(JSON.stringify(metadata));
    if (request.url.startsWith('/tenant/v1/proposals?')) return response.end(`{"items":[${current}],"nextCursor":"next-page"}`);
    if (request.url.includes('/edit?')) {
      current = current.replace('"revision":1', '"revision":2').replace(inputJson, body.slice('{"input":'.length, -1));
    }
    response.end(current);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    assert.equal(typeof client.prepareProposalJson, 'function');
    assert.equal(typeof client.listProposalsJson, 'function');
    const contract = await client.registryContract('author');
    const collection = contract.selectProposals('author');
    const page = await client.listProposalsJson(collection, '{"action":"correct","limit":1}');
    assert.equal(page.nextCursor, 'next-page');
    assert.match(page.items[0].inputJson, /9223372036854775807/);
    assert.match(page.items[0].inputJson, /"decimal":"0.7500"/);
    const url = new URL(requests.at(-1).url, 'http://fixture.invalid');
    assert.equal(url.pathname, '/tenant/v1/proposals');
    assert.equal(url.searchParams.get('accessProfile'), 'author');
    assert.equal(url.searchParams.get('action'), 'correct');
    assert.equal(url.searchParams.get('limit'), '1');
    const draft = page.items[0];
    const before = requests.length;
    for (const body of ['{"input":{"wide":1,"wide":2}}', '{"input":{"wide":1e9999}}', '{"input":[]}', '[]']) {
      assert.throws(() => client.prepareProposalJson(draft, 'edit', body, 'invalid'), error => error.kind === 'invalid-request' && !error.outcomeUnknown);
    }
    assert.throws(() => client.prepareProposalJson(draft, 'apply', '{}', 'illegal-transition'), error => error.kind === 'invalid-request');
    assert.throws(() => client.prepareProposal(draft, 'edit', {input: {wide: Number.MAX_SAFE_INTEGER + 1}}, 'unsafe'), error => error.kind === 'invalid-request');
    for (const query of ['{"limit":1,"limit":2}', '{"limit":0}', '{"unknown":true}', '{"limit":"one"}']) {
      await assert.rejects(client.listProposalsJson(collection, query), error => error.kind === 'invalid-request', query);
    }
    assert.equal(requests.length, before, 'invalid JSON, query, structured unsafe numbers and transitions fail before I/O');
    assert.throws(() => client.prepareProposalJson(draft, 'edit', `{"input":${inputJson}}`, 'inexact-binary64'), error => error.kind === 'invalid-request');
    const exactEditInputJson = inputJson.replaceAll('9223372036854775807', '9007199254740992');
    const attempt = client.prepareProposalJson(draft, 'edit', `{"input":${exactEditInputJson}}`, 'exact-edit-key');
    const bytes = attempt.toBytes();
    const restored = BRegPreparedProposal.fromBytes(bytes);
    await assert.rejects(client.executeProposal(restored), error => error.kind === 'invalid-request');
    assert.equal(requests.length, before, 'persisted evidence requires fresh matching Proposal authority');
    const recovered = client.recoverProposal(await client.readProposal(draft), restored);
    assert.deepEqual(recovered.toBytes(), bytes);
    const edited = await client.executeProposal(recovered);
    assert.match(edited.inputJson, /9007199254740992/);
    const sent = requests.at(-1);
    assert.equal(sent.url, `/tenant/v1/proposals/${id}/edit?accessProfile=author`);
    assert.equal(sent.headers['idempotency-key'], 'exact-edit-key');
    assert.equal(sent.headers['if-match'], '"draft-condition"');
    assert.match(sent.body, /"wide":9007199254740992/);
    assert.match(sent.body, /"decimal":"0.7500"/);
    assert.match(sent.body, /"values":\[9007199254740992,null,\{"amount":"0.7500"\}\]/);
    assert.equal(JSON.parse(sent.body).input.nullable, null);
    assert.ok(!Object.hasOwn(JSON.parse(sent.body).input, 'absent'));
  } finally { await new Promise(resolve => server.close(resolve)); }
});
