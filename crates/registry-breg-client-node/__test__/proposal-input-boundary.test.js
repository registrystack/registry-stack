'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient, BRegPreparedProposal } = require('..');

const id = '00000000-0000-4000-8000-000000000001';
const revision = `sha256:${'a'.repeat(64)}`;
const maximum = 3 * 1024 * 1024;
const metadata = {id: 'proposal-input', version: '1', revision, metadataVersion: '2',
  recordTypes: [], operations: [], actions: [], proposals: {
    get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['writer']},
    actions: [{actionId: 'correct', accessProfile: 'writer', operations: ['get'], readableInputs: [], readableContextFields: []}],
  }};

// JCS expands exponent-form 1e20 literals to twenty-one digits.
const input = size => {
  const value = Object.fromEntries(['a', 'b', 'c', 'd'].map(key => [key, Array(35746).fill(1e20)]));
  value.d.push('x'.repeat(size - 3145673 - 3));
  return value;
};
// JSON.stringify uses JCS number spelling, so retain compact exponent literals
// explicitly in this known numeric fixture passed through the JSON-text API.
const body = size => JSON.stringify({input: input(size)}).replaceAll('100000000000000000000', '1e20');

test('Proposal input canonical bound is preserved through native preparation and recovery', async () => {
  let document;
  let requests = 0;
  const bodies = [];
  const server = http.createServer(async (request, response) => {
    let received = '';
    for await (const chunk of request) received += chunk;
    if (request.method === 'POST') bodies.push(received);
    requests += 1;
    response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store',
      vary: 'authorization, accept', traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
    response.end(JSON.stringify(request.url.startsWith('/v1/registry') ? metadata : document));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/`});
    const get = (await client.registryContract('writer')).selectProposalGet('writer');
    for (const [operation, state] of [['edit', 'draft'], ['revise', 'submitted'], ['rebase', 'draft'], ['rebase', 'submitted']]) {
      document = {id, actionId: 'correct', actionRevision: revision, submissionVersion: 1, revision: 2,
        state, ...(state === 'submitted' ? {effectDigest: revision} : {}), links: {
          self: {method: 'GET', path: `/v1/proposals/${id}`, accessProfile: 'writer', operation: 'get'},
          [operation]: {method: 'POST', path: `/v1/proposals/${id}/${operation}`, accessProfile: 'writer',
            operation, ifMatch: '"condition"'},
        }};
      const held = await client.getProposal(get, id);
      const before = requests;
      const oversized = body(maximum + 1);
      assert.ok(Buffer.byteLength(oversized) < 2 * 1024 * 1024);
      assert.throws(() => client.prepareProposal(held, operation, oversized, 'bounded-input'),
        error => error.kind === 'invalid-request');
      const attempt = client.prepareProposal(held, operation, body(maximum), 'bounded-input');
      const saved = attempt.toBytes();
      const restored = BRegPreparedProposal.fromBytes(saved);
      const recovered = client.recoverProposal(held, restored);
      assert.deepEqual(recovered.toBytes(), saved);
      const invalid = JSON.parse(saved.toString());
      invalid.body = oversized;
      assert.throws(() => BRegPreparedProposal.fromBytes(Buffer.from(JSON.stringify(invalid))),
        error => error.kind === 'invalid-request');
      assert.equal(requests, before);
      document = {...document, state: 'draft', revision: 3, submissionVersion: state === 'submitted' ? 2 : 1};
      delete document.effectDigest;
      await client.executeProposal(recovered);
      assert.equal(requests, before + 1);
      assert.equal(bodies.at(-1), JSON.parse(saved.toString()).body);
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});
