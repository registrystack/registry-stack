'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient } = require('..');

test('answers use the promoted ask link, exact body, ETag and caller key', async () => {
  const id = '00000000-0000-4000-8000-000000000001';
  const ask = '00000000-0000-4000-8000-000000000007';
  const digest = `sha256:${'a'.repeat(64)}`;
  const metadata = {id: 'asks', version: '1', revision: digest, metadataVersion: '2', recordTypes: [], operations: [], actions: [],
    proposals: {actions: [{actionId: 'correct', accessProfile: 'author', operations: ['get', 'answer'], readableInputs: [], readableContextFields: []}],
      get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['author']}}};
  const document = {id, actionId: 'correct', actionRevision: digest, submissionVersion: 1, revision: 2, state: 'submitted', effectDigest: digest, links: {},
    asks: [{id: ask, text: 'Why?', wants: [{kind: 'answer'}], askedAt: '2026-11-27T00:00:00Z', state: 'open', links: {
      answer: {method: 'POST', path: `/v1/proposals/${id}/asks/${ask}/answer`, accessProfile: 'author', operation: 'answer', ifMatch: '"condition"', availability: {available: true, observedRevision: 2}}}}]};
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    requests.push({method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks)});
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('cache-control', 'no-store'); response.setHeader('content-type', 'application/json'); response.setHeader('vary', 'authorization, accept');
    if (request.method === 'POST') {
      document.revision = 3; document.asks[0].state = 'answered';
      document.asks[0].answer = {...JSON.parse(requests.at(-1).body), additions: [], answeredAt: '2026-11-27T01:00:00Z'};
      document.asks[0].links.answer.availability = {available: false, observedRevision: 3, reason: 'ask-answered', recovery: 'receipt-only'};
      response.setHeader('etag', `"breg-v1-${'c'.repeat(64)}"`);
    }
    response.end(JSON.stringify(request.url.includes('/registry?') ? metadata : document));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    assert.equal(typeof client.answerProposalAsk, 'function');
    const contract = await client.registryContract('author');
    const prior = await client.getProposal(contract.selectProposalGet('author'), id);
    const before = requests.length;
    await assert.rejects(client.answerProposalAsk(prior, ask, {text: ' '}, 'invalid'), error => error.kind === 'invalid-request');
    assert.equal(requests.length, before);
    document.asks[0].wants = [];
    const withoutWants = await client.getProposal(contract.selectProposalGet('author'), id);
    const beforeEmpty = requests.length;
    for (const body of [{}, {additions: []}]) {
      await assert.rejects(client.answerProposalAsk(withoutWants, ask, body, 'empty'), error => error.kind === 'invalid-request');
    }
    assert.equal(requests.length, beforeEmpty);
    document.asks[0].wants = [{kind: 'answer'}];
    const answered = await client.answerProposalAsk(prior, ask, {text: 'The explanation'}, 'answer-one');
    assert.equal(JSON.parse(answered.documentJson).asks[0].answer.text, 'The explanation');
    const wire = requests.at(-1);
    assert.equal(wire.url, `/tenant/v1/proposals/${id}/asks/${ask}/answer?accessProfile=author`);
    assert.equal(wire.headers['if-match'], '"condition"'); assert.equal(wire.headers['idempotency-key'], 'answer-one');
    assert.deepEqual(JSON.parse(wire.body), {text: 'The explanation'});
  } finally { await new Promise(resolve => server.close(resolve)); }
});
