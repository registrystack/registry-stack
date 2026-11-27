'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { createHash } = require('node:crypto');
const { test } = require('node:test');
const { BaseRegistryClient } = require('..');

test('additions preserve the submitted version and use exact binary exchanges', async () => {
  const id = '00000000-0000-4000-8000-000000000001';
  const file = '00000000-0000-4000-8000-000000000002';
  const revision = `sha256:${'a'.repeat(64)}`;
  const bytes = Buffer.from('support');
  const metadata = { id: 'additions', version: '1', revision, metadataVersion: '2', recordTypes: [], operations: [], actions: [],
    proposals: {actions: [{actionId: 'correct', accessProfile: 'writer', operations: ['get'], readableInputs: [], readableContextFields: []}],
      get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['writer']}} };
  const document = {id, actionId: 'correct', actionRevision: revision, submissionVersion: 1, revision: 2, state: 'submitted', effectDigest: revision, links: {},
    additions: {other: {id: 'other', maximumBytes: 64, maximumCount: 2, contentTypes: ['text/plain'], classification: 'restricted', items: [],
      links: {add: {method: 'POST', path: `/v1/proposals/${id}/additions/other`, accessProfile: 'writer', operation: 'add', ifMatch: '"condition"'}}}}};
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    requests.push({method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks)});
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('cache-control', 'no-store');
    if (request.url.includes(`/additions/${file}?`)) {
      response.setHeader('content-type', 'text/plain'); response.setHeader('content-disposition', 'attachment');
      response.setHeader('x-content-type-options', 'nosniff'); response.setHeader('vary', 'authorization');
      return response.end(bytes);
    }
    if (request.method === 'POST') {
      document.revision++;
      document.additions.other.items.push({id: file, submissionVersion: 1, sha256: createHash('sha256').update(bytes).digest('hex'),
        byteSize: bytes.length, contentType: 'text/plain', addedAt: '2026-11-27T00:00:00Z', verificationStatus: 'notRequired',
        links: {download: {method: 'GET', path: `/v1/proposals/${id}/additions/${file}?submissionVersion=1`, accessProfile: 'writer', operation: 'download'}}});
    }
    response.setHeader('content-type', 'application/json'); response.setHeader('vary', 'authorization, accept');
    response.end(JSON.stringify(request.url.includes('/registry?') ? metadata : document));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    assert.equal(typeof client.addProposalAddition, 'function');
    assert.equal(typeof client.downloadProposalAddition, 'function');
    const contract = await client.registryContract('writer');
    const prior = await client.getProposal(contract.selectProposalGet('writer'), id);
    const before = requests.length;
    await assert.rejects(client.addProposalAddition(prior, 'other', 'application/pdf', bytes, 'refused'), error => error.kind === 'invalid-request');
    assert.equal(requests.length, before);
    const added = await client.addProposalAddition(prior, 'other', 'text/plain', bytes, 'addition-one');
    assert.equal(JSON.parse(added.documentJson).submissionVersion, 1);
    assert.deepEqual((await client.downloadProposalAddition(added, file)).body, bytes);
    const upload = requests[before];
    assert.equal(upload.method, 'POST'); assert.equal(upload.headers['if-match'], '"condition"');
    assert.equal(upload.headers['idempotency-key'], 'addition-one'); assert.deepEqual(upload.body, bytes);
    assert.equal(upload.url, `/tenant/v1/proposals/${id}/additions/other?accessProfile=writer`);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
