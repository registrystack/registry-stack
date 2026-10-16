'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient, BRegProposalReviewBinding } = require('..');

test('review-only binding reads context and exact document without Proposal Get', async () => {
  const id = '00000000-0000-4000-8000-000000000001';
  const revision = `sha256:${'a'.repeat(64)}`;
  const body = Buffer.from('%PDF-1.7 synthetic review document');
  const requests = [];
  const metadata = { id: 'review-documents', version: '1', revision, metadataVersion: '2',
    recordTypes: [], operations: [], actions: [], proposals: { actions: [
      { actionId: 'correct', accessProfile: 'reviewer', operations: ['get-review-context'], readableInputs: [] },
      { actionId: 'correct', accessProfile: 'status', operations: ['get-review-status'], readableInputs: [] },
    ] } };
  const query = new URLSearchParams({ submissionVersion: '1', reviewContextField: 'support',
    effectDigest: revision, contextSchemaDigest: revision });
  const context = { id, actionId: 'correct', actionRevision: revision, submissionVersion: 1, revision: 2,
    effectDigest: revision, subject: { source: 'review-documents', subjectType: 'proposal', id, version: '1', digest: revision },
    reviewable: true, context: { reference: 'opaque',
      contract: { id: 'urn:registry:breg:review-context:review-documents:correct:review', revision, schemaDigest: revision },
      fields: { support: { type: 'document', slotId: 'support', contentType: 'application/pdf', byteSize: body.length,
        sha256: createHash('sha256').update(body).digest('hex'), download: { method: 'GET', operation: 'get-review-context',
          accessProfile: 'reviewer', path: `/v1/proposals/${id}/attachments/support?${query}` } } } } };
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    if (request.url.includes('/attachments/')) {
      response.setHeader('vary', 'authorization');
      response.setHeader('content-type', 'application/pdf');
      response.setHeader('content-disposition', 'attachment');
      response.setHeader('x-content-type-options', 'nosniff');
      return response.end(body);
    }
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(request.url.includes('/registry?') ? metadata : context));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}/tenant/` });
    const contract = await client.registryContract('reviewer');
    assert.throws(() => contract.selectProposalGet('reviewer'));
    const binding = contract.selectProposalReviewContext('reviewer', 'correct');
    assert.ok(binding instanceof BRegProposalReviewBinding);
    const observed = (await client.readProposalReviewById(binding, id)).value;
    const downloaded = await client.downloadProposalReviewDocument(binding, observed, 'support');
    assert.deepEqual(downloaded.body, body);
    assert.equal(downloaded.mediaType, 'application/pdf');
    const url = new URL(requests.at(-1), 'http://local');
    assert.equal(url.pathname, `/tenant/v1/proposals/${id}/attachments/support`);
    assert.equal(url.searchParams.get('accessProfile'), 'reviewer');
    assert.equal(url.searchParams.get('reviewContextField'), 'support');
    assert.equal(url.searchParams.get('contextSchemaDigest'), revision);
    const before = requests.length;
    const tampered = structuredClone(observed);
    tampered.context.fields.support.download.path = 'https://untrusted.invalid/file';
    await assert.rejects(client.downloadProposalReviewDocument(binding, tampered, 'support'), error => error.kind === 'invalid-request');
    await assert.rejects(client.downloadProposalReviewDocument(
      contract.selectProposalReviewStatus('status', 'correct'), observed, 'support'), error => error.kind === 'invalid-request');
    assert.equal(requests.length, before);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
