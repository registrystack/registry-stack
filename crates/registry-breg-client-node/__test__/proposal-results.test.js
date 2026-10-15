'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const {createHash} = require('node:crypto');
const {inspect} = require('node:util');
const {test} = require('node:test');
const {BaseRegistryClient, BRegPreparedProposal} = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const id = '00000000-0000-4000-8000-000000000001';
const targetId = '00000000-0000-4000-8000-000000000003';
const digest = `sha256:${'a'.repeat(64)}`;
const document = () => ({id, actionId: 'correct', actionRevision: digest, submissionVersion: 2, revision: 8, state: 'applied',
  effectDigest: digest, links: {self: {method: 'GET', path: `/v1/proposals/${id}`, accessProfile: 'reader', operation: 'get'}},
  application: {applicationId: id, submissionVersion: 2, effectDigest: digest,
    resultLinks: [{recordType: 'person', recordId: targetId, revision: 4}]}});

const statusDocument = state => {
  const value = document();
  value.state = ['applied', 'cancelled'].includes(state) ? state : 'submitted';
  if (state !== 'applied') delete value.application;
  value.applicationStatus = {state, mode: 'automatic'};
  if (['pending', 'blocked'].includes(state)) {
    value.applicationStatus.automaticRetry = {scheduled: state === 'pending', attempts: state === 'pending' ? 0 : 1, maximumAttempts: 3};
  }
  if (state === 'blocked') Object.assign(value.applicationStatus, {reason: 'dependency-outage', recovery: 'retry'});
  return value;
};

test('Proposal response boundaries preserve disclosure and exact Action revision bindings', async t => {
  let value = document();
  let downloadBytes;
  const requests = [];
  const metadata = {id: 'registry', version: '1', revision: digest, metadataVersion: '1', recordTypes: [], operations: [],
    proposals: {method: 'GET', path: '/v1/proposals', accessProfiles: [],
      get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['reader']}}};
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    if (downloadBytes !== undefined && request.method === 'GET' && request.url.includes('/attachments/')) {
      response.writeHead(200, {'content-type': 'application/pdf', 'content-disposition': 'attachment', 'x-content-type-options': 'nosniff',
        'cache-control': 'no-store', vary: 'authorization', traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
      response.end(downloadBytes);
      return;
    }
    response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store', 'vary': 'authorization, accept',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
    response.end(JSON.stringify(request.url.startsWith('/v1/registry') ? metadata : value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}`});
    const binding = (await client.registryContract('reader')).selectProposalGet('reader');
    const proposal = await client.getProposal(binding, id);
    assert.deepEqual(JSON.parse(proposal.documentJson).application.resultLinks, [{recordType: 'person', recordId: targetId, revision: 4}]);
    assert.doesNotMatch(inspect(proposal), new RegExp(`${id}|${targetId}|person`));
    const count = requests.length;
    assert.throws(() => client.prepareProposal(proposal, 'apply', '{}', 'ungranted'), error => error.kind === 'invalid-request');
    assert.equal(requests.length, count);
    for (const state of ['pending', 'blocked', 'applied', 'cancelled']) {
      value = statusDocument(state);
      const observed = JSON.parse((await client.getProposal(binding, id)).documentJson);
      assert.deepEqual(observed.applicationStatus, value.applicationStatus, state);
      assert.equal(observed.submissionVersion, 2);
      assert.equal(observed.effectDigest, digest);
    }
    for (const state of ['applied', 'cancelled']) {
      value = statusDocument(state);
      delete value.applicationStatus;
      delete value.application;
      delete value.effectDigest;
      const observed = JSON.parse((await client.getProposal(binding, id)).documentJson);
      assert.ok(!Object.hasOwn(observed, 'applicationStatus'), `${state}: erased retained evidence`);
    }
    value = document();
    value.application.resultLinks = [];
    assert.deepEqual(JSON.parse((await client.getProposal(binding, id)).documentJson).application.resultLinks, []);
    delete value.application;
    assert.ok(!Object.hasOwn(JSON.parse((await client.getProposal(binding, id)).documentJson), 'application'));
    for (const mutate of [
      item => {item.application.submissionVersion = 1;},
      item => {item.application.effectDigest = 'sha256:UPPERCASE';},
      item => {item.application.resultLinks[0].revision = 0;},
      item => {item.application.resultLinks[0].recordId = 'not-a-uuid';},
      item => {item.application.actorReference = 'private-canary';},
      item => {item.application.reason = 'private-canary';},
      item => {item.application.resultLinks[0].href = 'https://elsewhere.invalid/private';},
    ]) {
      value = document(); mutate(value);
      await assert.rejects(client.getProposal(binding, id), error => ['invalid-request', 'protocol'].includes(error.kind));
    }

    await t.test('promoted review Status refuses display fields while Context preserves them', async () => {
      value = document(); value.state = 'submitted'; delete value.application;
      for (const [name, suffix, operation] of [['reviewStatus', 'review-status', 'get-review-status'], ['reviewContext', 'review-context', 'get-review-context']]) {
        value.links[name] = {method: 'GET', path: `/v1/proposals/${id}/${suffix}`, accessProfile: 'reader', operation};
      }
      const prior = await client.getProposal(binding, id);
      const status = {id, actionId: 'correct', actionRevision: digest, submissionVersion: 2, revision: 8, effectDigest: digest,
        subject: {source: 'directory', subjectType: 'proposal', id, version: '2', digest},
        context: {reference: 'breg:directory:correct:proposal:2'}, reviewable: true};
      value = structuredClone(status);
      assert.equal((await client.readProposalReviewStatus(prior)).value.context.reference, status.context.reference);
      for (const fields of [{}, {private: 'private-canary'}]) {
        value = structuredClone(status); value.context.fields = fields;
        const count = requests.length;
        await assert.rejects(client.readProposalReviewStatus(prior), error => error.kind === 'invalid-request' && !error.message.includes('private-canary'));
        assert.equal(requests.length, count + 1);
        assert.match(requests.at(-1), /\/review-status\?accessProfile=reader$/);
      }
      value.context.contract = {id: 'urn:registry:breg:review-context:directory:correct:review', revision: digest, schemaDigest: digest};
      assert.deepEqual((await client.readProposalReviewContext(prior)).value.context.fields, {private: 'private-canary'});
    });
    await t.test('non-Rebase transitions and attachment writes preserve the bound Action revision', async () => {
      const successor = `sha256:${'b'.repeat(64)}`;
      value = document(); value.state = 'draft'; delete value.application;
      value.links.edit = {method: 'POST', path: `/v1/proposals/${id}/edit`, accessProfile: 'reader', operation: 'edit', ifMatch: '"edit-condition"'};
      value.attachments = {support: {id: 'support', required: false, maximumBytes: 1024, contentTypes: ['application/pdf'], classification: 'restricted',
        links: {upload: {method: 'PATCH', path: `/v1/proposals/${id}/attachments/support`, accessProfile: 'reader', operation: 'upload', ifMatch: '"attachment-condition"'},
          remove: {method: 'DELETE', path: `/v1/proposals/${id}/attachments/support`, accessProfile: 'reader', operation: 'remove', ifMatch: '"attachment-condition"'}}}};
      const prior = await client.getProposal(binding, id);
      const current = structuredClone(value); current.revision++;
      const attempt = client.prepareProposal(prior, 'edit', '{"input":{}}', 'edit-binding');
      for (const send of [() => client.executeProposal(attempt),
        () => client.uploadProposalAttachment(prior, 'support', 'application/pdf', Buffer.from('%PDF-fixture'), 'upload-binding'),
        () => client.deleteProposalAttachment(prior, 'support', 'remove-binding')]) {
        value = structuredClone(current);
        assert.equal(JSON.parse((await send()).documentJson).actionRevision, digest);
        value.actionRevision = successor;
        const count = requests.length;
        await assert.rejects(send(), error => error.kind === 'invalid-request');
        assert.equal(requests.length, count + 1, 'validate the actual received mutation response');
      }
      assert.equal(JSON.parse((await client.readProposal(prior)).documentJson).actionRevision, successor, 'ordinary reads can observe a new revision');
    });
    await t.test('explicit Rebase and exact recovery admit only the next successor Draft', async () => {
      for (const [state, before, after] of [['draft', 0, 0], ['submitted', 2, 3]]) {
        value = document(); value.state = state; value.submissionVersion = before; delete value.application;
        value.links.rebase = {method: 'POST', path: `/v1/proposals/${id}/rebase`, accessProfile: 'reader', operation: 'rebase', ifMatch: '"rebase-condition"',
          availability: {available: true, observedRevision: 8}};
        const prior = await client.getProposal(binding, id);
        const attempt = client.prepareProposal(prior, 'rebase', '{"input":{}}', `rebase-${state}`);
        const saved = attempt.toBytes();
        value.state = 'draft'; value.submissionVersion = after; value.revision = 9;
        value.actionRevision = `sha256:${'b'.repeat(64)}`; value.links.rebase.availability.observedRevision = 9;
        const rebased = await client.executeProposal(attempt);
        const restored = BRegPreparedProposal.fromBytes(saved);
        const recovered = client.recoverProposal(rebased, restored);
        assert.deepEqual(recovered.toBytes(), saved);
        assert.equal(JSON.parse((await client.executeProposal(recovered)).documentJson).actionRevision, value.actionRevision);
        value.revision = 10; value.links.rebase.availability.observedRevision = 10;
        const later = await client.getProposal(binding, id);
        const count = requests.length;
        assert.throws(() => client.recoverProposal(later, restored), error => error.kind === 'invalid-request');
        assert.equal(requests.length, count);
      }
    });

    await t.test('retained attachment download uses disclosed value size while upload uses current policy', async () => {
      downloadBytes = Buffer.from('%PDF-retained');
      value = document(); value.state = 'draft'; delete value.application;
      value.attachments = {support: {id: 'support', required: false, maximumBytes: 4, contentTypes: ['text/plain'], classification: 'restricted',
        value: {submissionVersion: 2, sha256: createHash('sha256').update(downloadBytes).digest('hex'), contentType: 'application/pdf', byteSize: downloadBytes.length, verificationStatus: 'notRequired'},
        links: {download: {method: 'GET', path: `/v1/proposals/${id}/attachments/support?submissionVersion=2`, accessProfile: 'reader', operation: 'download'},
          upload: {method: 'PATCH', path: `/v1/proposals/${id}/attachments/support`, accessProfile: 'reader', operation: 'upload', ifMatch: '"attachment-condition"'}}}};
      const retained = await client.getProposal(binding, id);
      assert.deepEqual((await client.downloadProposalAttachment(retained, 'support')).body, downloadBytes);
      const count = requests.length;
      await assert.rejects(client.uploadProposalAttachment(retained, 'support', 'application/pdf', Buffer.from('%PDF'), 'wrong-media'), error => error.kind === 'invalid-request');
      await assert.rejects(client.uploadProposalAttachment(retained, 'support', 'text/plain', Buffer.from('12345'), 'too-large'), error => error.kind === 'invalid-request');
      assert.equal(requests.length, count, 'new uploads keep current policy before I/O');
      await client.uploadProposalAttachment(retained, 'support', 'text/plain', Buffer.from('ok'), 'allowed-upload');
      downloadBytes = Buffer.concat([downloadBytes, Buffer.from('x')]);
      await assert.rejects(client.downloadProposalAttachment(retained, 'support'), error => error.kind === 'transport' && error.transportKind === 'response-too-large');
    });
  } finally { await new Promise(resolve => server.close(resolve)); }
});
