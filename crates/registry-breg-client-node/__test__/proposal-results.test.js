'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const {inspect} = require('node:util');
const {test} = require('node:test');
const {BaseRegistryClient} = process.env.BREG_CLIENT_PACKAGE
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

test('authorized Proposal receipts preserve inert result references and refuse widened or malformed projections', async () => {
  let value = document();
  const requests = [];
  const metadata = {id: 'registry', version: '1', revision: digest, metadataVersion: '1', recordTypes: [], operations: [],
    proposals: {method: 'GET', path: '/v1/proposals', accessProfiles: [],
      get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['reader']}}};
  const server = http.createServer((request, response) => {
    requests.push(request.url);
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
  } finally { await new Promise(resolve => server.close(resolve)); }
});
