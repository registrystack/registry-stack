'use strict';
const assert = require('node:assert/strict');
const { inspect } = require('node:util');
const { test } = require('node:test');
const binding = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const {
  BaseRegistryClient,
  BaseRegistryClientError,
  BRegRequestResultReference,
  BRegRetainedRequestProposalView,
  BRegRetainedRequestHistoryPage,
} = binding;

const requestId = '00000000-0000-4000-8000-000000000001';
const applicationId = '00000000-0000-4000-8000-000000000002';
const targetId = '00000000-0000-4000-8000-000000000003';
const digest = 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function record(resultLinks = [{
  targetEntityId: 'person', targetRecordId: targetId, targetRevision: 4,
}]) {
  return {
    data: {
      recordIdentifier: requestId,
      revisionIdentifier: '8',
      domainData: {},
      request: {
        bregState: 'applied', proposalVersion: 2, editable: false,
        application: {
          applicationId, proposalVersion: 2, effectDigest: digest,
          appliedAt: '2026-09-20T00:00:00Z',
        },
        history: {
          proposals: [{
            requestEntityId: 'request', requestId, proposalVersion: 2,
            bregState: 'applied', current: true, contractFingerprint: digest,
            detailErased: false, applicationId,
            resultLinkCount: resultLinks.length, resultLinks,
          }],
          nextAfterProposalVersion: 2,
        },
      },
    },
    meta: {
      registryIdentifier: 'registry', datasetIdentifier: 'dataset', entityTypeIdentifier: 'request',
    },
  };
}

test('request history projects exact inert results without I/O', () => {
  const client = new BaseRegistryClient({ baseUrl: 'http://127.0.0.1:1' });
  const page = client.requestHistory(record());
  assert(page instanceof BRegRetainedRequestHistoryPage);
  assert.equal(page.nextAfterProposalVersion, 2);
  const proposal = page.findApplication('request', requestId, 2, applicationId);
  assert(proposal instanceof BRegRetainedRequestProposalView);
  assert.equal(proposal.resultLinkCount, 1);
  assert(proposal.resultReferences[0] instanceof BRegRequestResultReference);
  assert.equal(proposal.resultReferences[0].targetEntityIdentifier, 'person');
  assert.equal(proposal.resultReferences[0].targetRecordIdentifier, targetId);
  assert.equal(proposal.resultReferences[0].targetRevision, 4);
  assert.equal(proposal.toString(), 'BRegRetainedRequestProposal(<redacted>)');
  assert.equal(proposal.resultReferences[0].toString(), 'BRegRequestResultReference(<redacted>)');
  assert.doesNotMatch(inspect(page), new RegExp(`${requestId}|${targetId}|${applicationId}|person`));

  const withoutHistory = record();
  delete withoutHistory.data.request.history;
  assert.equal(client.requestHistory(withoutHistory), null);
  const empty = client.requestHistory(record([]));
  assert.equal(empty.proposals[0].resultLinkCount, 0);
  assert.deepEqual(empty.proposals[0].resultReferences, []);
});

test('request history refuses malformed shapes without I/O', () => {
  const client = new BaseRegistryClient({ baseUrl: 'http://127.0.0.1:1' });
  const candidates = [
    value => { value.data.request.history.proposals[0].resultLinkCount = 2; },
    value => { value.data.request.history.proposals[0].applicationId = null; },
    value => { value.data.request.history.proposals[0].resultLinks[0].targetRevision = 0; },
    value => { value.data.request.history.proposals[0].resultLinks[0].targetRevision = Number.MAX_SAFE_INTEGER + 1; },
    value => { value.data.request.history.nextAfterProposalVersion = 1; },
    value => { value.data.request.history.proposals[0].unknown = true; },
  ];
  for (const mutate of candidates) {
    const value = record();
    mutate(value);
    assert.throws(() => client.requestHistory(value), error => error.kind === 'invalid_request');
  }
});

test('request history lookup helpers normalize invalid identities and versions', () => {
  const client = new BaseRegistryClient({ baseUrl: 'http://127.0.0.1:1' });
  const page = client.requestHistory(record());
  for (const invoke of [
    () => page.findProposal('request', 'not-a-uuid', 2),
    () => page.findProposal('request', requestId, 0),
    () => page.findProposal('request', requestId, 0x1_0000_0000),
    () => page.findApplication('request', requestId, 2, 'not-a-uuid'),
  ]) {
    assert.throws(invoke, error => (
      error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
    ));
  }
});
