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
    appliedBy: `hmac-sha256:${'a'.repeat(64)}`, appliedAt: '2026-10-16T01:02:03.000004Z',
    resultLinks: [{recordType: 'person', recordId: targetId, revision: 4}]}});

const statusDocument = state => {
  const value = document();
  value.state = ['applied', 'cancelled'].includes(state) ? state : 'submitted';
  if (state !== 'applied') delete value.application;
  value.applicationStatus = {state, mode: 'automatic'};
  if (['awaiting-review', 'pending', 'blocked'].includes(state)) {
    value.applicationStatus.automaticRetry = {scheduled: state === 'pending', attempts: state === 'pending' ? 0 : 1, maximumAttempts: 3};
  }
  if (state === 'blocked') Object.assign(value.applicationStatus, {reason: 'dependency-outage', recovery: 'retry'});
  return value;
};

test('Proposal response boundaries preserve disclosure and exact Action revision bindings', async t => {
  let value = document();
  let replyStatus = 200;
  let downloadBytes;
  const requests = [];
  const wireRequests = [];
  const metadata = {id: 'registry', version: '1', revision: digest, metadataVersion: '2', recordTypes: [], operations: [],
    proposals: {method: 'GET', path: '/v1/proposals', accessProfiles: [], actions: [],
      get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['reader']}}};
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push(request.url);
    wireRequests.push({method: request.method, url: request.url, body, key: request.headers['idempotency-key'], condition: request.headers['if-match']});
    if (downloadBytes !== undefined && request.method === 'GET' && request.url.includes('/attachments/')) {
      response.writeHead(200, {'content-type': 'application/pdf', 'content-disposition': 'attachment', 'x-content-type-options': 'nosniff',
        'cache-control': 'no-store', vary: 'authorization', traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
      response.end(downloadBytes);
      return;
    }
    response.writeHead(replyStatus, {'content-type': 'application/json', 'cache-control': 'no-store', 'vary': 'authorization, accept',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
    response.end(JSON.stringify(request.url.startsWith('/v1/registry') ? metadata : value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}`});
    const binding = (await client.registryContract('reader')).selectProposalGet('reader');
    const proposal = await client.getProposal(binding, id);
    assert.deepEqual(JSON.parse(proposal.documentJson).application.resultLinks, [{recordType: 'person', recordId: targetId, revision: 4}]);
    assert.deepEqual(JSON.parse(proposal.documentJson).application.appliedBy, `hmac-sha256:${'a'.repeat(64)}`);
    assert.doesNotMatch(inspect(proposal), new RegExp(`${id}|${targetId}|person`));
    const count = requests.length;
    assert.throws(() => client.prepareProposal(proposal, 'apply', '{}', 'ungranted'), error => error.kind === 'invalid-request');
    assert.equal(requests.length, count);
    for (const state of ['awaiting-review', 'pending', 'blocked', 'applied', 'cancelled']) {
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
    delete value.application; delete value.effectDigest;
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

    await t.test('application identity is canonical and exact receipt recovery survives validation', async () => {
      value = document(); value.state = 'submitted'; delete value.application;
      value.links.apply = {method: 'POST', path: `/v1/proposals/${id}/apply`, accessProfile: 'reader', operation: 'apply', ifMatch: '"apply-condition"'};
      const held = await client.getProposal(binding, id);
      const attempt = client.prepareProposal(held, 'apply', JSON.stringify({submissionVersion: 2, effectDigest: digest}), 'canonical-application');
      const canonical = '123e4567-e89b-42d3-a456-426614174000';
      const lifecycleApplication = structuredClone(document().application);
      delete lifecycleApplication.appliedBy; delete lifecycleApplication.appliedAt;
      const receipt = {...value, state: 'applied', revision: 9, application: {...lifecycleApplication, applicationId: canonical}};
      receipt.links.apply.availability = {available: false, observedRevision: 9, reason: 'already-applied', recovery: 'receipt-only'};
      for (const applicationId of [canonical.toUpperCase(), canonical.replaceAll('-', ''), '00000000-0000-0000-0000-000000000000']) {
        value = structuredClone(receipt); value.application.applicationId = applicationId;
        await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
        await assert.rejects(client.executeProposal(attempt), error => error.kind === 'protocol' && error.outcomeUnknown);
      }
      value = receipt;
      const committed = await client.executeProposal(attempt);
      assert.equal(JSON.parse(committed.documentJson).application.applicationId, canonical);
      const sent = wireRequests.at(-1);
      const recovered = client.recoverProposal(committed, BRegPreparedProposal.fromBytes(attempt.toBytes()));
      assert.deepEqual(recovered.toBytes(), attempt.toBytes());
      await client.executeProposal(recovered);
      assert.deepEqual(wireRequests.at(-1), sent);
    });

    await t.test('attachment availability preserves ordinary links and requires unavailable details', async () => {
      value = document(); value.state = 'draft'; delete value.application; delete value.effectDigest;
      value.links.edit = {method: 'POST', path: `/v1/proposals/${id}/edit`, accessProfile: 'reader', operation: 'edit', ifMatch: '"edit-condition"'};
      value.attachments = {support: {id: 'support', required: false, maximumBytes: 1024, contentTypes: ['application/pdf'], classification: 'restricted',
        links: {upload: {method: 'PATCH', path: `/v1/proposals/${id}/attachments/support`, accessProfile: 'reader', operation: 'upload', ifMatch: '"upload-condition"'}}}};
      const held = await client.getProposal(binding, id);
      const attempt = client.prepareProposal(held, 'edit', '{"input":{}}', 'availability-edit');
      const original = structuredClone(value);
      for (const missing of ['reason', 'recovery']) {
        value = structuredClone(original);
        const availability = {available: false, observedRevision: 8, reason: 'stale-revision', recovery: 'receipt-only'};
        delete availability[missing];
        value.attachments.support.links.upload.availability = availability;
        await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
        value.revision = availability.observedRevision = 9;
        await assert.rejects(client.executeProposal(attempt), error => error.kind === 'protocol' && error.outcomeUnknown);
      }
      for (const availability of [undefined, {available: true, observedRevision: 8},
        {available: false, observedRevision: 8, reason: 'stale-revision', recovery: 'receipt-only'}]) {
        value = structuredClone(original); value.attachments.support.links.upload.availability = availability;
        await client.getProposal(binding, id);
      }
    });

    await t.test('application result record identifiers retain canonical spelling', async () => {
      const canonical = '123e4567-e89b-42d3-a456-426614174000';
      for (const recordId of [canonical, '00000000-0000-0000-0000-000000000000']) {
        value = document(); value.application.resultLinks[0].recordId = recordId;
        assert.equal(JSON.parse((await client.getProposal(binding, id)).documentJson).application.resultLinks[0].recordId, recordId);
      }
      for (const recordId of [canonical.toUpperCase(), canonical.replaceAll('-', '')]) {
        value = document(); value.application.resultLinks[0].recordId = recordId;
        const count = requests.length;
        await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
        assert.equal(requests.length, count + 1, 'validate the actual received result reference');
      }
    });

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
    await t.test('Proposal documents require a version and state-appropriate frozen evidence', async () => {
      for (const state of ['draft', 'submitted', 'applied', 'cancelled']) {
        value = document(); value.state = state; value.submissionVersion = 0;
        delete value.application;
        if (state === 'draft') delete value.effectDigest;
        await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
      }
      value = document(); value.state = 'submitted'; delete value.application; delete value.effectDigest;
      await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
      value = document(); value.state = 'draft'; delete value.application;
      await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
      delete value.effectDigest;
      assert.equal(JSON.parse((await client.getProposal(binding, id)).documentJson).state, 'draft');
      value = document(); delete value.application;
      await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
    });
    await t.test('Review status preserves pending, terminal and expired evidence and Context excludes results', async () => {
      value = document(); value.state = 'submitted'; delete value.application;
      for (const [name, suffix, operation] of [['reviewStatus', 'review-status', 'get-review-status'], ['reviewContext', 'review-context', 'get-review-context']]) {
        value.links[name] = {method: 'GET', path: `/v1/proposals/${id}/${suffix}`, accessProfile: 'reader', operation};
      }
      const prior = await client.getProposal(binding, id);
      const base = {id, actionId: 'correct', actionRevision: digest, submissionVersion: 2, revision: 8, effectDigest: digest,
        subject: {source: 'directory', subjectType: 'proposal', id, version: '2', digest},
        context: {reference: `breg:directory:correct:${id}:2`}, reviewable: true};
      const configured = {...base, authority: 'review-provider', policy: {id: 'review', version: '1', digest}};
      const canonicalId = '123e4567-e89b-42d3-a456-426614174000';
      const terminal = {state: 'approved', resultId: targetId, completedAt: '2026-10-01T00:00:00.000000Z', availableUntil: '2026-10-02T00:00:00.000000Z'};
      value = structuredClone(base);
      assert.ok(!Object.hasOwn((await client.readProposalReviewStatus(prior)).value, 'result'));
      for (const result of [{state: 'pending'}, ...['approved', 'rejected', 'changes-requested', 'answered', 'cancelled', 'superseded', 'expired'].map(state => ({...terminal, state}))]) {
        value = {...structuredClone(configured), requestId: id, result};
        assert.deepEqual((await client.readProposalReviewStatus(prior)).value.result, result);
      }
      for (const correlationId of ['123e4567-e89b-12d3-a456-426614174000', canonicalId, '0192a870-1234-7abc-8def-123456789abc']) {
        value = {...structuredClone(configured), requestId: correlationId, result: {...terminal, resultId: correlationId}};
        const observed = (await client.readProposalReviewStatus(prior)).value;
        assert.equal(observed.requestId, correlationId);
        assert.equal(observed.result.resultId, correlationId);
      }
      value = {...structuredClone(configured), result: {state: 'pending'}};
      assert.equal((await client.readProposalReviewStatus(prior)).value.requestId, undefined);
      value.result = terminal;
      await assert.rejects(client.readProposalReviewStatus(prior), error => error.kind === 'invalid-request');
      const invalidResults = [
        ...['resultId', 'completedAt', 'availableUntil'].map(field => ({state: 'pending', [field]: terminal[field]})),
        ...['resultId', 'completedAt', 'availableUntil'].map(field => {const result = {...terminal}; delete result[field]; return result;}),
        {...terminal, resultId: 'not-a-uuid'}, {...terminal, resultId: '00000000-0000-0000-0000-000000000000'},
        ...[canonicalId.toUpperCase(), canonicalId.replaceAll('-', '')].map(resultId => ({...terminal, resultId})),
        {...terminal, completedAt: '2026-10-01'}, {...terminal, availableUntil: 'private-canary'},
        {...terminal, availableUntil: terminal.completedAt}, {...terminal, availableUntil: '2026-09-30T00:00:00Z'},
        {...terminal, state: 'expired', availableUntil: undefined}, {...terminal, state: 'unknown'},
      ];
      for (const result of invalidResults) {
        value = {...structuredClone(configured), requestId: id, result};
        const count = requests.length;
        await assert.rejects(client.readProposalReviewStatus(prior), error => error.kind === 'invalid-request' && !error.message.includes('private-canary'));
        assert.equal(requests.length, count + 1);
      }
      for (const invalid of [{...base, result: {state: 'pending'}}, configured]) {
        value = structuredClone(invalid);
        await assert.rejects(client.readProposalReviewStatus(prior), error => error.kind === 'invalid-request');
      }
      value = structuredClone(configured);
      value.context.contract = {id: 'urn:registry:breg:review-context:directory:correct:review', revision: digest, schemaDigest: digest};
      value.context.fields = {private: 'private-canary'};
      assert.deepEqual((await client.readProposalReviewContext(prior)).value.context.fields, value.context.fields);
      value.result = {state: 'pending'};
      await assert.rejects(client.readProposalReviewContext(prior), error => error.kind === 'invalid-request' && !error.message.includes('private-canary'));
    });
    await t.test('non-Rebase transitions and attachment writes preserve the bound Action revision', async () => {
      const successor = `sha256:${'b'.repeat(64)}`;
      value = document(); value.state = 'draft'; delete value.application; delete value.effectDigest;
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
        await assert.rejects(send(), error => error.kind === 'protocol' && error.outcomeUnknown);
        assert.equal(requests.length, count + 1, 'validate the actual received mutation response');
        for (const mutate of [item => {item.revision--;}, item => {item.revision++;},
          item => {item.state = 'submitted';}, item => {item.submissionVersion++;}]) {
          value = structuredClone(current); mutate(value);
          const before = requests.length;
          await assert.rejects(send(), error => error.kind === 'protocol' && error.outcomeUnknown);
          assert.equal(requests.length, before + 1);
        }
      }
      for (const version of [current.submissionVersion, current.submissionVersion + 1]) {
        value = structuredClone(current); value.submissionVersion = version;
        assert.equal(JSON.parse((await client.readProposal(prior)).documentJson).actionRevision, digest);
        value.actionRevision = successor;
        const count = requests.length;
        await assert.rejects(client.readProposal(prior), error => error.kind === 'invalid-request');
        assert.equal(requests.length, count + 1, 'validate the actual received refresh response');
      }
    });
    await t.test('Start receipt failures keep unknown outcome and the original command', async () => {
      const startAction = structuredClone(require('../../registry-breg-client/tests/fixtures/attachments.json').metadata.actions[0]);
      startAction.access.selectedProfile = 'reader'; metadata.actions = [startAction];
      const action = (await client.registryContract('reader')).selectAction('correct', 'reader');
      const draft = document(); draft.state = 'draft'; delete draft.application; delete draft.effectDigest;
      const wrongProfile = structuredClone(draft); wrongProfile.links.self.accessProfile = 'other';
      replyStatus = 201;
      try {
        for (const invalid of [{}, {...draft, actionRevision: `sha256:${'b'.repeat(64)}`}, wrongProfile, {...draft, state: 'submitted', effectDigest: digest}]) {
          value = invalid;
          const count = requests.length;
          await assert.rejects(client.startProposal(action, '{}', 'recover-start'), error => error.kind === 'protocol' && error.outcomeUnknown && error.status === 201);
          assert.equal(requests.length, count + 1, 'malformed Start success is not resent');
          const sent = wireRequests.at(-1);
          value = structuredClone(draft);
          assert.equal(JSON.parse((await client.startProposal(action, '{}', 'recover-start')).documentJson).state, 'draft');
          assert.deepEqual(wireRequests.at(-1), sent);
        }
      } finally { replyStatus = 200; }
    });
    await t.test('Submit validates the exact receipt while replay and saved recovery retain the original request', async () => {
      value = document(); value.state = 'draft'; value.submissionVersion = 1; delete value.application; delete value.effectDigest;
      value.links.submit = {method: 'POST', path: `/v1/proposals/${id}/submit`, accessProfile: 'reader', operation: 'submit', ifMatch: '"submit-condition"'};
      const prior = await client.getProposal(binding, id);
      const initial = structuredClone(value);
      const attempt = client.prepareProposal(prior, 'submit', '{}', 'exact-submit');
      const saved = attempt.toBytes();
      const receipt = {...structuredClone(initial), revision: 9, state: 'submitted', effectDigest: digest};
      for (const invalid of [initial, {...receipt, revision: 8}, {...receipt, revision: 10},
        {...receipt, state: 'draft'}, {...receipt, state: 'applied'}, {...receipt, submissionVersion: 2}]) {
        value = invalid;
        const count = requests.length;
        await assert.rejects(client.executeProposal(attempt), error => error.kind === 'protocol' && error.outcomeUnknown);
        assert.equal(requests.length, count + 1);
      }
      value = receipt;
      assert.equal(JSON.parse((await client.executeProposal(attempt)).documentJson).state, 'submitted');
      const sent = wireRequests.at(-1);
      assert.equal(JSON.parse((await client.executeProposal(attempt)).documentJson).revision, 9);
      assert.deepEqual(wireRequests.at(-1), sent);
      value = {...structuredClone(receipt), revision: 10, state: 'applied',
        application: {...document().application, submissionVersion: 1}};
      value.links.submit.availability = {available: false, observedRevision: 10, reason: 'already-applied', recovery: 'receipt-only'};
      const current = await client.readProposal(prior);
      const before = requests.length;
      const recovered = client.recoverProposal(current, BRegPreparedProposal.fromBytes(saved));
      assert.equal(requests.length, before, 'recovery performs no exchange');
      assert.deepEqual(recovered.toBytes(), saved);
      value = receipt;
      assert.equal(JSON.parse((await client.executeProposal(recovered)).documentJson).revision, 9);
      assert.deepEqual(wireRequests.at(-1), sent);
    });
    await t.test('held Proposal reads refuse backward workflow revisions and permit equal or later observations', async () => {
      value = document();
      const held = await client.getProposal(binding, id);
      value.revision = 7;
      const count = requests.length;
      await assert.rejects(client.readProposal(held), error => error.kind === 'invalid-request');
      assert.equal(requests.length, count + 1);
      for (const revision of [8, 9]) {
        value.revision = revision;
        assert.equal(JSON.parse((await client.readProposal(held)).documentJson).revision, revision);
      }
    });
    await t.test('explicit Rebase and exact recovery admit only the next successor Draft', async () => {
      for (const [state, before, after] of [['draft', 1, 1], ['submitted', 2, 3]]) {
        value = document(); value.state = state; value.submissionVersion = before; delete value.application;
        if (state === 'draft') delete value.effectDigest;
        value.links.rebase = {method: 'POST', path: `/v1/proposals/${id}/rebase`, accessProfile: 'reader', operation: 'rebase', ifMatch: '"rebase-condition"',
          availability: {available: true, observedRevision: 8}};
        const prior = await client.getProposal(binding, id);
        const attempt = client.prepareProposal(prior, 'rebase', '{"input":{}}', `rebase-${state}`);
        const saved = attempt.toBytes();
        value.state = 'draft'; value.submissionVersion = after; value.revision = 9; delete value.effectDigest;
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
      value = document(); value.state = 'draft'; delete value.application; delete value.effectDigest;
      value.attachments = {support: {id: 'support', required: false, maximumBytes: 4, contentTypes: ['text/plain'], classification: 'restricted',
        value: {submissionVersion: 2, uploadedAt: '2026-10-15T00:00:00.000000Z', sha256: createHash('sha256').update(downloadBytes).digest('hex'), contentType: 'application/pdf', byteSize: downloadBytes.length, verificationStatus: 'notRequired'},
        links: {download: {method: 'GET', path: `/v1/proposals/${id}/attachments/support?submissionVersion=2`, accessProfile: 'reader', operation: 'download'},
          upload: {method: 'PATCH', path: `/v1/proposals/${id}/attachments/support`, accessProfile: 'reader', operation: 'upload', ifMatch: '"attachment-condition"'}}}};
      const disclosed = structuredClone(value);
      for (const uploadedAt of [undefined, 'private-canary', '2026-10-15']) {
        value = structuredClone(disclosed); value.attachments.support.value.uploadedAt = uploadedAt;
        await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request' && !error.message.includes('private-canary'));
      }
      value = disclosed;
      const retained = await client.getProposal(binding, id);
      assert.deepEqual((await client.downloadProposalAttachment(retained, 'support')).body, downloadBytes);
      const count = requests.length;
      await assert.rejects(client.uploadProposalAttachment(retained, 'support', 'application/pdf', Buffer.from('%PDF'), 'wrong-media'), error => error.kind === 'invalid-request');
      await assert.rejects(client.uploadProposalAttachment(retained, 'support', 'text/plain', Buffer.from('12345'), 'too-large'), error => error.kind === 'invalid-request');
      assert.equal(requests.length, count, 'new uploads keep current policy before I/O');
      value.revision++;
      Object.assign(value.attachments.support.value, {sha256: createHash('sha256').update('ok').digest('hex'), contentType: 'text/plain', byteSize: 2});
      await client.uploadProposalAttachment(retained, 'support', 'text/plain', Buffer.from('ok'), 'allowed-upload');
      downloadBytes = Buffer.concat([downloadBytes, Buffer.from('x')]);
      await assert.rejects(client.downloadProposalAttachment(retained, 'support'), error => error.kind === 'transport' && error.transportKind === 'response-too-large');
    });
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('Proposal turn, decision and the submission read decode exactly', async () => {
  const proposal = {...document(), state: 'rejected', turn: 'nobody', createdAt: '2026-10-01T09:00:00.123456Z',
    decision: {status: 'rejected', decidedAt: '2026-10-01T10:00:00.000000Z', publicReason: 'Public reason'},
    applicationStatus: {state: 'rejected', mode: 'manual'}};
  delete proposal.application;
  const submission = {id, actionId: 'correct', submissionVersion: 2, current: true, effectDigest: digest,
    review: {state: 'rejected', resultId: targetId, completedAt: '2026-10-01T10:00:00.000000Z', availableUntil: '2026-10-02T10:00:00.000000Z'},
    application: {state: 'rejected', mode: 'manual'}, decision: proposal.decision};
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    const headers = {'content-type': 'application/json', 'cache-control': 'no-store', vary: 'authorization, accept',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'};
    if (request.url.startsWith(`/v1/proposals/${id}/submissions/1?`)) {
      response.writeHead(410, {...headers, 'content-type': 'application/problem+json'});
      response.end(JSON.stringify({type: 'https://id.registrystack.org/problems/registry-breg/proposal/submission_expired',
        title: 'Gone', status: 410, code: 'proposal.submission_expired', traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        detail: 'The review result and application receipt of the submission are no longer retained.'}));
      return;
    }
    const metadata = {id: 'registry', version: '1', revision: digest, metadataVersion: '2', recordTypes: [], operations: [],
      proposals: {method: 'GET', path: '/v1/proposals', accessProfiles: [], actions: [],
        get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['reader']}}};
    response.writeHead(200, headers);
    response.end(JSON.stringify(request.url.startsWith('/v1/registry') ? metadata
      : request.url.includes('/submissions/') ? submission : proposal));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}`});
    const binding = (await client.registryContract('reader')).selectProposalGet('reader');
    const current = await client.getProposal(binding, id);
    const observed = JSON.parse(current.documentJson);
    assert.equal(observed.state, 'rejected');
    assert.equal(observed.turn, 'nobody');
    assert.equal(observed.createdAt, '2026-10-01T09:00:00.123456Z');
    assert.deepEqual(observed.decision, proposal.decision);
    const read = await client.readProposalSubmission(current, 2);
    assert.deepEqual(read.value, submission);
    assert.ok(requests.at(-1).startsWith(`/v1/proposals/${id}/submissions/2?accessProfile=reader`));
    await assert.rejects(client.readProposalSubmission(current, 1),
      error => error.kind === 'problem' && error.code === 'proposal.submission_expired');
    await assert.rejects(client.readProposalSubmission(current, 0), error => error.kind === 'invalid-request');
    proposal.decision = {...proposal.decision, publicReason: 'x'.repeat(2001)};
    await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
    proposal.decision = {status: 'rejected', decidedAt: '2026-10-01T10:00:00.000000Z'};
    proposal.turn = 'someone';
    await assert.rejects(client.getProposal(binding, id), error => error.kind === 'invalid-request');
  } finally {
    server.close();
  }
});
