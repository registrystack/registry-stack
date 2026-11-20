'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient, BRegPreparedProposal } = require('..');

const revision = `sha256:${'a'.repeat(64)}`;
const id = '00000000-0000-4000-8000-000000000001';
const metadata = {
  id: 'proposal-client', version: '1', revision, metadataVersion: '2', recordTypes: [], operations: [],
  proposals: {method: 'GET', path: '/v1/proposals', accessProfiles: ['author'],
    actions: [{actionId: 'correct', accessProfile: 'author', operations: ['get', 'list', 'submit'], readableInputs: [], readableContextFields: []}],
    get: {method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['author']}},
  actions: [{id: 'correct', apiName: 'correct', revision, display: {}, execution: {mode: 'proposal'},
    attachments: [{id: 'supporting-file', required: true, contentTypes: ['application/pdf'], maximumBytes: 1024}],
    route: '/v1/actions/correct/proposals', inputMode: 'fixed', inputs: [
      {id: 'address', apiName: 'address', required: true, nullable: false, classification: 'internal',
        schema: {type: 'string', minLength: 1, maxLength: 100},
        fieldType: {type: 'string', minimumLength: 1, maximumLength: 100}},
    ], referenceInputs: [], requiredConditionKeys: [], resultEffects: [],
    access: {selectedProfile: 'author'}, routes: {start: {method: 'POST', path: '/v1/actions/correct/proposals', operationId: 'actions.correct.start',
      requiresIdempotencyKey: true, inputSchema: 'action-correct-invoke-input', responseSchema: 'action-correct-invoke-response'}},
    bounds: {maximumTargets: 16, maximumFieldMutations: 128, maximumSnapshotBytes: 2097152}}],
};
const proposal = {id, actionId: 'correct', actionRevision: revision, submissionVersion: 1, revision: 1, state: 'draft', links: {
  self: {method: 'GET', path: `/v1/proposals/${id}`, accessProfile: 'author', operation: 'get'},
  edit: {method: 'POST', path: `/v1/proposals/${id}/edit`, accessProfile: 'author', operation: 'edit', ifMatch: '"draft-condition"'},
  submit: {method: 'POST', path: `/v1/proposals/${id}/submit`, accessProfile: 'author', operation: 'submit', ifMatch: '"draft-condition"'},
}};

test('proposal object methods preserve exact bodies and refuse JSON strings before I/O', async () => {
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
    if (request.url.includes('/submit?')) return response.end(JSON.stringify({...proposal, revision: 2, state: 'submitted', effectDigest: revision}));
    response.end(JSON.stringify(proposal));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    const contract = await client.registryContract('author');
    assert.deepEqual(contract.proposalActions, metadata.proposals.actions);
    assert.deepEqual(contract.actions[0].attachments, metadata.actions[0].attachments);
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
    const draft = await client.startProposal(binding, {}, 'start-once');
    assert.equal(draft.identifier, id);
    assert.equal(JSON.parse(draft.documentJson).submissionVersion, 1);
    assert.equal(requests.at(-1).body, '{"input":{}}');
    assert.ok(client.prepareProposal(draft, 'edit', {input: {}}, 'edit-empty'));
    await client.startProposal(binding, {}, 'k'.repeat(256));
    assert.equal(requests.at(-1).headers['idempotency-key'], 'k'.repeat(256));
    const startCount = requests.length;
    for (const invalid of [{address: null}, {address: 42}, {address: ''}]) {
      await assert.rejects(client.startProposal(binding, invalid, 'invalid-start'), error => error.kind === 'invalid-request');
    }
    await assert.rejects(client.startProposal(binding, {}, 'k'.repeat(257)), error => error.kind === 'invalid-request');
    assert.equal(requests.length, startCount, 'invalid supplied Proposal inputs fail before credential acquisition or I/O');
    const attempt = client.prepareProposal(draft, 'submit', {}, 'submit-once');
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
    const page = await client.listProposals(contract.selectProposals('author'), {action: 'correct', limit: 1});
    assert.equal(page.items[0].identifier, id);
    assert.equal(page.nextCursor, undefined);
    assert.throws(() => client.prepareProposal(draft, 'submit', {input: {}}, 'invalid-body'), error => error.kind === 'invalid-request');
    const oldShapeCount = requests.length;
    await assert.rejects(client.startProposal(binding, '{}', 'old-start'), error => error.kind === 'invalid-request');
    await assert.rejects(client.listProposals(contract.selectProposals('author'), '{}'), error => error.kind === 'invalid-request');
    assert.throws(() => client.prepareProposal(draft, 'submit', '{}', 'old-submit'), error => error.kind === 'invalid-request');
    assert.equal(requests.length, oldShapeCount, 'retired JSON-string forms fail before I/O');
    const foreign = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/other/`});
    await assert.rejects(foreign.getProposal(getBinding, id), error => error.kind === 'invalid-request');
    await assert.rejects(foreign.readProposal(draft), error => error.kind === 'invalid-request');
  } finally { await new Promise(resolve => server.close(resolve)); }
});


test('metadata inventory preserves profile boundaries and refuses old or malformed contracts', async () => {
  let document = structuredClone(metadata);
  document.proposals.actions = [
    {actionId: 'correct', accessProfile: 'author', operations: ['get'], readableInputs: ['address'], readableContextFields: []},
    {actionId: 'correct', accessProfile: 'queue', operations: ['list'], readableInputs: [], readableContextFields: []},
    {actionId: 'correct', accessProfile: 'executor', operations: ['apply'], readableInputs: [], readableContextFields: []},
  ];
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.end(JSON.stringify(document));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/`});
    const contract = await client.registryContract('author');
    assert.deepEqual(contract.proposalActions, document.proposals.actions);
    assert.deepEqual(contract.actions[0].attachments, document.actions[0].attachments);
    assert.throws(() => contract.selectAction('correct', 'queue'));
    document = {metadataVersion: '1'};
    await assert.rejects(client.registryContract('author'), error => error.kind === 'protocol');
    document = {...metadata, recordTypes: undefined, entities: []};
    await assert.rejects(client.registryContract('author'), error => error.kind === 'protocol');
    document = structuredClone(metadata);
    delete document.proposals.actions[0].readableInputs;
    await assert.rejects(client.registryContract('author'), error => error.kind === 'protocol');
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('proposal actions expose served review and application values and null from older servers', async () => {
  let document = metadata;
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.end(JSON.stringify(document));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/`});
    const older = (await client.registryContract('author')).actions[0];
    assert.equal(older.review, null);
    assert.equal(older.application, null);
    for (const [review, application] of [['required', 'automatic'], ['none', 'manual'], ['future-review', 'future-application']]) {
      document = structuredClone(metadata);
      document.actions[0].execution = {mode: 'proposal', review, application};
      const action = (await client.registryContract('author')).actions[0];
      assert.equal(action.review, review);
      assert.equal(action.application, application);
    }
    for (const execution of [{mode: 'proposal', review: true}, {mode: 'proposal', application: 'Manual'}]) {
      document = structuredClone(metadata);
      document.actions[0].execution = execution;
      await assert.rejects(client.registryContract('author'), error => error.kind === 'protocol');
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('returned Proposal cursors are usable for explicit bounded continuation', async () => {
  let value = {items: []};
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store',
      vary: 'authorization, accept', traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
    response.end(JSON.stringify(request.url.startsWith('/tenant/v1/registry') ? metadata : value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    const collection = (await client.registryContract('author')).selectProposals('author');
    const pendingManual = {...proposal, state: 'submitted', effectDigest: revision,
      applicationStatus: {state: 'pending', mode: 'manual'}};
    value = {items: [pendingManual]};
    const selected = await client.listProposals(collection, {pendingManualApplication: true});
    assert.equal(selected.items[0].identifier, id);
    assert.equal(new URL(requests.at(-1), 'http://fixture.invalid').searchParams.get('pendingManualApplication'), 'true');
    value = {items: [pendingManual]};
    await client.listProposals(collection, {pendingManualApplication: false});
    assert.equal(new URL(requests.at(-1), 'http://fixture.invalid').searchParams.has('pendingManualApplication'), false);
    for (const applicationStatus of [
      undefined,
      {state: 'pending', mode: 'automatic', automaticRetry: {scheduled: true, attempts: 0, maximumAttempts: 3}},
      {state: 'blocked', mode: 'manual', reason: 'dependency-outage', recovery: 'retry'},
    ]) {
      value = {items: [{...pendingManual, applicationStatus}]};
      await assert.rejects(
        client.listProposals(collection, {pendingManualApplication: true}),
        error => error.kind === 'invalid-request',
      );
    }
    for (const cursor of ['', ' ', 'cursor\nvalue', 'cursor\tvalue', 'é', 'x'.repeat(513)]) {
      value = {items: [proposal], nextCursor: cursor};
      const count = requests.length;
      await assert.rejects(client.listProposals(collection, {}), error => error.kind === 'invalid-request');
      assert.equal(requests.length, count + 1, 'refuse the received page without automatically following it');
    }
    for (const cursor of [id, 'x'.repeat(512)]) {
      value = {items: [], nextCursor: cursor};
      const emptyPage = await client.listProposals(collection, {});
      assert.equal(emptyPage.nextCursor, cursor);
      value = {items: [proposal], nextCursor: cursor};
      await assert.rejects(client.listProposals(collection, {cursor}), error => error.kind === 'invalid-request');
      const page = await client.listProposals(collection, {});
      assert.equal(page.nextCursor, cursor);
      value = {items: []};
      const finalPage = await client.listProposals(collection, {cursor: page.nextCursor});
      assert.equal(new URL(requests.at(-1), 'http://fixture.invalid').searchParams.get('cursor'), cursor);
      assert.equal(finalPage.nextCursor, undefined);
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});


test('Proposal Start accepts exact Draft replay and refuses otherwise valid terminal or Submitted responses', async () => {
  let value = structuredClone(proposal);
  const requests = [];
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    requests.push({url: request.url, body, key: request.headers['idempotency-key']});
    response.writeHead(request.method === 'POST' ? 201 : 200, {'content-type': 'application/json', 'cache-control': 'no-store',
      vary: 'authorization, accept', traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
    response.end(JSON.stringify(request.url.startsWith('/tenant/v1/registry') ? metadata : value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    const contract = await client.registryContract('author');
    const start = contract.selectAction('correct', 'author');
    const get = contract.selectProposalGet('author');
    const first = await client.startProposal(start, {}, 'exact-draft-start');
    const repeated = await client.startProposal(start, {}, 'exact-draft-start');
    assert.equal(first.documentJson, repeated.documentJson);
    assert.deepEqual(requests.at(-1), requests.at(-2));
    for (const state of ['submitted', 'applied', 'cancelled']) {
      value = structuredClone(proposal); value.state = state; value.submissionVersion = 1; value.links = {self: value.links.self};
      if (state === 'submitted') value.effectDigest = revision;
      assert.equal(JSON.parse((await client.getProposal(get, id)).documentJson).state, state, 'ordinary reads permit this representation');
      const count = requests.length;
      await assert.rejects(client.startProposal(start, {}, `wrong-start-${state}`), error => error.kind === 'protocol' && error.outcomeUnknown);
      assert.equal(requests.length, count + 1, 'validate one actual Start response');
      assert.equal(requests.at(-1).url, '/tenant/v1/actions/correct/proposals?accessProfile=author');
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});


test('review status preserves accepted request correlation without widening context reads', async () => {
  const requestId = '00000000-0000-4000-8000-000000000002';
  const readable = {...proposal, links: {...proposal.links,
    reviewStatus: {method: 'GET', path: `/v1/proposals/${id}/review-status`, accessProfile: 'author', operation: 'get-review-status'},
    reviewContext: {method: 'GET', path: `/v1/proposals/${id}/review-context`, accessProfile: 'author', operation: 'get-review-context'}}};
  const base = {id, actionId: 'correct', actionRevision: revision, submissionVersion: 1, revision: 2,
    effectDigest: revision, subject: {source: 'proposal-client', subjectType: 'proposal', id, version: '1', digest: revision},
    context: {reference: 'opaque-review-context'}, reviewable: true};
  const status = {...base, authority: 'review', policy: {id: 'correction'}, result: {state: 'pending'}};
  const context = {...base, context: {...base.context,
    contract: {id: 'urn:registry:breg:review-context:proposal-client:correct:display', revision, schemaDigest: revision}, fields: {}}};
  let responseValue = status;
  const server = http.createServer((request, response) => {
    response.writeHead(200, {'content-type': 'application/json', 'cache-control': 'no-store',
      vary: 'authorization, accept', traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'});
    response.end(JSON.stringify(request.url.startsWith('/tenant/v1/registry') ? metadata
      : request.url.includes('/review-') ? responseValue : readable));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/tenant/`});
    const binding = (await client.registryContract('author')).selectProposalGet('author');
    const current = await client.getProposal(binding, id);
    assert.equal((await client.readProposalReviewStatus(current)).value.requestId, undefined);
    responseValue = {...status, requestId};
    assert.equal((await client.readProposalReviewStatus(current)).value.requestId, requestId);
    responseValue = {...status, requestId: '00000000-0000-0000-0000-000000000000'};
    await assert.rejects(client.readProposalReviewStatus(current), error => error.kind === 'invalid-request');
    responseValue = context;
    assert.equal((await client.readProposalReviewContext(current)).value.requestId, undefined);
    responseValue = {...context, requestId};
    await assert.rejects(client.readProposalReviewContext(current), error => error.kind === 'invalid-request');
  } finally { await new Promise(resolve => server.close(resolve)); }
});


test('Proposal responseEtag observes only its individual HTTP response and never replaces opaque conditions', async () => {
  let observed = '"breg-observed-one"';
  const requests = [];
  const server = http.createServer(async (request, response) => {
    for await (const _ of request) { /* consume the exact normal client body */ }
    requests.push({url: request.url, headers: request.headers});
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    if (request.url.startsWith('/v1/registry')) return response.end(JSON.stringify(metadata));
    if (observed !== null) response.setHeader('etag', observed);
    response.end(JSON.stringify(request.url.startsWith('/v1/proposals?') ? {items: [proposal]} :
      request.url.includes('/submit?') ? {...proposal, revision: 2, state: 'submitted', effectDigest: revision} : proposal));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({baseUrl: `http://127.0.0.1:${server.address().port}/`});
    const contract = await client.registryContract('author');
    const started = await client.startProposal(contract.selectAction('correct', 'author'), {}, 'observed-start');
    assert.equal(started.responseEtag, observed);
    assert.notEqual(started.responseEtag, JSON.parse(started.documentJson).links.submit.ifMatch);
    assert.throws(() => { started.responseEtag = '"breg-forged"'; }, TypeError);
    observed = '"breg-observed-two"';
    const read = await client.readProposal(started);
    assert.equal(read.responseEtag, observed);
    assert.equal(started.responseEtag, '"breg-observed-one"', 'later responses do not mutate retained observation');
    observed = '"breg-observed-three"';
    const located = await client.getProposal(contract.selectProposalGet('author'), id);
    assert.equal(located.responseEtag, observed);
    observed = '"breg-observed-four"';
    const executed = await client.executeProposal(client.prepareProposal(located, 'submit', {}, 'observed-execute'));
    assert.equal(executed.responseEtag, observed);
    assert.equal(requests.at(-1).headers['if-match'], '"draft-condition"', 'actual observation never overrides promoted opaque authority');
    const page = await client.listProposals(contract.selectProposals('author'), {});
    assert.equal(page.items[0].responseEtag, null, 'a page response header is not an item observation');
    observed = null;
    assert.equal((await client.readProposal(started)).responseEtag, null, 'missing response header never falls back to retained/link/document data');
    for (const invalid of ['W/"breg-weak"', '"foreign-tag"', 'unquoted']) {
      observed = invalid;
      await assert.rejects(client.getProposal(contract.selectProposalGet('author'), id), error => error.kind === 'protocol');
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});

for (const operation of ['recovered-start', 'upload', 'delete']) {
  test(`Complete-backed Proposal ${operation} preserves its own response ETag without changing authority`, async () => {
    const fixture = require('../../registry-breg-client/tests/fixtures/attachments.json');
    const { createHash } = require('node:crypto');
    const bytes = Buffer.from(fixture.content), slot = 'supporting-file';
    let observed = `"breg-${operation}-actual"`;
    const requests = [];
    const server = http.createServer(async (request, response) => {
      const chunks = []; for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      requests.push({ method: request.method, headers: request.headers, body });
      const value = structuredClone(request.url.startsWith('/v1/registry') ? fixture.metadata : fixture.proposal);
      if (request.method === 'PATCH') {
        value.revision++;
        Object.assign(value.attachments[slot].value, { sha256: createHash('sha256').update(body).digest('hex'), contentType: request.headers['content-type'], byteSize: body.length });
      } else if (request.method === 'DELETE') { value.revision++; delete value.attachments[slot].value; }
      response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store', vary: 'authorization, accept',
        traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
        ...(!request.url.startsWith('/v1/registry') && observed !== null ? { etag: observed } : {}) });
      response.end(JSON.stringify(value));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}/`, maximumMutationRetries: 0 });
      const binding = (await client.registryContract('writer')).selectAction('correct', 'writer');
      const initial = await client.startProposal(binding, {}, 'initial');
      const send = async key => {
        if (operation === 'recovered-start') {
          const prepared = client.prepareActionJson(binding, '{}', key);
          const count = requests.length;
          assert.throws(() => client.recoverActionJson(binding, prepared, '{}', key + '-different'), error => error.kind === 'invalid-request');
          assert.equal(requests.length, count);
          return client.executeRecoveredProposalStart(binding, client.recoverActionJson(binding, prepared, '{}', key));
        }
        return operation === 'upload'
          ? client.uploadProposalAttachment(initial, slot, 'application/pdf', bytes, key)
          : client.deleteProposalAttachment(initial, slot, key);
      };
      const result = await send('observed');
      assert.equal(result.responseEtag, observed);
      assert.throws(() => { result.responseEtag = '"breg-forged"'; }, TypeError);
      if (operation !== 'recovered-start') assert.equal(requests.at(-1).headers['if-match'], '"condition"');
      assert.equal(requests.at(-1).headers['idempotency-key'], 'observed');
      if (operation === 'upload') assert.deepEqual(requests.at(-1).body, bytes);
      observed = null;
      assert.equal((await send('missing')).responseEtag, null);
      assert.equal(result.responseEtag, `"breg-${operation}-actual"`, 'a later exchange cannot replace the retained observation');
      for (const invalid of ['W/"breg-weak"', '"foreign-tag"', 'unquoted']) {
        observed = invalid;
        const before = requests.length;
        await assert.rejects(send('invalid-' + before), error => error.kind === 'protocol');
        assert.equal(requests.length, before + 1, 'invalid response metadata never triggers a new send');
      }
    } finally { await new Promise(resolve => server.close(resolve)); }
  });
}
