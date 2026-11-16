'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { setTimeout: delay } = require('node:timers/promises');
const { getEventListeners } = require('node:events');
const { test } = require('node:test');
const { BaseRegistryClient, BaseRegistryClientError } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const id = '00000000-0000-4000-8000-000000000001';
const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const meta = { registryIdentifier: 'registry', datasetIdentifier: 'dataset', recordTypeIdentifier: 'company' };
const record = { recordIdentifier: id, revisionIdentifier: '1', domainData: { label: 'synthetic' } };
const link = '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/company>; rel="describedby"';
async function until(check, message) {
  for (let i = 0; i < 100; i++) { if (check()) return; await delay(10); }
  assert.fail(message);
}
const observe = promise => promise.then(value => ({ value }), error => ({ error }));
function cancelled(result) {
  assert(result.error instanceof BaseRegistryClientError);
  assert.equal(result.error.kind, 'cancelled');
  assert.equal(result.error.outcomeUnknown, false);
  assert(!JSON.stringify(result.error).includes('abort-reason-canary'));
  assert(!result.error.message.includes('abort-reason-canary'));
}
async function serve(t) {
  const requests = [];
  let mode = 'finish';
  const server = http.createServer((request, response) => {
    const collection = !request.url.split('?')[0].endsWith(id);
    const body = JSON.stringify(collection
      ? { items: [record], pageInfo: { nextCursor: request.url.includes('$skiptoken=') ? null : 'next' }, meta }
      : { data: record, meta });
    const entry = { url: request.url, headers: request.headers, closed: false, finish: () => response.end(body) };
    requests.push(entry);
    response.on('close', () => { entry.closed = true; });
    response.setHeader('content-type', 'application/json');
    response.setHeader('traceparent', traceparent);
    response.setHeader('link', link);
    if (!collection) response.setHeader('etag', '"breg-record-000000000001"');
    if (mode === 'finish') entry.finish();
    if (mode === 'body') { response.flushHeaders(); response.write(' '); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  return { requests, mode: value => { mode = value; }, client: new BaseRegistryClient({
    baseUrl: `http://127.0.0.1:${server.address().port}`, authorization: { static: 'synthetic-token' },
    attemptTimeoutMilliseconds: 3_000,
  }) };
}

for (const method of ['getRecord', 'getRecordJson', 'listRecords', 'listRecordsJson']) {
  test(`${method}: already-aborted sends nothing; omitted signal keeps existing behavior`, async t => {
    const fixture = await serve(t);
    const args = method.startsWith('get') ? ['companies', id, { accessProfile: 'reader' }] : ['companies', { accessProfile: 'reader' }];
    const controller = new AbortController(); controller.abort('abort-reason-canary');
    cancelled(await observe(fixture.client[method](...args, { signal: controller.signal })));
    assert.equal(fixture.requests.length, 0);
    await fixture.client[method](...args);
    assert.equal(fixture.requests.length, 1);
    assert.equal(fixture.requests[0].headers.authorization, 'Bearer synthetic-token');
    assert(fixture.requests[0].url.includes('accessProfile=reader'));
  });
}

for (const mode of ['headers', 'body']) {
  test(`abort during ${mode} drops underlying HTTP without cancelling a concurrent same-client read`, async t => {
    const fixture = await serve(t); fixture.mode(mode);
    const controller = new AbortController();
    // Even another listener stopping ordinary event propagation cannot suppress cancellation.
    controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
    const count = getEventListeners(controller.signal, 'abort').length;
    const first = observe(fixture.client.getRecordJson('companies', id, { accessProfile: 'first' }, { signal: controller.signal }));
    const second = observe(fixture.client.getRecordJson('companies', id, { accessProfile: 'second' }));
    await until(() => fixture.requests.length === 2, 'two native HTTP reads started');
    const firstRequest = fixture.requests.find(x => x.url.includes('accessProfile=first'));
    const secondRequest = fixture.requests.find(x => x.url.includes('accessProfile=second'));
    controller.abort('abort-reason-canary');
    cancelled(await first);
    await until(() => firstRequest.closed, 'cancelled HTTP request closed upstream');
    assert.equal(secondRequest.closed, false);
    secondRequest.finish(); assert((await second).value);
    assert.equal(getEventListeners(controller.signal, 'abort').length, count);
    fixture.mode('finish'); await fixture.client.listRecordsJson('companies');
    await delay(30); assert.equal(fixture.requests.length, 3, 'no read retry');
  });
}

for (const suffix of ['', 'Json']) {
  test(`explicit continuation${suffix} aborts its HTTP read and cannot start again after abort`, async t => {
    const fixture = await serve(t);
    const first = await fixture.client[`listRecords${suffix}`]('companies', { accessProfile: 'reader' });
    fixture.mode('body');
    const controller = new AbortController();
    const pending = observe(fixture.client[`continueList${suffix}`](first.continuation, { signal: controller.signal }));
    await until(() => fixture.requests.length === 2, 'continuation reached upstream');
    controller.abort(); cancelled(await pending);
    await until(() => fixture.requests[1].closed, 'continuation request closed');
    cancelled(await observe(fixture.client[`continueList${suffix}`](first.continuation, { signal: controller.signal })));
    await delay(30); assert.equal(fixture.requests.length, 2);
    assert(fixture.requests[1].url.includes('$skiptoken=next'));
    assert(fixture.requests[1].url.includes('accessProfile=reader'));
    fixture.mode('finish'); await fixture.client[`continueList${suffix}`](first.continuation);
    assert.equal(fixture.requests.length, 3);
  });
}

test('signal listener is removed on success and malformed request options execute no getters or HTTP', async t => {
  const fixture = await serve(t); const controller = new AbortController();
  await fixture.client.getRecord('companies', id, undefined, { signal: controller.signal });
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  let touched = false;
  for (const request of [{ signal: {} }, { get signal() { touched = true; throw new Error('abort-reason-canary'); } }, { signal: controller.signal, extra: true }]) {
    assert.throws(() => fixture.client.getRecord('companies', id, undefined, request), error => error.kind === 'invalid-request');
  }
  assert.equal(touched, false); assert.equal(fixture.requests.length, 1);
});

for (const cancelLeader of [false, true]) {
  test(`cancellation ${cancelLeader ? 'during token HTTP' : 'while queued for token'} preserves another invocation and sends no cancelled resource read`, async t => {
    // Ephemeral synthetic OAuth fixture, never an operator credential.
    const { generateKeyPairSync } = require('node:crypto');
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' });
    Object.assign(key, { alg: 'ES256', kid: 'synthetic-cancellation-test' });
    const tokens = []; const resources = [];
    const server = http.createServer((request, response) => {
      if (request.url === '/token') {
        const token = { closed: false, finish() {
          response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store', pragma: 'no-cache' });
          response.end(JSON.stringify({ access_token: 'synthetic-acquired', token_type: 'Bearer', expires_in: 300, scope: 'records:get' }));
        } };
        response.on('close', () => { token.closed = true; }); tokens.push(token);
      } else {
        resources.push(request.headers.authorization);
        response.writeHead(200, { 'content-type': 'application/json', traceparent, link, etag: '"breg-record-000000000001"' });
        response.end(JSON.stringify({ data: record, meta }));
      }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const client = new BaseRegistryClient({ baseUrl, authorization: { privateKeyJwt: {
      tokenEndpoint: `${baseUrl}/token`, clientId: 'synthetic-client', clientKey: key,
      resource: 'urn:test:resource', scopes: ['records:get'], attemptTimeoutMilliseconds: 3_000,
    } } });
    const controller = new AbortController();
    const first = observe(client.getRecordJson('companies', id, undefined, cancelLeader ? { signal: controller.signal } : undefined));
    await until(() => tokens.length === 1, 'first token acquisition');
    const second = observe(client.getRecordJson('companies', id, undefined, cancelLeader ? undefined : { signal: controller.signal }));
    // Give the second native invocation time to wait behind the held acquisition.
    await delay(30);
    assert.equal(tokens.length, 1); assert.equal(resources.length, 0);
    controller.abort();
    cancelled(await (cancelLeader ? first : second));
    assert.equal(resources.length, 0);
    if (cancelLeader) {
      await until(() => tokens[0].closed && tokens.length === 2, 'cancelled acquisition closes and survivor acquires');
      tokens[1].finish();
    } else {
      assert.equal(tokens[0].closed, false, 'queued cancellation must not abort another acquisition');
      tokens[0].finish();
    }
    assert((await (cancelLeader ? second : first)).value);
    await delay(30);
    assert.deepEqual(resources, ['Bearer synthetic-acquired']);
    assert.equal(tokens.length, cancelLeader ? 2 : 1);
    // Token cache and the non-cancelled client remain usable; no extra acquisition.
    await client.getRecordJson('companies', id);
    assert.equal(resources.length, 2); assert.equal(tokens.length, cancelLeader ? 2 : 1);
  });
}

for (const [method, args] of [
  ['registryMetadata', ['reader']], ['registryContract', ['reader']], ['recordSchema', ['company', 'reader']],
  ['recordRevisions', ['companies', id, 'reader']], ['getRecordRevision', ['companies', id, 1, { accessProfile: 'reader' }]],
  ['eventRecordCreationRevision', ['companies', id, 'reader']],
]) {
  test(`${method}: a secondary read observes the same invocation signal`, async t => {
    const fixture = await serve(t); fixture.mode('headers');
    const controller = new AbortController();
    const pending = observe(fixture.client[method](...args, { signal: controller.signal }));
    await until(() => fixture.requests.length === 1, 'secondary HTTP read started');
    controller.abort(); cancelled(await pending);
    await until(() => fixture.requests[0].closed, 'secondary HTTP read closed');
    cancelled(await observe(fixture.client[method](...args, { signal: controller.signal })));
    assert.equal(fixture.requests.length, 1, 'no later read after abort');
  });
}

test('metadata-bound proposal get/list cancellation preserves opaque bindings and caller profile', async t => {
  const revision = `sha256:${'a'.repeat(64)}`;
  const metadata = { id: 'synthetic', version: '1', revision, metadataVersion: '2', recordTypes: [], operations: [],
    proposals: { method: 'GET', path: '/v1/proposals', accessProfiles: ['reader'], actions: [],
      get: { method: 'GET', path: '/v1/proposals/{proposal_id}', accessProfiles: ['reader'] } } };
  const reads = [];
  let hold = true, observed = '\"breg-cancel-compatible-response\"';
  const proposal = { id, actionId: 'correct', actionRevision: revision, submissionVersion: 1, revision: 1, state: 'draft',
    links: { self: { method: 'GET', path: `/v1/proposals/${id}`, accessProfile: 'reader', operation: 'get' } } };
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'application/json'); response.setHeader('traceparent', traceparent);
    response.setHeader('cache-control', 'no-store'); response.setHeader('vary', 'authorization, accept');
    if (request.url.startsWith('/v1/registry')) return response.end(JSON.stringify(metadata));
    const entry = { closed: false, url: request.url }; reads.push(entry);
    response.on('close', () => { entry.closed = true; });
    if (!hold) {
      if (observed !== null) response.setHeader('etag', observed);
      response.end(JSON.stringify(request.url.split('?')[0] === '/v1/proposals' ? { items: [proposal], nextCursor: null } : proposal));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}`, attemptTimeoutMilliseconds: 3_000 });
  const contract = await client.registryContract('reader');
  const get = contract.selectProposalGet('reader'); const list = contract.selectProposals('reader');
  for (const [method, args] of [['getProposal', [get, id]], ['listProposals', [list, {}]], ['listProposalsJson', [list, '{}']]]) {
    const controller = new AbortController(); const before = reads.length;
    const pending = observe(client[method](...args, { signal: controller.signal }));
    await until(() => reads.length === before + 1, 'proposal read started');
    controller.abort(); cancelled(await pending);
    await until(() => reads[before].closed, 'proposal read closed');
    assert(reads[before].url.includes('accessProfile=reader'));
    cancelled(await observe(client[method](...args, { signal: controller.signal })));
    assert.equal(reads.length, before + 1);
  }
  // Integration with the separately retained18bd contract: adding a read
  // signal preserves actual individual response metadata, never page headers.
  hold = false;
  const active = new AbortController();
  const complete = await client.getProposal(get, id, { signal: active.signal });
  assert.equal(complete.responseEtag, observed);
  assert.equal((await client.readProposal(complete, { signal: active.signal })).responseEtag, observed);
  const page = await client.listProposals(list, {}, { signal: active.signal });
  assert.equal(page.items[0].responseEtag, null);
  active.abort('abort-reason-canary');
  assert.equal(complete.responseEtag, '\"breg-cancel-compatible-response\"');
  observed = null;
  assert.equal((await client.getProposal(get, id, { signal: new AbortController().signal })).responseEtag, null);
  assert.equal(complete.responseEtag, '\"breg-cancel-compatible-response\"');
});
