'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { after, before, test } = require('node:test');

const {
  BaseRegistryClient,
  BaseRegistryClientError,
  BRegIngestionChunk,
  BRegIngestionPrefixDigest,
  encodeIngestionChunk,
} = require('..');

const TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';
const TRACEPARENT = `00-${TRACE_ID}-00f067aa0ba902b7-01`;
const RUN_ID = '00000000-0000-4000-8000-000000000001';
const INPUT_DIGEST = 'a'.repeat(64);
const PREFIX_DIGEST = 'b'.repeat(64);
const CHUNK_DIGEST = '73b2e2a853c51aff25dafdf04d36e97d92a062c385fa2aa41f4a2b9814510aca';
const EMPTY_PREFIX_DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const ITEMS = [{ operation: 'create', data: { label: 'Example Ltd' } }];

function runWire(overrides = {}) {
  return {
    runId: RUN_ID,
    status: 'open',
    blockedReason: null,
    entityId: 'people',
    operation: 'create',
    profileId: 'importer.v1',
    packageRevision: 'revision-1',
    schemaFingerprint: 'fingerprint-1',
    inputDigest: INPUT_DIGEST,
    inputLength: 4321,
    itemCount: 10,
    chunkCount: 3,
    chunkAlgorithmVersion: 'greedy-canonical-http-batch-v1',
    maximumItems: 100,
    maximumBytes: 1048576,
    nextChunkIndex: 1,
    committedItems: 0,
    committedPrefixDigest: EMPTY_PREFIX_DIGEST,
    lastAttempt: null,
    createdAt: '2026-09-19T00:00:00Z',
    updatedAt: '2026-09-19T00:01:00Z',
    complete: false,
    ...overrides,
  };
}

function receiptWire() {
  return {
    chunkIndex: 0,
    digest: CHUNK_DIGEST,
    replayed: false,
    erased: false,
    batch: {
      snapshot: 'breg1_00000000-0000-4000-8000-000000000002',
      results: [{ operation: 'create', id: RUN_ID, revision: 1, etag: '"breg-record-v1-abcdef012345"', data: { label: 'Example Ltd' } }],
    },
  };
}

let server;
let baseUrl;
const seen = [];

before(async () => {
  server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      const body = Buffer.concat(chunks).toString();
      seen.push({ url: request.url, method: request.method, contentType: request.headers['content-type'], body });
      const answer = (status, document) => {
        response.setHeader('traceparent', TRACEPARENT);
        response.setHeader('content-type', 'application/json');
        response.setHeader('cache-control', 'no-store');
        response.setHeader('vary', 'authorization, accept');
        response.statusCode = status;
        response.end(JSON.stringify(document));
      };
      if (request.method === 'POST' && request.url.endsWith('/v1/records/people/ingestion-runs')) {
        return answer(201, { run: runWire() });
      }
      if (request.method === 'GET' && request.url.includes('/chunks/0/receipt')) {
        return answer(200, { receipt: receiptWire() });
      }
      if (request.method === 'GET' && /ingestion-runs\/[0-9a-f-]+$/.test(request.url)) {
        return answer(200, { run: runWire({ status: 'cancelled', nextChunkIndex: 1 }) });
      }
      if (request.method === 'GET' && request.url.includes('/chunks/1/receipt')) {
        response.setHeader('traceparent', TRACEPARENT);
        response.setHeader('content-type', 'application/problem+json');
        response.setHeader('cache-control', 'no-store');
        response.statusCode = 410;
        return response.end(JSON.stringify({
          type: 'https://id.registrystack.org/problems/registry-breg/ingestion/receipt_erased',
          title: 'Gone',
          status: 410,
          detail: 'The chunk receipt was erased with the record history it described.',
          code: 'ingestion.receipt_erased',
          traceId: TRACE_ID,
        }));
      }
      if (request.method === 'GET' && request.url.includes('/ingestion-runs')) {
        return answer(200, { runs: [runWire()], hasMore: false, nextAfter: null });
      }
      if (request.method === 'POST' && request.url.endsWith('/chunks')) {
        return answer(200, { run: runWire({ committedItems: 1, nextChunkIndex: 1 }), receipt: receiptWire() });
      }
      if (request.method === 'POST' && request.url.endsWith('/cancel')) {
        return answer(200, { run: runWire({ status: 'cancelled' }) });
      }
      response.statusCode = 404;
      response.end('{}');
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}/tenant`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

test('the prefix digest accumulator follows the Rust empty-input base and raw bytes', () => {
  const digest = new BRegIngestionPrefixDigest();
  assert.equal(digest.digest(), EMPTY_PREFIX_DIGEST);
  digest.update(Buffer.from('abc'));
  assert.equal(digest.digest(), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  digest.update(Buffer.from('def'));
  assert.equal(digest.digest(), crypto.createHash('sha256').update('abcdef').digest('hex'));
  const fresh = new BRegIngestionPrefixDigest();
  assert.equal(fresh.digest(), EMPTY_PREFIX_DIGEST);
});

test('encodeIngestionChunk derives the chunk digest in Rust', () => {
  const chunk = encodeIngestionChunk(2, [{ a: 1 }], PREFIX_DIGEST);
  assert.ok(chunk instanceof BRegIngestionChunk);
  assert.equal(chunk.chunkIndex, 2);
  assert.equal(chunk.itemCount, 1);
  assert.equal(chunk.digest, CHUNK_DIGEST);
  assert.equal(chunk.prefixDigest, PREFIX_DIGEST);
});

test('encodeIngestionChunk refuses broken planning inputs without echoing values', () => {
  assert.throws(() => encodeIngestionChunk(0, [], PREFIX_DIGEST), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  assert.throws(() => encodeIngestionChunk(0, ['not-an-object'], PREFIX_DIGEST), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  assert.throws(() => encodeIngestionChunk(0, [{ a: 1 }], 'not-a-digest'), (error) => (
    error instanceof BaseRegistryClientError
    && error.kind === 'invalid_request'
    && !error.message.includes('not-a-digest')
  ));
  assert.throws(() => encodeIngestionChunk(1.5, [{ a: 1 }], PREFIX_DIGEST), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
});

test('createIngestionRun announces the exact run binding', async () => {
  const client = new BaseRegistryClient({ baseUrl });
  const outcome = await client.createIngestionRun('people', {
    operation: 'create',
    profileId: 'importer.v1',
    packageRevision: 'revision-1',
    schemaFingerprint: 'fingerprint-1',
    inputDigest: INPUT_DIGEST,
    inputLength: 4321,
    itemCount: 10,
    chunkCount: 3,
    chunkAlgorithmVersion: 'greedy-canonical-http-batch-v1',
  });
  assert.equal(outcome.kind, 'complete');
  assert.equal(outcome.traceId, TRACE_ID);
  assert.equal(outcome.value.runId, RUN_ID);
  assert.equal(outcome.value.status, 'open');
  assert.equal(outcome.value.itemCount, 10);
  assert.equal(outcome.value.complete, false);
  const announcement = JSON.parse(seen.at(-1).body);
  assert.deepEqual(announcement, {
    operation: 'create',
    profileId: 'importer.v1',
    packageRevision: 'revision-1',
    schemaFingerprint: 'fingerprint-1',
    inputDigest: INPUT_DIGEST,
    inputLength: 4321,
    itemCount: 10,
    chunkCount: 3,
    chunkAlgorithmVersion: 'greedy-canonical-http-batch-v1',
  });
  assert.equal(seen.at(-1).contentType, 'application/json');
});

test('createIngestionRun refuses unsupported, missing, and broken fields', async () => {
  const client = new BaseRegistryClient({ baseUrl });
  const valid = {
    operation: 'create',
    profileId: 'importer.v1',
    packageRevision: 'revision-1',
    schemaFingerprint: 'fingerprint-1',
    inputDigest: INPUT_DIGEST,
    inputLength: 4321,
    itemCount: 10,
    chunkCount: 3,
    chunkAlgorithmVersion: 'greedy-canonical-http-batch-v1',
  };
  await assert.rejects(client.createIngestionRun('people', { ...valid, extra: 1 }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  const missingItemCount = { ...valid };
  delete missingItemCount.itemCount;
  await assert.rejects(client.createIngestionRun('people', missingItemCount), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  await assert.rejects(client.createIngestionRun('people', { ...valid, operation: 'delete' }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  await assert.rejects(client.createIngestionRun('people', { ...valid, inputDigest: 'aaaa' }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  await assert.rejects(client.createIngestionRun('people', { ...valid, chunkAlgorithmVersion: 'greedy-canonical-http-batch-v2' }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
});

test('listIngestionRuns sends contract filters in order and returns the page', async () => {
  const client = new BaseRegistryClient({ baseUrl });
  const outcome = await client.listIngestionRuns('people', {
    limit: 25,
    after: 'cursor+/=',
    status: 'open',
    inputDigest: INPUT_DIGEST,
  });
  assert.equal(outcome.value.runs.length, 1);
  assert.equal(outcome.value.runs[0].runId, RUN_ID);
  assert.equal(outcome.value.hasMore, false);
  assert.equal(outcome.value.nextAfter, null);
  const query = new URLSearchParams(seen.at(-1).url.split('?')[1]);
  assert.deepEqual([...query.keys()], ['limit', 'after', 'status', 'inputDigest']);
  assert.equal(query.get('status'), 'open');
  assert.equal(query.get('inputDigest'), INPUT_DIGEST);

  await assert.rejects(client.listIngestionRuns('people', { status: 'archived' }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  await assert.rejects(client.listIngestionRuns('people', { limit: 0 }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  await assert.rejects(client.listIngestionRuns('people', { inputDigest: 'xyz' }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  const unfiltered = await client.listIngestionRuns('people');
  assert.equal(unfiltered.value.runs.length, 1);
});

test('readIngestionRun and cancelIngestionRun address one run', async () => {
  const client = new BaseRegistryClient({ baseUrl });
  const read = await client.readIngestionRun('people', RUN_ID);
  assert.equal(read.value.status, 'cancelled');
  assert.match(seen.at(-1).url, new RegExp(`/v1/records/people/ingestion-runs/${RUN_ID}$`));
  await assert.rejects(client.readIngestionRun('people', 'not-a-uuid'), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));

  const cancelled = await client.cancelIngestionRun('people', RUN_ID);
  assert.equal(cancelled.value.status, 'cancelled');
  const cancel = seen.at(-1);
  assert.match(cancel.url, /\/cancel$/);
  assert.equal(cancel.body, '');
  assert.equal(cancel.contentType, undefined);
});

test('submitIngestionChunk sends the encoded chunk and returns run and receipt', async () => {
  const client = new BaseRegistryClient({ baseUrl });
  const chunk = encodeIngestionChunk(0, ITEMS, PREFIX_DIGEST);
  const outcome = await client.submitIngestionChunk('people', RUN_ID, chunk);
  assert.equal(outcome.kind, 'complete');
  assert.equal(outcome.value.run.committedItems, 1);
  assert.equal(outcome.value.receipt.chunkIndex, 0);
  assert.equal(outcome.value.receipt.digest, CHUNK_DIGEST);
  assert.equal(outcome.value.receipt.batch.snapshot, 'breg1_00000000-0000-4000-8000-000000000002');
  assert.deepEqual(JSON.parse(seen.at(-1).body), {
    chunkIndex: 0,
    items: ITEMS,
    digest: chunk.digest,
    prefixDigest: PREFIX_DIGEST,
  });
});

test('ingestionChunkReceipt reads one retained receipt and reports an erased one', async () => {
  const client = new BaseRegistryClient({ baseUrl });
  const retained = await client.ingestionChunkReceipt('people', RUN_ID, 0);
  assert.equal(retained.value.replayed, false);
  assert.equal(retained.value.batch.results.length, 1);
  await assert.rejects(client.ingestionChunkReceipt('people', RUN_ID, 1), (error) => (
    error instanceof BaseRegistryClientError
    && error.kind === 'problem'
    && error.code === 'ingestion.receipt_erased'
    && error.status === 410
  ));
});
