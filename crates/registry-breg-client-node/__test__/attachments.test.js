'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient, BaseRegistryClientError } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const fixture = require('../../registry-breg-client/tests/fixtures/attachments.json');

const RECORD_ID = fixture.record.data.recordIdentifier;
const SLOT_PATH = `/v1/records/companies/${RECORD_ID}/attachments/supporting-file`;
const ETAG = '"breg-record-000000000001"';
const TRACEPARENT = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const CONTENT = Buffer.from(fixture.content);

function emptied() {
  const value = structuredClone(fixture.record);
  value.data.domainData['supporting-file'] = null;
  return value;
}

async function harness() {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: Buffer.concat(chunks),
    });
    response.setHeader('traceparent', TRACEPARENT);
    response.setHeader('cache-control', 'no-store');
    if (request.url.startsWith('/v1/registry')) {
      response.setHeader('content-type', 'application/json');
      response.setHeader('vary', 'authorization, accept');
      return response.end(JSON.stringify(fixture.metadata));
    }
    if (request.method === 'GET') {
      response.setHeader('content-type', 'application/pdf');
      response.setHeader('content-disposition', 'attachment');
      response.setHeader('x-content-type-options', 'nosniff');
      response.setHeader('vary', 'authorization');
      return response.end(CONTENT);
    }
    response.setHeader('content-type', 'application/json');
    response.setHeader('vary', 'authorization, accept');
    response.setHeader('etag', ETAG);
    response.setHeader(
      'link',
      '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", '
        + '</v1/schemas/company>; rel="describedby"',
    );
    response.end(JSON.stringify(request.method === 'DELETE' ? emptied() : fixture.record));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
  const metadata = await client.registryContract('company-writer');
  const [slot] = metadata.selectAttachments('company', 'company-writer');
  return {
    client,
    metadata,
    slot,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test('a selected slot exposes the served limits and its record projection', async () => {
  const { slot, requests, close } = await harness();
  try {
    assert.equal(slot.slotIdentifier, 'supporting-file');
    assert.equal(slot.entityIdentifier, 'company');
    assert.equal(slot.accessProfile, 'company-writer');
    assert.equal(slot.requiredForSubmit, true);
    assert.equal(slot.maximumBytes, 1024);
    assert.deepEqual(slot.contentTypes, ['application/pdf']);
    assert.equal(slot.acceptsContentType('application/pdf'), true);
    assert.equal(slot.acceptsContentType('image/png'), false);
    assert.equal(slot.canDownload, true);
    assert.equal(slot.canUpload, true);
    assert.equal(slot.canRemove, true);

    assert.deepEqual(slot.valueIn(fixture.record), {
      kind: 'filled',
      value: {
        slotIdentifier: 'supporting-file',
        proposalVersion: 2,
        erased: false,
        byteSize: CONTENT.length,
        sha256: fixture.record.data.domainData['supporting-file'].sha256,
        contentType: 'application/pdf',
        uploadedAt: '2026-01-02T03:04:05.000000Z',
        uploadedBy: 'urn:registry:actor:filer',
        verificationStatus: 'approved',
      },
    });
    assert.deepEqual(slot.valueIn(emptied()), { kind: 'empty', value: null });
    const unselected = structuredClone(fixture.record);
    delete unselected.data.domainData['supporting-file'];
    assert.deepEqual(slot.valueIn(unselected), { kind: 'not_selected', value: null });
    assert.equal(requests.length, 1);
  } finally {
    await close();
  }
});

test('an upload the slot cannot accept never reaches the engine', async () => {
  const { slot, requests, close } = await harness();
  try {
    for (const [contentType, body] of [
      ['application/pdf', Buffer.alloc(0)],
      ['application/pdf', Buffer.alloc(1025, 0x41)],
      ['image/png', CONTENT],
      ['Application/PDF', CONTENT],
      ['application/pdf; charset=utf-8', CONTENT],
      ['*/*', CONTENT],
    ]) {
      assert.throws(
        () => slot.prepareUpload(contentType, body),
        (error) => error instanceof BaseRegistryClientError && error.kind === 'invalid_request',
      );
    }
    assert.equal(requests.length, 1);
  } finally {
    await close();
  }
});

test('the three attachment exchanges use the engine routes and governed headers', async () => {
  const { client, slot, requests, close } = await harness();
  try {
    const upload = slot.prepareUpload('application/pdf', CONTENT);
    assert.equal(upload.contentType, 'application/pdf');
    assert.equal(upload.byteSize, CONTENT.length);

    const uploaded = await client.uploadAttachment(slot, RECORD_ID, ETAG, upload, 'upload-1');
    assert.equal(uploaded.kind, 'complete');
    assert.equal(uploaded.value.data.recordIdentifier, RECORD_ID);
    assert.equal(uploaded.etag, ETAG);
    const patch = requests.at(-1);
    assert.equal(patch.method, 'PATCH');
    assert.equal(patch.url, `${SLOT_PATH}?accessProfile=company-writer`);
    assert.equal(patch.headers['content-type'], 'application/pdf');
    assert.equal(patch.headers['if-match'], ETAG);
    assert.equal(patch.headers['idempotency-key'], 'upload-1');
    assert.deepEqual(patch.body, CONTENT);

    const download = await client.downloadAttachment(slot, RECORD_ID, 2);
    assert.equal(download.mediaType, 'application/pdf');
    assert.deepEqual(download.body, CONTENT);
    assert.equal(
      requests.at(-1).url,
      `${SLOT_PATH}?proposalVersion=2&accessProfile=company-writer`,
    );
    assert.equal(requests.at(-1).method, 'GET');

    const removed = await client.deleteAttachment(slot, RECORD_ID, ETAG, 'remove-1');
    assert.equal(removed.value.data.domainData['supporting-file'], null);
    const remove = requests.at(-1);
    assert.equal(remove.method, 'DELETE');
    assert.equal(remove.url, `${SLOT_PATH}?accessProfile=company-writer`);
    assert.equal(remove.headers['if-match'], ETAG);
    assert.equal(remove.headers['idempotency-key'], 'remove-1');
    assert.equal(remove.body.length, 0);

    const exact = await client.uploadAttachmentJson(slot, RECORD_ID, ETAG, upload, 'upload-1');
    assert.equal(JSON.parse(exact.valueJson).data.recordIdentifier, RECORD_ID);
    const exactRemoval = await client.deleteAttachmentJson(slot, RECORD_ID, ETAG, 'remove-1');
    assert.equal(JSON.parse(exactRemoval.valueJson).data.domainData['supporting-file'], null);
  } finally {
    await close();
  }
});

test('slot authority stays bound to the client source and the served routes', async () => {
  const first = await harness();
  const second = await harness();
  try {
    const before = second.requests.length;
    await assert.rejects(
      second.client.downloadAttachment(first.slot, RECORD_ID, 1),
      (error) => error instanceof BaseRegistryClientError && error.kind === 'invalid_request',
    );
    await assert.rejects(
      second.client.downloadAttachment(second.slot, RECORD_ID, 0),
      (error) => error instanceof BaseRegistryClientError && error.kind === 'invalid_request',
    );
    await assert.rejects(
      second.client.uploadAttachment(second.slot, 'not-a-uuid', ETAG,
        second.slot.prepareUpload('application/pdf', CONTENT), 'upload-1'),
      (error) => error instanceof BaseRegistryClientError && error.kind === 'invalid_request',
    );
    assert.throws(
      () => second.metadata.selectAttachments('missing-entity', 'company-writer'),
      (error) => error instanceof BaseRegistryClientError
        && error.kind === 'metadata_selection' && error.code === 'not_found',
    );
    assert.throws(
      () => second.metadata.selectAttachments('company', 'auditor'),
      (error) => error instanceof BaseRegistryClientError
        && error.kind === 'metadata_selection' && error.code === 'profile_mismatch',
    );
    assert.equal(second.requests.length, before);
  } finally {
    await first.close();
    await second.close();
  }
});
