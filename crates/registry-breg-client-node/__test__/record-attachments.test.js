'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { createHash } = require('node:crypto');
const { BaseRegistryClient } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const id = '00000000-0000-4000-8000-000000000001';
const slot = 'evidence';
const bytes = Buffer.from('%PDF-1.7 promoted record file');
const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const profileLink = '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/application>; rel="describedby"';
const meta = { registryIdentifier: 'registry', datasetIdentifier: 'dataset', recordTypeIdentifier: 'application' };
const proposal = { actionId: 'amend', proposalId: '00000000-0000-4000-8000-0000000000aa', submissionVersion: 1 };
const revision = { recordIdentifier: id, revisionIdentifier: '2', domainData: { name: 'one' }, proposal };

function digest(body) {
  return `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
}

async function serve(t, digestHeader) {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({ url: request.url, accept: request.headers.accept });
    response.setHeader('traceparent', traceparent);
    response.setHeader('cache-control', 'no-store');
    const path = request.url.split('?')[0];
    if (path.includes('/attachments/')) {
      response.setHeader('content-type', 'application/pdf');
      response.setHeader('content-disposition', 'attachment');
      response.setHeader('x-content-type-options', 'nosniff');
      response.setHeader('vary', 'authorization');
      if (digestHeader !== undefined) response.setHeader('repr-digest', digestHeader);
      return response.end(bytes);
    }
    response.setHeader('content-type', 'application/json');
    response.setHeader('link', profileLink);
    const document = path.endsWith('/revisions')
      ? { items: [revision], pageInfo: { hasNextPage: false } }
      : { data: revision, meta };
    response.end(JSON.stringify(document));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { client: new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` }), requests };
}

test('a record attachment download uses the slot route and returns the verified digest', async t => {
  const { client, requests } = await serve(t, digest(bytes));
  const downloaded = await client.downloadRecordAttachment('applications', id, slot, 'auditor');
  assert.deepEqual(downloaded.body, bytes);
  assert.equal(downloaded.mediaType, 'application/pdf');
  assert.equal(downloaded.reprDigest, digest(bytes));
  assert.equal(requests[0].url, `/v1/records/applications/${id}/attachments/${slot}?accessProfile=auditor`);
  assert.equal(requests[0].accept, '*/*');
});

test('a record attachment whose bytes miss the stated digest is a protocol refusal', async t => {
  for (const header of [digest(Buffer.from('other bytes')), undefined]) {
    const { client } = await serve(t, header);
    await assert.rejects(
      client.downloadRecordAttachment('applications', id, slot),
      error => error.kind === 'protocol',
    );
  }
});

test('invalid record attachment selectors never reach HTTP', async t => {
  const { client, requests } = await serve(t, digest(bytes));
  for (const [route, record, name] of [
    ['applications', 'not-a-record', slot],
    ['applications', id, '../evidence'],
    ['applications', id, 'Evidence'],
    ['applications/other', id, slot],
  ]) {
    await assert.rejects(
      client.downloadRecordAttachment(route, record, name),
      error => error.kind === 'invalid-request',
    );
  }
  assert.equal(requests.length, 0);
});

test('revision reads keep the Proposal link the server sent', async t => {
  const { client } = await serve(t, digest(bytes));
  const history = JSON.parse((await client.recordRevisions('applications', id, 'auditor')).body);
  assert.deepEqual(history.items[0].proposal, proposal);
  const single = JSON.parse((await client.getRecordRevision('applications', id, 2, { accessProfile: 'auditor' })).body);
  assert.deepEqual(single.data.proposal, proposal);
});
