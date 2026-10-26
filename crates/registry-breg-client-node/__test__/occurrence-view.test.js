'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { test } = require('node:test');
const pkg = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const { BaseRegistryClient, occurrenceView } = pkg;

const fixtures = path.join(
  __dirname, '..', '..', 'registry-breg-client', 'tests', 'fixtures', 'occurrence-view',
);
const read = (name) => fs.readFileSync(path.join(fixtures, name), 'utf8');

const revision = `sha256:${'a'.repeat(64)}`;
const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const recordId = '6f1e0c62-0000-4000-8000-000000000001';
const hiddenId = '6f1e0c62-0000-4000-8000-000000000404';
const link = '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/incorporation>; rel="describedby"';

test('occurrenceView projects every generated fixture to its recorded view', () => {
  for (const name of [
    'incorporation', 'suspension-decision', 'suspension-correction', 'ownership-transfer',
  ]) {
    const view = occurrenceView(read(`${name}.input.json`));
    assert.equal(typeof view, 'string');
    assert.deepEqual(JSON.parse(view), JSON.parse(read(`${name}.json`)), name);
  }
});

test('occurrenceView raises a described occurrence failure', () => {
  const input = JSON.parse(read('incorporation.input.json'));
  input.descriptor.descriptorVersion = 2;
  assert.throws(() => occurrenceView(JSON.stringify(input)), (error) => {
    assert.equal(error.kind, 'occurrence');
    assert.equal(error.code, 'unsupported-version');
    assert.equal(error.outcomeUnknown, false);
    return true;
  });
  assert.throws(() => occurrenceView('{"unknown":true}'), (error) => {
    assert.equal(error.kind, 'occurrence');
    assert.equal(error.code, 'invalid-input');
    return true;
  });
  assert.throws(() => occurrenceView({}), (error) => error.kind === 'invalid-request');
});

test('the metadata accessor and the creation-revision read follow the declared contract', async () => {
  const input = JSON.parse(read('incorporation.input.json'));
  const metadata = {
    id: 'fixture-registry', version: '1', revision, metadataVersion: '2',
    recordTypes: [
      {
        id: 'incorporation', datasetIdentifier: 'register', route: 'incorporations',
        operations: [], readableFields: [], schema: '/v1/schemas/incorporation',
        occurrence: input.descriptor,
      },
      {
        id: 'note', datasetIdentifier: 'register', route: 'notes', operations: [],
        readableFields: [], schema: '/v1/schemas/note',
      },
    ],
    operations: [],
  };
  const created = {
    data: {
      recordIdentifier: recordId, revisionIdentifier: '1', domainData: {},
      predecessorRevision: null, lifecycle: 'active', packageRevision: revision,
      operationIdentifier: 'records.incorporation.create', mutationKind: 'create',
      createdAt: '2026-10-26T08:15:30.123456Z', actorReference: 'actor-ref-1',
      requestReference: 'request-ref-1',
    },
    meta: { registryIdentifier: 'registry', datasetIdentifier: 'dataset', entityTypeIdentifier: 'incorporation' },
  };
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    response.setHeader('traceparent', traceparent);
    if (request.url.startsWith('/v1/registry')) {
      response.setHeader('content-type', 'application/json');
      response.setHeader('cache-control', 'no-store');
      response.setHeader('vary', 'authorization, accept');
      return response.end(JSON.stringify(metadata));
    }
    if (request.url.includes('/incorporations/')) {
      if (request.url.includes(hiddenId)) {
        response.statusCode = 404;
        response.setHeader('content-type', 'application/problem+json');
        response.setHeader('cache-control', 'no-store');
        return response.end(JSON.stringify({
          type: 'https://id.registrystack.org/problems/registry-breg/resource/not_found',
          title: 'Not Found', status: 404, detail: 'The requested resource was not found.',
          code: 'resource.not_found', traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
        }));
      }
      response.setHeader('content-type', 'application/json');
      response.setHeader('link', link);
      return response.end(JSON.stringify(created));
    }
    response.statusCode = 500;
    return response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
    const contract = await client.registryContract();
    const descriptor = JSON.parse(contract.occurrenceDescriptor('incorporation'));
    assert.equal(descriptor.descriptorVersion, 1);
    assert.equal(descriptor.label, 'Incorporation');
    for (const absent of ['note', 'unknown-type']) {
      assert.throws(() => contract.occurrenceDescriptor(absent), (error) => {
        assert.equal(error.kind, 'occurrence');
        assert.equal(error.code, 'not-an-occurrence');
        return true;
      });
    }

    const text = await client.occurrenceCreationRevision('incorporations', recordId);
    assert.deepEqual(JSON.parse(text), {
      recordType: 'incorporation', recordId, revision: '1',
      createdAt: '2026-10-26T08:15:30.123456Z',
    });
    assert.ok(requests.some((url) => url.includes(`/incorporations/${recordId}/revisions/1`)));
    assert.equal(await client.occurrenceCreationRevision('incorporations', hiddenId), null);
    input.creationRevision = JSON.parse(text);
    assert.deepEqual(
      JSON.parse(occurrenceView(JSON.stringify(input))).recordedAt,
      { status: 'available', type: 'instant', value: '2026-10-26T08:15:30.123456Z' },
    );
    input.creationRevision.recordType = 'ownership-transfer';
    assert.throws(() => occurrenceView(JSON.stringify(input)), (error) => {
      assert.equal(error.kind, 'occurrence');
      assert.equal(error.code, 'wrong-record-evidence');
      assert.doesNotMatch(error.message, /ownership-transfer/);
      return true;
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
