'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const id = '00000000-0000-4000-8000-000000000001';
const snapshot = 'breg1_00000000-0000-4000-8000-000000000002';
const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const link = '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", </v1/schemas/company>; rel="describedby"';
const meta = { registryIdentifier: 'registry', datasetIdentifier: 'dataset', entityTypeIdentifier: 'company' };
const record = { recordIdentifier: id, revisionIdentifier: '1', domainData: { label: 'one' } };
const feature = { type: 'Feature', id, geometry: null, properties: { wide: 9007199254740992 }, registry: { revision: 1 } };

function respond(response, mediaType, document, includeLink = false, etag = false) {
  response.setHeader('content-type', mediaType);
  response.setHeader('traceparent', traceparent);
  if (includeLink) response.setHeader('link', link);
  if (etag) response.setHeader('etag', '"breg-record-000000000001"');
  response.end(typeof document === 'string' ? document : JSON.stringify(document));
}

test('specialized read methods keep routes, cursors, snapshots, exact JSON and option boundaries', async () => {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({ accept: request.headers.accept, url: request.url });
    const path = request.url.split('?')[0];
    const continuation = request.url.includes('$skiptoken=');
    if (request.headers.accept === 'application/geo+json') {
      if (path.endsWith(id)) return respond(response, 'application/geo+json', feature);
      return respond(response, 'application/geo+json', `{"type":"FeatureCollection","features":[{"type":"Feature","id":"${id}","geometry":null,"properties":{"wide":9007199254740992},"registry":{"revision":1}}],"numberReturned":1,"registry":{"pageInfo":{"nextCursor":${continuation ? 'null' : '"geo-next"'}}}}`);
    }
    const collection = !path.endsWith(id) && !path.includes('/revisions/');
    if (collection) {
      const document = { items: [record], pageInfo: { nextCursor: continuation ? null : 'next' }, meta };
      if (path.includes(':snapshot')) {
        document.snapshot = snapshot;
        if (request.url.includes('validAt=')) document.validAt = '2026-09-10T00:00:00Z';
      }
      return respond(response, 'application/json', document, true);
    }
    if (path.includes('/revisions/')) return respond(response, 'application/json', { data: record, meta }, true);
    return respond(response, 'application/json', { data: record, meta }, true, true);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
    await client.listRecords('companies', { bbox: ['100.1', '13.1', '100.2', '13.2'] });
    await client.listRecordsJson('companies', { bbox: ['100.1', '13.1', '100.2', '13.2'] });
    await client.getRecord('companies', id, { requestHistoryAfterProposalVersion: 3 });
    await client.getRecordJson('companies', id, { requestHistoryAfterProposalVersion: 4 });
    assert(Buffer.isBuffer((await client.getRecordRevision('companies', id, 1)).body));

    assert.equal((await client.getGeoJsonRecord('companies', id)).value.type, 'Feature');
    assert.match((await client.getGeoJsonRecordJson('companies', id)).valueJson, /9007199254740992/);
    const geo = await client.listGeoJsonRecords('companies', { accessProfile: 'map', bbox: ['100.1', '13.1', '100.2', '13.2'] });
    await client.continueGeoJsonList(geo.continuation);
    const geoJson = await client.listGeoJsonRecordsJson('companies');
    assert.match(geoJson.valueJson, /9007199254740992/);
    await client.continueGeoJsonListJson(geoJson.continuation);

    const current = await client.listCurrentRecords('companies');
    await client.continueCurrentList(current.continuation);
    const currentJson = await client.listCurrentRecordsJson('companies');
    await client.continueCurrentListJson(currentJson.continuation);

    const asOf = await client.listRecordsAsOf('companies', { asOf: '2026-09-10T00:00:00Z' });
    await client.continueAsOfList(asOf.continuation);
    const asOfJson = await client.listRecordsAsOfJson('companies', { asOf: '2026-09-10T00:00:00Z' });
    await client.continueAsOfListJson(asOfJson.continuation);

    const snapshotPage = await client.listSnapshotRecords('companies', { validAt: '2026-09-10T00:00:00Z' });
    assert.equal(snapshotPage.snapshot, snapshot);
    assert.equal(snapshotPage.validAt, '2026-09-10T00:00:00Z');
    const snapshotContinuationPage = await client.listSnapshotRecords('companies');
    await client.continueSnapshotList(snapshotContinuationPage.continuation);
    const snapshotJson = await client.listSnapshotRecordsJson('companies');
    await client.continueSnapshotListJson(snapshotJson.continuation);

    const related = await client.listRelationshipRecords('companies', id, 'related');
    await client.continueRelationshipList(related.continuation);
    const relatedJson = await client.listRelationshipRecordsJson('companies', id, 'related');
    await client.continueRelationshipListJson(relatedJson.continuation);

    assert(requests.some(item => item.url.includes('bbox=100.1%2C13.1%2C100.2%2C13.2')));
    assert(requests.some(item => item.url.includes('requestHistoryAfterProposalVersion=3')));
    assert(requests.some(item => item.accept === 'application/geo+json' && item.url.includes('$skiptoken=geo-next')));
    assert(requests.some(item => item.url.includes('/companies:as-of?asOf=2026-09-10T00%3A00%3A00Z')));
    assert(requests.some(item => item.url.includes(`/companies/${id}/related?$skiptoken=next`)));

    const requestCount = requests.length;
    await assert.rejects(client.listCurrentRecords('companies', { bbox: ['1', '2', '3', '4'] }), error => error.kind === 'invalid_request');
    await assert.rejects(client.getRecordRevision('companies', id, Number.MAX_SAFE_INTEGER + 1), error => error.kind === 'invalid_request');
    assert.equal(requests.length, requestCount);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
