// SPDX-License-Identifier: Apache-2.0
'use strict';

const assert = require('node:assert/strict');
const { breg } = require(process.env.BREG_TEST_NODE_PACKAGE);

(async () => {
  const client = new breg.BaseRegistryClient({ baseUrl: process.env.BREG_TEST_CLIENT_URL });
  const metadata = await client.registryContract('operator');
  assert(metadata.operations.length > 0);
  const binding = metadata.selectCreate('records.entry.create', 'operator');
  const data = { code: 'NODE', label: 'Node package', validFrom: '2020-01-01' };
  const prepared = client.prepareCreate(binding, data, 'node-package-create');
  const first = await client.createRecord(binding, data, 'node-package-create');
  const fresh = await client.registryContract('operator');
  const currentBinding = fresh.selectCreate('records.entry.create', 'operator');
  const restored = breg.BRegPreparedCreate.fromBytes(prepared.toBytes());
  const recovered = client.recoverCreate(currentBinding, restored);
  const replay = await client.executeRecoveredCreate(currentBinding, recovered);
  assert.equal(replay.value.data.recordIdentifier, first.value.data.recordIdentifier);
  const historical = await client.listRecordsAsOf('entries', {
    accessProfile: 'operator', asOf: '2020-06-01T00:00:00Z',
  });
  assert.equal(historical.value.items[0].recordIdentifier, first.value.data.recordIdentifier);
  const current = await client.listCurrentRecords('entries', { accessProfile: 'operator' });
  assert.equal(current.value.items.length, 1);
  const batch = fresh.selectBatch('entry', 'operator');
  const batchResult = await client.batchRecords(batch, {
    items: [{ operation: 'create', data: { code: 'NODE-BATCH', label: 'Atomic Node package', validFrom: '2020-01-01' } }],
    changeContext: { kind: 'correction', reasonCode: 'package-proof' },
  }, 'node-package-batch');
  assert.equal(batchResult.value.results.length, 1);
  const exactBatch = await client.batchRecordsJson(batch,
    '{"items":[{"operation":"create","data":{"code":"NODE-EXACT","label":"Exact Node package","validFrom":"2020-01-01"}}]}',
    'node-package-exact-batch');
  assert.equal(JSON.parse(exactBatch.valueJson).results.length, 1);
  const snapshot = await client.listSnapshotRecords('entries', { accessProfile: 'operator', top: 1 });
  assert.equal(snapshot.value.items.length, 1);
  assert(snapshot.continuation);
  const snapshotNext = await client.continueSnapshotList(snapshot.continuation);
  assert.equal(snapshotNext.snapshot, snapshot.snapshot);
  const retained = await client.listSnapshotRecords('entries', {
    accessProfile: 'operator', snapshot: snapshot.snapshot,
  });
  assert.equal(retained.value.items.length, 3);
  const revision = await client.getRecordRevision('entries', first.value.data.recordIdentifier, 1, {
    accessProfile: 'operator',
  });
  assert(Buffer.isBuffer(revision.body));
  const revisions = await client.recordRevisions('entries', first.value.data.recordIdentifier, 'operator');
  assert(Buffer.isBuffer(revisions.body));
  const tombstone = fresh.selectTombstone('entry', 'operator');
  const removed = await client.tombstoneRecord(tombstone, first.value.data.recordIdentifier,
    first.etag, 'node-package-tombstone');
  assert.equal(removed.value.data.recordIdentifier, first.value.data.recordIdentifier);
  const removedReplay = await client.tombstoneRecordJson(tombstone, first.value.data.recordIdentifier,
    first.etag, 'node-package-tombstone');
  assert.equal(JSON.parse(removedReplay.valueJson).data.recordIdentifier, first.value.data.recordIdentifier);
  console.log('Installed public Node package completed real BREG reads, recovery, batch and tombstone mutations');
})().catch(error => {
  console.error(error.name, error.kind, error.code);
  process.exitCode = 1;
});
