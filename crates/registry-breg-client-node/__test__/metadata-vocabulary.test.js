'use strict';
const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const revision = `sha256:${'a'.repeat(64)}`;
const vocabularies = [
  'https://example.org/vocabularies/licence-statuses',
  'สถานะใบอนุญาต/許可状態',
  '',
  'line one\nline two\0',
];

function metadata(vocabulary) {
  return {
    id: 'fixture-registry', version: '1', revision, metadataVersion: '2',
    recordTypes: [], operations: [],
    statisticalDatasets: [{
      id: 'item-counts', unit: 'item', periodKind: 'flow', granularity: 'month',
      firstPeriod: '2025-01', definitionDigest: revision, operations: ['read-live'],
      dimensions: [{ field: 'status', vocabulary, codes: ['active', '_T'] }],
    }],
    actions: [{
      id: 'update-status', apiName: 'updateStatus', revision,
      display: { label: 'Update status' }, execution: { mode: 'immediate' },
      route: '/v1/actions/update-status', inputMode: 'handler', maximumInputStringBytes: 16384,
      inputs: [{
        id: 'status', apiName: 'status', schema: { type: 'string', enum: ['active'] },
        fieldType: { type: 'vocabulary-code', vocabulary, values: ['active'] },
        required: true, nullable: false, classification: 'internal',
      }],
      referenceInputs: [], requiredConditionKeys: [], resultEffects: [],
      access: { selectedProfile: 'writer' },
      routes: { invoke: {
        method: 'POST', path: '/v1/actions/update-status',
        operationId: 'actions.update-status.invoke', requiresIdempotencyKey: true,
        inputSchema: 'action-update-status-invoke-input',
        responseSchema: 'action-update-status-invoke-response',
      } },
      bounds: { maximumTargets: 1, maximumFieldMutations: 1, maximumSnapshotBytes: 1024 },
    }],
  };
}

test('registry contract preserves every bounded engine vocabulary string', async () => {
  let vocabulary = vocabularies[0];
  const server = http.createServer((_request, response) => {
    const body = JSON.stringify(metadata(vocabulary));
    response.setHeader('content-type', 'application/json');
    response.setHeader('traceparent', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('vary', 'authorization, accept');
    response.end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = new BaseRegistryClient({ baseUrl: `http://127.0.0.1:${server.address().port}` });
    for (vocabulary of vocabularies) {
      const contract = await client.registryContract('writer');
      assert.equal(contract.statisticalDatasets[0].dimensions[0].vocabulary, vocabulary);
      assert.equal(JSON.parse(contract.actions[0].inputs[0].fieldTypeJson).vocabulary, vocabulary);
      contract.selectAction('update-status', 'writer');
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
