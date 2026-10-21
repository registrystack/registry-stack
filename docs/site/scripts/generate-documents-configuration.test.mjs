import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { test } from 'node:test';

import { buildDocumentsConfiguration, CONTRACTS } from './generate-documents-configuration.mjs';

test('Document Store covers every committed configuration schema', async () => {
  const root = new URL('../../../products/documents/generated/', import.meta.url);
  const files = (await Promise.all(['project', 'runtime'].map(async (directory) =>
    (await readdir(new URL(`${directory}/`, root))).map((name) => `${directory}/${name}`),
  ))).flat().sort();
  assert.deepEqual(files, CONTRACTS.map((contract) => contract.file.split('/generated/')[1]).sort());
  const document = await buildDocumentsConfiguration();
  assert.deepEqual(document.contracts.map((contract) => contract.id), ['project', 'runtime']);
  for (const contract of document.contracts) {
    assert.equal(contract.field_count, new Set(contract.fields.map((field) => field.key_path)).size);
  }
});

test('Document Store reference carries the keys the operate page names', async () => {
  const document = await buildDocumentsConfiguration();
  const paths = (id) => new Set(document.contracts.find((contract) => contract.id === id)
    .fields.map((field) => field.key_path));
  const expected = {
    project: ['accessProfiles.*.role', 'documentPolicies.*.custodian',
      'documentPolicies.*.recipientProfiles',
      'documentPolicies.*.mandatoryRestrictions.cleanupGraceHours',
      'documentPolicies.*.mandatoryRestrictions.maximumGrantExpiryHours'],
    runtime: ['identity.databaseId', 'package.root', 'package.expectedDigest', 'listener.bind',
      'storage.maximumDocumentBytes', 'contentVerification.policyId', 'cleanup.erasure',
      'transfers.minimumDeadlineSeconds', 'retention.receiptRetentionDays'],
  };
  for (const [id, keys] of Object.entries(expected)) {
    const known = paths(id);
    for (const key of keys) assert.ok(known.has(key), `${id}: ${key}`);
  }
});
