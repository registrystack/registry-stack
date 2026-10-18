import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { test } from 'node:test';

import { buildMessagingConfiguration, CONTRACTS } from './generate-messaging-configuration.mjs';

test('Messaging covers every committed configuration schema', async () => {
  const root = new URL('../../../products/messaging/generated/', import.meta.url);
  const files = (await Promise.all(['authoring', 'runtime'].map(async (directory) =>
    (await readdir(new URL(`${directory}/`, root))).map((name) => `${directory}/${name}`),
  ))).flat().sort();
  assert.deepEqual(files, CONTRACTS.map((contract) => contract.file.split('/generated/')[1]).sort());
  const document = await buildMessagingConfiguration();
  assert.deepEqual(document.contracts.map((contract) => contract.id), ['project', 'template', 'provider', 'runtime']);
  for (const contract of document.contracts) {
    assert.equal(contract.field_count, new Set(contract.fields.map((field) => field.key_path)).size);
  }
});

test('Messaging reference carries the keys the author and operator pages name', async () => {
  const document = await buildMessagingConfiguration();
  const paths = (id) => new Set(document.contracts.find((contract) => contract.id === id)
    .fields.map((field) => field.key_path));
  const expected = {
    project: ['senderProfiles[].maximumSegments', 'senderProfiles[].retry.maximumAttempts',
      'senderProfiles[].onUncertain', 'accessProfiles[].requesterClients', 'accessProfiles[].burst'],
    template: ['channel', 'locales', 'parts'],
    provider: ['prepareScript', 'capabilities.receipts', 'capabilities.ratePerSecond'],
    runtime: ['identity.databaseId', 'listener.bind', 'package.root', 'package.expectedDigest',
      'retention.receiptRetentionDays', 'authentication.oidc.allowedClients'],
  };
  for (const [id, keys] of Object.entries(expected)) {
    const known = paths(id);
    for (const key of keys) assert.ok(known.has(key), `${id}: ${key}`);
  }
});
