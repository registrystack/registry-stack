import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { test } from 'node:test';

import { buildSchedulingConfiguration, CONTRACTS } from './generate-scheduling-configuration.mjs';

test('Scheduling covers every committed configuration schema', async () => {
  const root = new URL('../../../products/scheduling/generated/', import.meta.url);
  const files = (await Promise.all(['project', 'records', 'fixture', 'runtime'].map(async (directory) =>
    (await readdir(new URL(`${directory}/`, root))).map((name) => `${directory}/${name}`),
  ))).flat().sort();
  assert.deepEqual(files, CONTRACTS.map((contract) => contract.file.split('/generated/')[1]).sort());
  const document = await buildSchedulingConfiguration();
  assert.deepEqual(document.contracts.map((contract) => contract.id), ['project', 'records', 'fixture', 'runtime']);
  for (const contract of document.contracts) {
    assert.equal(contract.field_count, new Set(contract.fields.map((field) => field.key_path)).size);
  }
});

test('Scheduling runtime reference carries the keys an operator sets', async () => {
  const document = await buildSchedulingConfiguration();
  const runtime = new Map(document.contracts.find((contract) => contract.id === 'runtime')
    .fields.map((field) => [field.key_path, field]));
  for (const path of ['identity.databaseId', 'listener.bind', 'package.root']) {
    assert.ok(runtime.has(path), path);
  }
});
