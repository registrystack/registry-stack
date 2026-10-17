import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { test } from 'node:test';

import { buildCaseworkConfiguration, CONTRACTS } from './generate-casework-configuration.mjs';

test('Casework covers every committed configuration schema', async () => {
  const root = new URL('../../../products/casework/generated/', import.meta.url);
  const directories = (await readdir(root, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  const files = (await Promise.all(directories.map(async (directory) =>
    (await readdir(new URL(`${directory}/`, root)))
      .filter((name) => name.endsWith('.schema.json'))
      .map((name) => `${directory}/${name}`),
  ))).flat().sort();
  assert.deepEqual(files, CONTRACTS.map((contract) => contract.file.split('/generated/')[1]).sort());
  const document = await buildCaseworkConfiguration();
  assert.deepEqual(document.contracts.map((contract) => contract.id), ['project', 'fixture', 'dev-clients', 'holiday-set', 'runtime']);
  for (const contract of document.contracts) {
    assert.ok(contract.field_count > 0, contract.id);
    assert.equal(contract.field_count, new Set(contract.fields.map((field) => field.key_path)).size);
  }
});

test('Casework project reference carries the keys an author sets', async () => {
  const document = await buildCaseworkConfiguration();
  const project = new Map(document.contracts.find((contract) => contract.id === 'project')
    .fields.map((field) => [field.key_path, field]));
  for (const path of ['reviewPolicies', 'reviewPolicies.*.context.provider', 'contextProviders.*.sourceNamespace']) {
    assert.ok(project.has(path), path);
  }
});

test('Casework runtime reference carries the keys an operator sets', async () => {
  const document = await buildCaseworkConfiguration();
  const runtime = new Map(document.contracts.find((contract) => contract.id === 'runtime')
    .fields.map((field) => [field.key_path, field]));
  for (const path of ['identity.databaseId', 'listener.bind', 'database.runtimeUrlRef']) {
    assert.ok(runtime.has(path), path);
  }
});
