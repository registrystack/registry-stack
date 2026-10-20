import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { test } from 'node:test';

import { buildRenderConfiguration, CONTRACTS } from './generate-render-configuration.mjs';

test('Render covers every committed configuration schema', async () => {
  const root = new URL('../../../products/render/schemas/', import.meta.url);
  const files = (await readdir(root)).sort();
  assert.deepEqual(files, CONTRACTS.map((contract) => contract.file.split('/schemas/')[1]).sort());
  const document = await buildRenderConfiguration();
  assert.deepEqual(document.contracts.map((contract) => contract.id), ['bundle', 'labels', 'runtime']);
  for (const contract of document.contracts) {
    assert.equal(contract.field_count, new Set(contract.fields.map((field) => field.key_path)).size);
  }
});

test('Render reference carries the keys an author and an operator set', async () => {
  const document = await buildRenderConfiguration();
  const keys = (id) => new Set(document.contracts.find((contract) => contract.id === id)
    .fields.map((field) => field.key_path));
  for (const path of ['documents[].id', 'documents[].entryFile', 'documents[].labels']) {
    assert.ok(keys('bundle').has(path), path);
  }
  assert.ok(keys('labels').has('labels.*'));
  for (const path of ['listener.bind', 'package.root', 'auth.apiKeyRef', 'audit.path']) {
    assert.ok(keys('runtime').has(path), path);
  }
});

test('Render listener.bind states the port rule and every host shape, not only the length', async () => {
  const document = await buildRenderConfiguration();
  const runtime = document.contracts.find((contract) => contract.id === 'runtime');
  const bind = runtime.fields.find((field) => field.key_path === 'listener.bind');
  // One alternative per host shape: IPv4, hexadecimal IPv6, and mixed IPv6.
  assert.equal(bind.constraints.length, 3);
  for (const group of bind.constraints) {
    assert.ok(group.includes('maxLength: 128'), JSON.stringify(group));
    assert.ok(group.some((constraint) => constraint.startsWith('pattern: :0*(?:[0-9]{1,4}')), JSON.stringify(group));
    assert.equal(group.filter((constraint) => constraint.startsWith('pattern: ^')).length, 1);
  }
});
