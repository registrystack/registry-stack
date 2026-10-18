import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';

import {
  buildCoordinatorConfiguration,
  CONTRACTS,
  operationRows,
} from './generate-coordinator-configuration.mjs';

const generated = new URL('../../../products/coordinator/generated/', import.meta.url);

test('Coordinator covers every committed configuration schema', async () => {
  const directories = ['project', 'runtime', 'scenarios'];
  const files = (await Promise.all(directories.map(async (directory) =>
    (await readdir(new URL(`${directory}/`, generated)))
      .filter((name) => name.endsWith('.schema.json'))
      .map((name) => `${directory}/${name}`),
  ))).flat().sort();
  assert.deepEqual(files, CONTRACTS.map((contract) => contract.file.split('/generated/')[1]).sort());
  const document = await buildCoordinatorConfiguration();
  assert.deepEqual(document.contracts.map((contract) => contract.id), ['project', 'scenarios', 'runtime']);
  for (const contract of document.contracts) {
    assert.ok(contract.field_count > 0, contract.id);
    assert.equal(contract.field_count, new Set(contract.fields.map((field) => field.key_path)).size);
  }
});

test('Coordinator project and runtime references carry the keys authors and operators set', async () => {
  const document = await buildCoordinatorConfiguration();
  const keys = (id) => new Set(document.contracts.find((contract) => contract.id === id)
    .fields.map((field) => field.key_path));
  const project = keys('project');
  for (const path of ['workflow.steps', 'workflow.start', 'operations.*.uses', 'functions.*.entrypoint']) {
    assert.ok(project.has(path), path);
  }
  const runtime = keys('runtime');
  for (const path of [
    'connections',
    'deployment.databaseId',
    'deployment.packages[].expectedDigest',
    // stateKeys is a map declared through patternProperties, not additionalProperties.
    'deployment.stateKeys.*.keyRef',
  ]) {
    assert.ok(runtime.has(path), path);
  }
});

test('Coordinator operations follow the committed catalogue', async () => {
  const catalog = JSON.parse(await readFile(new URL('operations/catalog.json', generated), 'utf8'));
  const document = await buildCoordinatorConfiguration();
  assert.deepEqual(document.operations.map((row) => row.id), Object.keys(catalog));
  const review = document.operations.find((row) => row.id === 'casework.submit-review-request/v1');
  assert.equal(review.completion, 'result');
  assert.throws(() => operationRows({ 'a/v1': { host: { identity: { id: 'b/v1' }, limits: {} } } }), /names b\/v1/u);
});

// The reference page states one authority and one attempt budget for every
// operation, so a catalogue that starts to vary them must change the page too.
test('Coordinator operations share the authority and budget the reference states once', async () => {
  const document = await buildCoordinatorConfiguration();
  const shared = new Set(document.operations.map((row) =>
    `${row.authority} ${row.maximum_call_attempts} ${row.attempt_timeout_seconds}`));
  assert.deepEqual([...shared], ['current-bound-connection-authority 10 10']);
});

test('the reference page renders every operation column the catalogue generates', async () => {
  const document = await buildCoordinatorConfiguration();
  const page = await readFile(
    new URL('../src/content/docs/reference/coordinator-configuration.mdx', import.meta.url), 'utf8');
  assert.match(page, /<CoordinatorOperationsTable \/>/u);
  const component = await readFile(
    new URL('../src/components/CoordinatorOperationsTable.astro', import.meta.url), 'utf8');
  for (const column of ['id', 'product', 'effect', 'recovery', 'read_receipt', 'key_requirement', 'completion']) {
    assert.match(component, new RegExp(`operation\\.${column}`, 'u'), column);
    assert.ok(document.operations.every((row) => column in row), column);
  }
});
