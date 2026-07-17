import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolve } from 'node:path';
import {
  buildProjectStarterMatrix,
  starterSources,
} from './generate-project-starters.mjs';

const repoRoot = resolve(import.meta.dirname, '../../..');

test('derives all advertised starter selections from committed golden workspaces', async () => {
  const starters = await buildProjectStarterMatrix(repoRoot);

  assert.deepEqual(
    starters.map(({ starter, integration, fixture }) => ({ starter, integration, fixture })),
    [
      { starter: 'http', integration: 'person-record', fixture: 'active-person' },
      {
        starter: 'dhis2-tracker',
        integration: 'health-record',
        fixture: 'complete-health-match',
      },
      {
        starter: 'opencrvs-dci',
        integration: 'birth-record',
        fixture: 'birth-record-match',
      },
      { starter: 'fhir-r4', integration: 'coverage', fixture: 'coverage-active' },
      { starter: 'snapshot', integration: 'person-snapshot', fixture: 'snapshot-match' },
    ],
  );
});

test('emits one canonical seven-command sequence for every starter', async () => {
  const starters = await buildProjectStarterMatrix(repoRoot);

  assert.equal(starters.length, starterSources.length);
  for (const starter of starters) {
    assert.equal(starter.commands.length, 7);
    assert.match(starter.commands[0], /^registryctl init --from /);
    assert.match(starter.commands[1], /^registryctl authoring editor --project-dir /);
    assert.match(starter.commands[2], / --trace$/);
    assert.match(starter.commands[3], / --watch$/);
    assert.match(starter.commands[4], /^registryctl test --project-dir [^ ]+$/);
    assert.match(starter.commands[5], / --environment local --explain$/);
    assert.match(starter.commands[6], / --environment local$/);
  }
});
