import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { dirname, join, resolve } from 'node:path';
import YAML from 'yaml';
import {
  buildProjectAuthoringJourneyMatrix,
  buildProjectStarterMatrix,
} from './generate-project-starters.mjs';

const repoRoot = resolve(import.meta.dirname, '../../..');
const catalogRelative = 'crates/registryctl/tests/fixtures/project-authoring-journeys.yaml';

async function withIsolatedProjectCatalog(run) {
  const root = await mkdtemp(join(tmpdir(), 'registry-project-catalog-'));
  try {
    const catalogPath = resolve(root, catalogRelative);
    const catalog = YAML.parse(await readFile(resolve(repoRoot, catalogRelative), 'utf8'));
    await mkdir(dirname(catalogPath), { recursive: true });
    await writeFile(catalogPath, YAML.stringify(catalog));
    const sources = new Set([
      ...catalog.workspaces.map((workspace) => workspace.source),
      'crates/registryctl/assets/project-starters/bounded-http',
      'crates/registryctl/assets/project-starters/spreadsheet',
    ]);
    for (const source of sources) {
      const destination = resolve(root, source);
      await mkdir(dirname(destination), { recursive: true });
      await cp(resolve(repoRoot, source), destination, { recursive: true });
    }
    await run({ root, catalog, catalogPath });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('classifies every golden and derives topology from committed workspace content', async () => {
  const journeys = await buildProjectAuthoringJourneyMatrix(repoRoot);

  assert.equal(journeys.length, 15);
  assert.deepEqual(
    journeys.map(({ id, classification, topology }) => ({ id, classification, topology })),
    [
      { id: 'http', classification: 'maintained', topology: 'relay-only' },
      { id: 'custom-system', classification: 'maintained', topology: 'relay-only' },
      { id: 'dhis2-script', classification: 'conformance-only', topology: 'relay-only' },
      { id: 'dhis2-tracker', classification: 'maintained', topology: 'relay-only' },
      { id: 'fhir-r4-coverage-active', classification: 'maintained', topology: 'relay-only' },
      { id: 'nia-attribute-release', classification: 'conformance-only', topology: 'relay-only' },
      { id: 'opencrvs-dci', classification: 'maintained', topology: 'relay-only' },
      { id: 'opencrvs-events-api', classification: 'maintained', topology: 'relay-only' },
      { id: 'opencrvs-country-variant', classification: 'maintained', topology: 'relay-only' },
      { id: 'openspp-exact', classification: 'maintained', topology: 'relay-only' },
      { id: 'relay-only-materialization', classification: 'maintained', topology: 'relay-only' },
      { id: 'relay-only-records', classification: 'maintained', topology: 'relay-only' },
      { id: 'snapshot', classification: 'maintained', topology: 'relay-only' },
      { id: 'snapshot-with-records', classification: 'maintained', topology: 'relay-only' },
      { id: 'spreadsheet', classification: 'maintained', topology: 'relay-only' },
    ],
  );
});

test('derives both public starters from committed workspace content', async () => {
  const starters = await buildProjectStarterMatrix(repoRoot);

  assert.deepEqual(
    starters.map(({ starter, integration, fixture }) => ({ starter, integration, fixture })),
    [
      { starter: 'spreadsheet', integration: 'project-record-snapshot', fixture: 'match' },
      { starter: 'http', integration: 'person-record', fixture: 'active-person' },
    ],
  );
});

test('emits one canonical 1.0 authoring and development sequence for both starters', async () => {
  const starters = await buildProjectStarterMatrix(repoRoot);

  assert.equal(starters.length, 2);
  for (const starter of starters) {
    assert.deepEqual(starter.capabilities, [
      'init',
      'editor',
      'trace',
      'watch',
      'test',
      'check',
      'compare',
      'build',
      'dev',
    ]);
    assert.equal(starter.commands.length, 11);
    assert.match(
      starter.commands[0],
      new RegExp(`^registryctl init ${starter.project_dir} --template ${starter.starter}$`),
    );
    assert.match(starter.commands[1], /^registryctl -C [^ ]+ tooling editor$/);
    assert.match(starter.commands[2], / --trace$/);
    assert.match(starter.commands[3], / --watch$/);
    assert.match(starter.commands[4], /^registryctl -C [^ ]+ test$/);
    assert.match(starter.commands[5], / --environment local --explain$/);
    assert.match(starter.commands[6], / review compare --environment local$/);
    assert.match(starter.commands[7], / --environment local$/);
    assert.match(starter.commands[8], / dev --detach$/);
    assert.match(starter.commands[9], / dev smoke$/);
    assert.match(starter.commands[10], / dev down$/);
  }
});

test('internal workspaces never emit a public template command', async () => {
  const journeys = await buildProjectAuthoringJourneyMatrix(repoRoot);
  const nonStarters = journeys.filter((journey) => !journey.starter);
  assert.equal(nonStarters.length, 13);
  for (const journey of nonStarters) {
    assert.equal(journey.commands.some((command) => command.includes(' init ')), false);
    assert.equal(journey.project_dir, journey.source);
    assert.equal(
      journey.commands.every((command) => command.includes(`-C ${journey.source}`)),
      true,
    );
    assert.doesNotMatch(
      journey.commands.join('\n'),
      /registryctl (?:authoring|project|compare|start|stop|smoke)\b/,
    );
  }

  assert.deepEqual(
    journeys
      .filter((journey) => journey.capabilities.includes('watch'))
      .map((journey) => journey.id),
    [
      'http',
      'custom-system',
      'dhis2-tracker',
      'fhir-r4-coverage-active',
      'opencrvs-dci',
      'opencrvs-events-api',
      'opencrvs-country-variant',
      'openspp-exact',
      'snapshot',
      'snapshot-with-records',
      'spreadsheet',
    ],
  );
});

test('keeps country, snapshot-records, OpenSPP, and conformance decisions explicit', async () => {
  const journeys = await buildProjectAuthoringJourneyMatrix(repoRoot);
  const byId = Object.fromEntries(journeys.map((journey) => [journey.id, journey]));

  assert.deepEqual(
    {
      integration: byId['opencrvs-country-variant'].integration,
      fixture: byId['opencrvs-country-variant'].fixture,
      source: byId['opencrvs-country-variant'].source,
    },
    {
      integration: 'birth-record',
      fixture: 'provincial-birth-match',
      source:
        'crates/registryctl/tests/fixtures/project-authoring/opencrvs-country-variant',
    },
  );
  assert.deepEqual(
    {
      integration: byId['snapshot-with-records'].integration,
      fixture: byId['snapshot-with-records'].fixture,
      source: byId['snapshot-with-records'].source,
    },
    {
      integration: 'person-snapshot',
      fixture: 'snapshot-match',
      source: 'crates/registryctl/tests/fixtures/project-authoring/snapshot-with-records',
    },
  );
  assert.equal(byId['openspp-exact'].evidence, 'offline-fixture-validation');
  assert.equal(byId['dhis2-script'].classification, 'conformance-only');
  assert.equal(byId['dhis2-script'].starter, undefined);
  assert.deepEqual(byId['dhis2-script'].capabilities, ['test', 'check', 'build']);
  assert.equal(byId['nia-attribute-release'].focus, 'solmara');
  assert.equal(byId['nia-attribute-release'].starter, undefined);
});

test('rejects unsafe catalog-derived command arguments before generation', async () => {
  await withIsolatedProjectCatalog(async ({ root, catalog, catalogPath }) => {
    const workspace = catalog.workspaces.find((candidate) => candidate.id === 'http');
    for (const { field, value, error } of [
      {
        field: 'project_dir',
        value: 'registry-project --live',
        error: /http project_dir must be a safe relative project path/,
      },
      {
        field: 'project_dir',
        value: 'registry-project/../escape',
        error: /http project_dir must be a safe relative project path/,
      },
      {
        field: 'project_dir',
        value: 'registry-project;touch-pwned',
        error: /http project_dir must be a safe relative project path/,
      },
      {
        field: 'project_dir',
        value: '/tmp/registry-project',
        error: /http project_dir must be a safe relative project path/,
      },
      {
        field: 'project_dir',
        value: '--registry-project',
        error: /http project_dir must be a safe relative project path/,
      },
      {
        field: 'starter',
        value: '--help',
        error: /http starter must be a safe CLI token/,
      },
      {
        field: 'environment',
        value: 'local$(touch-pwned)',
        error: /http environment must be a safe CLI token/,
      },
    ]) {
      const original = workspace[field];
      workspace[field] = value;
      await writeFile(catalogPath, YAML.stringify(catalog));
      await assert.rejects(buildProjectAuthoringJourneyMatrix(root), error);
      workspace[field] = original;
    }
  });
});

test('rejects unsafe workspace and fixture command arguments before generation', async () => {
  await withIsolatedProjectCatalog(async ({ root, catalog }) => {
    const workspace = catalog.workspaces.find((candidate) => candidate.id === 'http');
    const projectPath = resolve(root, workspace.source, 'registry-stack.yaml');
    const projectText = await readFile(projectPath, 'utf8');
    const project = YAML.parse(projectText);
    const integrationReference = project.integrations['person-record'];

    for (const integration of ['--help', 'person-record;touch-pwned', '../person-record']) {
      project.integrations = { [integration]: integrationReference };
      await writeFile(projectPath, YAML.stringify(project));
      await assert.rejects(
        buildProjectAuthoringJourneyMatrix(root),
        /http integration id must be a safe CLI token/,
      );
    }
    await writeFile(projectPath, projectText);

    const fixturePath = resolve(
      root,
      workspace.source,
      dirname(integrationReference.file),
      'fixtures',
      workspace.focused_fixture_file,
    );
    const fixtureText = await readFile(fixturePath, 'utf8');
    const fixture = YAML.parse(fixtureText);
    for (const name of ['active-person --watch', 'active-person;touch-pwned', '../active-person']) {
      fixture.name = name;
      await writeFile(fixturePath, YAML.stringify(fixture));
      await assert.rejects(
        buildProjectAuthoringJourneyMatrix(root),
        /http fixture name must be a safe CLI token/,
      );
    }
  });
});

test('does not publish legacy fixture starter markers as templates', async () => {
  await withIsolatedProjectCatalog(async ({ root, catalog, catalogPath }) => {
    const fhir = catalog.workspaces.find((workspace) => workspace.starter === 'fhir-r4');
    fhir.starter = 'http';
    await writeFile(catalogPath, YAML.stringify(catalog));

    const starters = await buildProjectStarterMatrix(root);
    assert.deepEqual(
      starters.map(({ starter }) => starter),
      ['spreadsheet', 'http'],
    );
  });
});

test('keeps generated template commands on the 1.0 command hierarchy', async () => {
  const starters = await buildProjectStarterMatrix(repoRoot);
  const commands = starters.flatMap(({ commands }) => commands).join('\n');
  assert.doesNotMatch(
    commands,
    /registryctl (?:authoring|project|compare|start|stop|restart|status|open|smoke|logs|preflight|capabilities)\b/,
  );
  assert.doesNotMatch(commands, /registryctl init --from/);
  assert.match(commands, /registryctl -C http-project tooling editor/);
  assert.match(commands, /registryctl -C http-project dev smoke/);
  assert.match(commands, /registryctl init spreadsheet-project --template spreadsheet/);
  assert.match(commands, /registryctl -C spreadsheet-project dev smoke/);
});
