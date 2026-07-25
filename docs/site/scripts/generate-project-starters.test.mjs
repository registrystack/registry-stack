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
    for (const source of new Set(catalog.workspaces.map((workspace) => workspace.source))) {
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

  assert.equal(journeys.length, 14);
  assert.deepEqual(
    journeys.map(({ id, classification, topology }) => ({ id, classification, topology })),
    [
      { id: 'http', classification: 'maintained', topology: 'combined' },
      { id: 'custom-system', classification: 'maintained', topology: 'combined' },
      { id: 'dhis2-script', classification: 'conformance-only', topology: 'combined' },
      { id: 'dhis2-tracker', classification: 'maintained', topology: 'combined' },
      { id: 'fhir-r4-coverage-active', classification: 'maintained', topology: 'combined' },
      { id: 'nia-attribute-release', classification: 'conformance-only', topology: 'relay-only' },
      { id: 'opencrvs-dci', classification: 'maintained', topology: 'combined' },
      { id: 'opencrvs-country-variant', classification: 'maintained', topology: 'combined' },
      { id: 'openspp-exact', classification: 'maintained', topology: 'combined' },
      { id: 'relay-only-materialization', classification: 'maintained', topology: 'relay-only' },
      { id: 'relay-only-records', classification: 'maintained', topology: 'relay-only' },
      { id: 'snapshot', classification: 'maintained', topology: 'combined' },
      { id: 'snapshot-with-records', classification: 'maintained', topology: 'combined' },
      { id: 'notary-only-evaluation', classification: 'maintained', topology: 'notary-only' },
    ],
  );
});

test('derives all advertised starter selections from committed workspaces', async () => {
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

test('emits one canonical seven-command sequence for exactly five starters', async () => {
  const starters = await buildProjectStarterMatrix(repoRoot);

  assert.equal(starters.length, 5);
  for (const starter of starters) {
    assert.deepEqual(starter.capabilities, [
      'init',
      'editor',
      'trace',
      'watch',
      'test',
      'check',
      'build',
    ]);
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

test('non-starters never emit init and supported steps follow fixture maintenance status', async () => {
  const journeys = await buildProjectAuthoringJourneyMatrix(repoRoot);
  const nonStarters = journeys.filter((journey) => !journey.starter);
  assert.equal(nonStarters.length, 9);
  for (const journey of nonStarters) {
    assert.equal(journey.commands.some((command) => command.includes(' init --from ')), false);
    assert.equal(journey.project_dir, journey.source);
    assert.equal(
      journey.commands.every((command) => command.includes(`--project-dir ${journey.source}`)),
      true,
    );
  }

  for (const id of [
    'nia-attribute-release',
    'relay-only-materialization',
    'relay-only-records',
    'notary-only-evaluation',
  ]) {
    const journey = journeys.find((candidate) => candidate.id === id);
    assert.deepEqual(journey.capabilities, ['check', 'build']);
    assert.deepEqual(journey.commands, [
      `registryctl check --project-dir ${journey.project_dir} --environment local --explain`,
      `registryctl build --project-dir ${journey.project_dir} --environment local`,
    ]);
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
      'opencrvs-country-variant',
      'openspp-exact',
      'snapshot',
      'snapshot-with-records',
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
  assert.equal(byId['openspp-exact'].evidence, 'offline-fixture-only-pending-357');
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

test('rejects duplicate starter entries instead of collapsing them', async () => {
  await withIsolatedProjectCatalog(async ({ root, catalog, catalogPath }) => {
    const fhir = catalog.workspaces.find((workspace) => workspace.starter === 'fhir-r4');
    fhir.starter = 'http';
    await writeFile(catalogPath, YAML.stringify(catalog));

    await assert.rejects(
      buildProjectAuthoringJourneyMatrix(root),
      /public starter catalog contains a duplicate starter/,
    );
  });
});

test('rejects a catalog with fewer than five starter entries', async () => {
  await withIsolatedProjectCatalog(async ({ root, catalog, catalogPath }) => {
    const fhir = catalog.workspaces.find((workspace) => workspace.starter === 'fhir-r4');
    delete fhir.starter;
    fhir.steps = fhir.steps.filter((step) => step !== 'init');
    await writeFile(catalogPath, YAML.stringify(catalog));

    await assert.rejects(
      buildProjectAuthoringJourneyMatrix(root),
      /public starter catalog must contain exactly 5 entries/,
    );
  });
});

test('publishes the authoring tutorial with the catalog-backed HTTP command sequence', async () => {
  const [starters, tutorial, astroConfig] = await Promise.all([
    buildProjectStarterMatrix(repoRoot),
    readFile(
      resolve(repoRoot, 'docs/site/src/content/docs/tutorials/author-registry-project.mdx'),
      'utf8',
    ),
    readFile(resolve(repoRoot, 'docs/site/astro.config.mjs'), 'utf8'),
  ]);
  const normalizedTutorial = tutorial.replaceAll(/\\\n\s*/g, '').replaceAll(/\s+/g, ' ');
  const http = starters.find((starter) => starter.starter === 'http');

  assert.match(tutorial, /^status: current$/m);
  assert.doesNotMatch(tutorial, /^draft: true$/m);
  for (const command of http.commands) {
    assert.equal(
      normalizedTutorial.includes(command),
      true,
      `authoring tutorial must document catalog command: ${command}`,
    );
  }
  assert.equal(
    astroConfig.match(/slug: 'tutorials\/author-registry-project'/g)?.length,
    1,
    'authoring tutorial has one author-path placement',
  );
  const integrations = astroConfig.slice(
    astroConfig.indexOf("label: 'Integrations'"),
    astroConfig.indexOf("label: 'Concepts'"),
  );
  assert.match(integrations, /slug: 'tutorials\/author-registry-project'/);
});
