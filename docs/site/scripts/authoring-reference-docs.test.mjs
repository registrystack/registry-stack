import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

import { validateAuthoringReference } from './generate-authoring-reference.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const repoRoot = resolve(siteRoot, '../..');
const execFileAsync = promisify(execFile);

async function readJson(relative) {
  return JSON.parse(await readFile(resolve(siteRoot, relative), 'utf8'));
}

test('committed internal and public reference artifacts are exact and complete', async () => {
  const [reference, coverage, publicReference, publicCoverage] = await Promise.all([
    readJson('src/data/generated/configuration-reference.json'),
    readJson('src/data/generated/configuration-reference-coverage.json'),
    readJson('public/generated/configuration-reference.v1.json'),
    readJson('public/generated/configuration-reference-coverage.v1.json'),
  ]);

  validateAuthoringReference(reference, coverage);
  assert.deepEqual(publicReference, reference);
  assert.deepEqual(publicCoverage, coverage);
  assert.equal(reference.fields.length, 1677);
  assert.deepEqual(reference.coverage.by_schema, {
    project: 160,
    environment: 191,
    integration: 138,
    fixture: 40,
    entity: 35,
    relay: 584,
    notary: 529,
  });
  assert.deepEqual(reference.coverage.by_path_kind, {
    root: 7,
    property: 1339,
    map_key: 23,
    map_value: 44,
    array_item: 172,
    branch: 92,
  });
  assert.equal(
    Object.values(reference.coverage.by_intent_profile).reduce(
      (total, count) => total + count,
      0,
    ),
    1113,
  );
});

test('published reference page identifies generated sources and the no-country-value boundary', async () => {
  const [page, component, packageJson] = await Promise.all([
    readFile(resolve(siteRoot, 'src/content/docs/reference/project-configuration.mdx'), 'utf8'),
    readFile(resolve(siteRoot, 'src/components/AuthoringConfigurationReference.astro'), 'utf8'),
    readJson('package.json'),
  ]);

  assert.match(page, /Generator: `registryctl authoring reference`/);
  assert.match(page, /Coverage gate: `registryctl authoring reference --coverage`/);
  assert.match(page, /Country workspace or runtime configuration reads: none/);
  assert.match(page, /Relay and Notary runtime schemas/);
  assert.match(page, /does not inspect a project, live runtime configuration, environment variables/);
  assert.match(page, /five project-authoring sections describe configuration people commit/);
  assert.match(page, /intent sidecars are documentation knowledge\s+only/);
  assert.match(component, /configuration-reference-coverage\.json/);
  assert.match(component, /generated\/configuration-reference\.v1\.json/);
  assert.match(component, /Reviewed intent profile/);
  assert.match(component, /JSON Schema pointer/);
  assert.match(component, /human-authored country\s+files/);
  assert.match(component, /not runtime configuration/);
  assert.match(packageJson.scripts.generate, /generate-authoring-reference\.mjs/);
});

test('committed reference and coverage are byte-exact to the CLI', async () => {
  const [
    { stdout: referenceStdout },
    { stdout: coverageStdout },
    committedReference,
    publicReference,
    committedCoverage,
    publicCoverage,
  ] = await Promise.all([
    execFileAsync(
      'cargo',
      ['run', '--locked', '--quiet', '-p', 'registryctl', '--', 'authoring', 'reference'],
      {
        cwd: repoRoot,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      },
    ),
    execFileAsync(
      'cargo',
      [
        'run',
        '--locked',
        '--quiet',
        '-p',
        'registryctl',
        '--',
        'authoring',
        'reference',
        '--coverage',
      ],
      {
        cwd: repoRoot,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      },
    ),
    readFile(resolve(siteRoot, 'src/data/generated/configuration-reference.json'), 'utf8'),
    readFile(resolve(siteRoot, 'public/generated/configuration-reference.v1.json'), 'utf8'),
    readFile(
      resolve(siteRoot, 'src/data/generated/configuration-reference-coverage.json'),
      'utf8',
    ),
    readFile(
      resolve(siteRoot, 'public/generated/configuration-reference-coverage.v1.json'),
      'utf8',
    ),
  ]);

  assert.equal(committedReference, referenceStdout);
  assert.equal(publicReference, referenceStdout);
  assert.equal(committedCoverage, coverageStdout);
  assert.equal(publicCoverage, coverageStdout);
  assert.match(committedReference, /"value": 18446744073709551615/);
});
