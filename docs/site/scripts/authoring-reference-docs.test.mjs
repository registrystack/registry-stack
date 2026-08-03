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
  assert.equal(reference.fields.length, 1155);
  assert.equal(coverage.reviewed_intent_assignment_required_count, 1155);
  assert.equal(coverage.reviewed_intent_assignment_covered_count, 1155);
  assert.equal(coverage.distinct_reviewed_intent_count, 490);
  assert.equal(coverage.distinct_reviewed_intents_reused_count, 62);
  assert.equal(coverage.reviewed_intent_assignments_using_reused_intent_count, 727);
  assert.deepEqual(reference.reference_baseline, {
    generator_lifecycle: 'unreleased',
    published_release: null,
    field_history_status: 'not_verified',
    history_verification_method: null,
    compared_releases: [],
  });
  assert.ok(
    reference.fields.every(
      (field) =>
        field.history_status === 'not_verified' &&
        field.introduced_in === null &&
        field.version_history.length === 0 &&
        !Object.hasOwn(field.default, 'source_version'),
    ),
    'unverified release history must remain explicit and cannot contain a fabricated version',
  );
  assert.deepEqual(reference.coverage.by_schema, {
    project: 191,
    environment: 126,
    integration: 171,
    fixture: 39,
    entity: 35,
    relay: 593,
  });
  assert.deepEqual(reference.coverage.by_path_kind, {
    root: 6,
    property: 903,
    map_key: 22,
    map_value: 34,
    array_item: 102,
    branch: 88,
  });
  assert.equal(
    Object.values(reference.coverage.by_intent_profile).reduce(
      (total, count) => total + count,
      0,
    ),
    593,
  );
  assert.equal(reference.fields.filter((field) => field.empty_behavior === 'allowed').length, 260);
  assert.equal(reference.fields.filter((field) => field.empty_behavior === 'rejected').length, 259);
  assert.equal(
    reference.fields.filter((field) => field.empty_behavior === 'not_applicable').length,
    636,
  );
});

test('generated reference publishes field-specific byte defaults and ceilings', async () => {
  const reference = await readJson('src/data/generated/configuration-reference.json');
  const field = (pointer) =>
    reference.fields.find(
      (candidate) =>
        candidate.address.schema === 'integration' && candidate.address.pointer === pointer,
    );
  const constraint = (pointer, keyword) =>
    field(pointer).constraints.find((candidate) => candidate.keyword === keyword)?.value;

  assert.equal(
    field('/$defs/source/properties/response/properties/max_bytes').default.schema_value,
    '512KiB',
  );
  assert.equal(
    field('/$defs/limits/properties/request_bytes').default.schema_value,
    '64KiB',
  );
  assert.equal(
    field('/$defs/limits/properties/source_bytes').default.schema_value,
    '2MiB',
  );
  assert.equal(constraint('/$defs/integrationResponseByteSize/oneOf/0', 'maximum'), 8388608);
  assert.equal(constraint('/$defs/integrationRequestByteSize/oneOf/0', 'maximum'), 1048576);
  assert.equal(constraint('/$defs/integrationSourceByteSize/oneOf/0', 'maximum'), 16777216);
  assert.equal(
    constraint('/$defs/input/properties/maxLength', 'maximum'),
    1024,
  );
});

test('Script tutorial deadline matches the generated authoring authority', async () => {
  const [reference, tutorial] = await Promise.all([
    readJson('src/data/generated/configuration-reference.json'),
    readFile(
      resolve(siteRoot, 'src/content/docs/tutorials/configure-project-script-adapter.mdx'),
      'utf8',
    ),
  ]);
  const deadline = reference.fields.find(
    (field) =>
      field.address.schema === 'integration' &&
      field.address.pointer === '/$defs/limits/properties/deadline',
  );
  assert.ok(deadline, 'generated reference contains the integration deadline');
  const pattern = deadline.constraints.find((constraint) => constraint.keyword === 'pattern')?.value;
  assert.equal(typeof pattern, 'string');
  const authority = new RegExp(pattern);
  assert.equal(authority.test('20s'), true);
  assert.equal(authority.test('21s'), false);
  assert.equal(authority.test('60s'), false);
  assert.match(tutorial, /hard\s+ceilings[^.]*20 seconds\./s);
  assert.doesNotMatch(tutorial, /hard\s+ceilings[^.]*60 seconds\./s);
});

test('published reference page identifies generated sources and the no-country-value boundary', async () => {
  const [page, component, packageJson] = await Promise.all([
    readFile(resolve(siteRoot, 'src/content/docs/reference/project-configuration.mdx'), 'utf8'),
    readFile(resolve(siteRoot, 'src/components/AuthoringConfigurationReference.astro'), 'utf8'),
    readJson('package.json'),
  ]);

  assert.match(page, /Generator: `registryctl tooling reference configuration`/);
  assert.match(
    page,
    /Coverage gate: `registryctl tooling reference configuration --coverage`/,
  );
  assert.match(page, /Country workspace or runtime configuration reads: none/);
  assert.match(page, /Relay runtime schema/);
  assert.match(page, /does not inspect a project, live runtime configuration, environment variables/);
  assert.match(page, /five project-authoring sections describe configuration people commit/);
  assert.match(page, /intent sidecar is documentation knowledge\s+only/);
  assert.match(page, /Field release history: not verified/);
  assert.match(page, /Assignment coverage does not claim that every path has unique prose/);
  assert.match(component, /configuration-reference-coverage\.json/);
  assert.match(component, /generated\/configuration-reference\.v1\.json/);
  assert.match(component, /Reviewed intent profile/);
  assert.match(component, /JSON Schema pointer/);
  assert.match(component, /human-authored country\s+files/);
  assert.match(component, /not runtime configuration/);
  assert.match(component, /Reviewed intent assignments/);
  assert.match(component, /Distinct reviewed intents/);
  assert.match(component, /Release history/);
  assert.match(component, /Not verified/);
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
      [
        'run',
        '--locked',
        '--quiet',
        '-p',
        'registryctl',
        '--',
        'tooling',
        'reference',
        'configuration',
      ],
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
        'tooling',
        'reference',
        'configuration',
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
  assert.match(committedReference, /"schema_value": "512KiB"/);
  assert.match(committedReference, /"value": 16777216/);
});
