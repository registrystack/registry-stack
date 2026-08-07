import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');
const sourceManifest = JSON.parse(
  readFileSync(new URL('./authoring-reference-sources.json', import.meta.url), 'utf8'),
);

const referenceSchemaId =
  'https://id.registrystack.org/schemas/registryctl/project-documentation/registry.project.configuration_reference.v1.schema.json';
const coverageSchemaId =
  'https://id.registrystack.org/schemas/registryctl/project-documentation/registry.project.configuration_reference_coverage.v1.schema.json';
const schemaOrder = sourceManifest.schema_order;
const schemaSources = sourceManifest.schema_sources;
const fieldKnowledgeSource = sourceManifest.field_knowledge;
const humanIntentSource = sourceManifest.human_intent;
const runtimeIntentSources = sourceManifest.runtime_intent;
const runtimeSchemas = new Set(sourceManifest.runtime_schemas);
const pathKinds = ['root', 'property', 'map_key', 'map_value', 'array_item', 'branch'];

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} did not emit JSON: ${error.message}`);
  }
}

async function executeRegistryctl(repoRoot, args) {
  try {
    const { stdout } = await execFileAsync(
      'cargo',
      ['run', '--locked', '--quiet', '-p', 'registryctl', '--', ...args],
      {
        cwd: repoRoot,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    return stdout;
  } catch (error) {
    const stdout = typeof error?.stdout === 'string' ? error.stdout.trim() : '';
    const stderr = typeof error?.stderr === 'string' ? error.stderr.trim() : '';
    const detail = stdout || stderr || error.message;
    throw new Error(`registryctl ${args.join(' ')} failed: ${detail}`);
  }
}

function assertInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
}

function assertSourceContract(source, label) {
  if (
    !source ||
    source.reads_country_workspaces !== false ||
    source.reads_runtime_configuration !== false
  ) {
    throw new Error(`${label} must prohibit country-workspace and runtime-configuration reads`);
  }
  if (JSON.stringify(source.schemas) !== JSON.stringify(schemaOrder)) {
    throw new Error(`${label} must cover the exact configuration domains in order`);
  }
  if (
    JSON.stringify(source.schema_sources) !== JSON.stringify(schemaSources) ||
    source.field_knowledge !== fieldKnowledgeSource ||
    source.human_intent !== humanIntentSource ||
    JSON.stringify(source.runtime_intent) !== JSON.stringify(runtimeIntentSources)
  ) {
    throw new Error(`${label} must identify the exact committed authoring-reference sources`);
  }
}

function assertReferenceBaseline(baseline, label) {
  if (
    !baseline ||
    baseline.generator_lifecycle !== 'unreleased' ||
    baseline.published_release !== null ||
    baseline.field_history_status !== 'not_verified' ||
    baseline.history_verification_method !== null ||
    !Array.isArray(baseline.compared_releases) ||
    baseline.compared_releases.length !== 0
  ) {
    throw new Error(
      `${label} must identify an unreleased generator with field history not verified`,
    );
  }
}

function assertCoverageShape(coverage, label) {
  if (!coverage || typeof coverage !== 'object') {
    throw new Error(`${label}.coverage must be an object`);
  }
  assertInteger(coverage.schema_count, `${label}.coverage.schema_count`);
  assertInteger(coverage.path_count, `${label}.coverage.path_count`);
  assertInteger(coverage.reference_count, `${label}.coverage.reference_count`);
  if (coverage.schema_count !== schemaOrder.length) {
    throw new Error(`${label} must cover every configuration schema`);
  }
  const schemaTotal = schemaOrder.reduce((total, schema) => {
    assertInteger(coverage.by_schema?.[schema], `${label}.coverage.by_schema.${schema}`);
    return total + coverage.by_schema[schema];
  }, 0);
  if (schemaTotal !== coverage.path_count) {
    throw new Error(`${label} schema counts do not add up to path_count`);
  }
  const pathKindTotal = pathKinds.reduce((total, kind) => {
    assertInteger(coverage.by_path_kind?.[kind], `${label}.coverage.by_path_kind.${kind}`);
    return total + coverage.by_path_kind[kind];
  }, 0);
  if (pathKindTotal !== coverage.path_count) {
    throw new Error(`${label} path-kind counts do not add up to path_count`);
  }
  const intentSourceEntries = Object.entries(coverage.by_intent_source ?? {});
  const intentSourceTotal = intentSourceEntries.reduce((total, [source, count]) => {
    assertInteger(count, `${label}.coverage.by_intent_source.${source}`);
    return total + count;
  }, 0);
  if (intentSourceTotal !== coverage.path_count) {
    throw new Error(`${label} intent-source counts do not add up to path_count`);
  }
  const intentProfileEntries = Object.entries(coverage.by_intent_profile ?? {});
  const intentProfileTotal = intentProfileEntries.reduce((total, [profile, count]) => {
    assertInteger(count, `${label}.coverage.by_intent_profile.${profile}`);
    return total + count;
  }, 0);
  const runtimePathCount = [...runtimeSchemas].reduce(
    (total, schema) => total + coverage.by_schema[schema],
    0,
  );
  if (intentProfileTotal !== runtimePathCount) {
    throw new Error(`${label} intent-profile counts do not cover every runtime path`);
  }
}

function fieldIdentity(field) {
  return `${field?.address?.schema ?? ''}#${field?.address?.pointer ?? ''}#${
    field?.address?.key_path ?? ''
  }`;
}

export function validateAuthoringReferenceCoverage(coverage) {
  if (coverage?.schema_id !== coverageSchemaId || coverage.format_version !== '1.0') {
    throw new Error('configuration-reference coverage uses an unsupported contract');
  }
  if (coverage.status !== 'complete') {
    const missing = Array.isArray(coverage.missing_intent) ? coverage.missing_intent.length : 'unknown';
    throw new Error(`configuration-reference coverage is incomplete (${missing} missing intents)`);
  }
  assertCoverageShape(coverage.coverage, 'coverage report');
  assertReferenceBaseline(coverage.reference_baseline, 'coverage report reference baseline');
  assertSourceContract(coverage.source_contract, 'coverage report source contract');
  for (const field of [
    'reviewed_intent_assignment_required_count',
    'reviewed_intent_assignment_covered_count',
    'distinct_reviewed_intent_count',
    'distinct_reviewed_intents_reused_count',
    'reviewed_intent_assignments_using_reused_intent_count',
  ]) {
    assertInteger(coverage[field], `coverage report.${field}`);
  }
  if (
    coverage.reviewed_intent_assignment_required_count !== coverage.coverage.path_count ||
    coverage.reviewed_intent_assignment_covered_count !== coverage.coverage.path_count ||
    coverage.distinct_reviewed_intent_count >
      coverage.reviewed_intent_assignment_covered_count ||
    coverage.distinct_reviewed_intents_reused_count >
      coverage.distinct_reviewed_intent_count ||
    coverage.reviewed_intent_assignments_using_reused_intent_count >
      coverage.reviewed_intent_assignment_covered_count ||
    (coverage.distinct_reviewed_intents_reused_count === 0) !==
      (coverage.reviewed_intent_assignments_using_reused_intent_count === 0) ||
    coverage.reviewed_intent_assignments_using_reused_intent_count <
      coverage.distinct_reviewed_intents_reused_count * 2 ||
    !Array.isArray(coverage.missing_intent) ||
    coverage.missing_intent.length !== 0
  ) {
    throw new Error(
      'configuration-reference reviewed-intent assignment coverage is not exhaustively consistent',
    );
  }
}

export function validateAuthoringReference(reference, coverage) {
  validateAuthoringReferenceCoverage(coverage);
  if (reference?.schema_id !== referenceSchemaId || reference.format_version !== '1.0') {
    throw new Error('configuration reference uses an unsupported contract');
  }
  assertCoverageShape(reference.coverage, 'configuration reference');
  assertReferenceBaseline(reference.reference_baseline, 'configuration reference baseline');
  assertSourceContract(reference.source_contract, 'configuration reference source contract');
  if (JSON.stringify(reference.reference_baseline) !== JSON.stringify(coverage.reference_baseline)) {
    throw new Error('configuration reference and coverage report baselines differ');
  }
  if (JSON.stringify(reference.source_contract) !== JSON.stringify(coverage.source_contract)) {
    throw new Error('configuration reference and coverage report provenance differ');
  }
  if (JSON.stringify(reference.coverage) !== JSON.stringify(coverage.coverage)) {
    throw new Error('configuration reference and coverage report counts differ');
  }
  if (
    !Array.isArray(reference.fields) ||
    reference.fields.length !== reference.coverage.path_count
  ) {
    throw new Error('configuration reference must contain one entry per covered path');
  }
  const identities = new Set();
  const intentCounts = new Map();
  for (const [index, field] of reference.fields.entries()) {
    const identity = fieldIdentity(field);
    const runtimeField = runtimeSchemas.has(field?.address?.schema);
    if (
      !schemaOrder.includes(field?.address?.schema) ||
      typeof field?.address?.pointer !== 'string' ||
      (field.address.pointer !== '' && !field.address.pointer.startsWith('/')) ||
      runtimeField !== (typeof field.address.key_path === 'string') ||
      !pathKinds.includes(field?.address?.path_kind)
    ) {
      throw new Error(`configuration reference field ${index} has an invalid address`);
    }
    if (identities.has(identity)) {
      throw new Error(`configuration reference repeats ${identity}`);
    }
    identities.add(identity);
    if (
      typeof field.purpose !== 'string' ||
      field.purpose.trim().length < 24 ||
      field.example?.contains_country_values !== false
    ) {
      throw new Error(`configuration reference field ${identity} lacks reviewed, safe intent`);
    }
    intentCounts.set(field.purpose, (intentCounts.get(field.purpose) ?? 0) + 1);
    if (
      field.history_status !== 'not_verified' ||
      field.introduced_in !== null ||
      !Array.isArray(field.version_history) ||
      field.version_history.length !== 0 ||
      Object.hasOwn(field.default ?? {}, 'source_version')
    ) {
      throw new Error(
        `configuration reference field ${identity} fabricates unverified release history`,
      );
    }
    if (
      runtimeField !==
      (typeof field.intent_profile === 'string' && field.intent_profile.trim().length > 0)
    ) {
      throw new Error(
        `configuration reference field ${identity} must have an exact product-owned runtime intent profile`,
      );
    }
    if (field.empty_behavior === 'allowed') {
      for (const constraint of field.constraints ?? []) {
        const falselyAllowsEmpty =
          (constraint.keyword === 'minLength' && constraint.value > 0) ||
          (constraint.keyword === 'pattern' &&
            typeof constraint.value === 'string' &&
            !new RegExp(constraint.value).test('')) ||
          (constraint.keyword === 'enum' &&
            Array.isArray(constraint.value) &&
            !constraint.value.includes('')) ||
          (constraint.keyword === 'const' && constraint.value !== '');
        if (falselyAllowsEmpty) {
          throw new Error(
            `configuration reference field ${identity} reports an allowed empty string rejected by ${constraint.keyword}`,
          );
        }
      }
    }
    if (runtimeField && Object.hasOwn(field.default ?? {}, 'schema_value')) {
      throw new Error(
        `configuration reference field ${identity} exposes a runtime default value`,
      );
    }
  }
  const reusedIntentCounts = [...intentCounts.values()].filter((count) => count > 1);
  if (
    coverage.distinct_reviewed_intent_count !== intentCounts.size ||
    coverage.distinct_reviewed_intents_reused_count !== reusedIntentCounts.length ||
    coverage.reviewed_intent_assignments_using_reused_intent_count !==
      reusedIntentCounts.reduce((total, count) => total + count, 0)
  ) {
    throw new Error(
      'configuration reference reviewed-intent reuse differs from the coverage report',
    );
  }
}

async function readAuthoringReference(
  repoRoot = defaultRepoRoot,
  execute = executeRegistryctl,
) {
  const coverageText = await execute(
    repoRoot,
    ['tooling', 'reference', 'configuration', '--coverage'],
  );
  const coverage = parseJson(
    coverageText,
    'registryctl tooling reference configuration --coverage',
  );
  validateAuthoringReferenceCoverage(coverage);
  const referenceText = await execute(
    repoRoot,
    ['tooling', 'reference', 'configuration'],
  );
  const reference = parseJson(
    referenceText,
    'registryctl tooling reference configuration',
  );
  validateAuthoringReference(reference, coverage);
  return { reference, coverage, referenceText, coverageText };
}

export async function buildAuthoringReference(
  repoRoot = defaultRepoRoot,
  execute = executeRegistryctl,
) {
  const { reference, coverage } = await readAuthoringReference(repoRoot, execute);
  return { reference, coverage };
}

async function publishJson(path, text) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, text.endsWith('\n') ? text : `${text}\n`, {
      encoding: 'utf8',
      flag: 'wx',
    });
    await rename(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function generateAuthoringReference(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
  execute = executeRegistryctl,
) {
  const { reference, referenceText, coverageText } = await readAuthoringReference(
    repoRoot,
    execute,
  );
  const destinations = [
    ['src/data/generated/configuration-reference.json', referenceText],
    ['src/data/generated/configuration-reference-coverage.json', coverageText],
    ['public/generated/configuration-reference.v1.json', referenceText],
    ['public/generated/configuration-reference-coverage.v1.json', coverageText],
  ];
  await Promise.all(
    destinations.map(([relative, text]) => publishJson(resolve(docsRoot, relative), text)),
  );
  console.log(
    `Generated authoring reference for ${reference.fields.length} paths across ${reference.coverage.schema_count} schemas.`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateAuthoringReference();
}
