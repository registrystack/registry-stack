import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

import {
  buildAuthoringReference,
  generateAuthoringReference,
  validateAuthoringReference,
} from './generate-authoring-reference.mjs';

const schemas = ['project', 'environment', 'integration', 'fixture', 'entity', 'relay', 'notary'];
const sourceContract = {
  schemas,
  schema_sources: [
    'project.schema.json',
    'environment.schema.json',
    'integration.schema.json',
    'fixture.schema.json',
    'entity.schema.json',
    'registry-relay.config.schema.json',
    'registry-notary.config.schema.json',
  ],
  field_knowledge: 'schemas/project-authoring/parity-coverage.json#field_knowledge',
  human_intent: 'schemas/project-authoring/documentation-intent.json',
  runtime_intent: [
    'crates/registry-relay/config/documentation-intent.json',
    'crates/registry-notary-core/config/documentation-intent.json',
  ],
  reads_country_workspaces: false,
  reads_runtime_configuration: false,
};
const counts = {
  schema_count: 7,
  path_count: 7,
  reference_count: 0,
  by_schema: Object.fromEntries(schemas.map((schema) => [schema, 1])),
  by_path_kind: {
    root: 7,
    property: 0,
    map_key: 0,
    map_value: 0,
    array_item: 0,
    branch: 0,
  },
  by_sensitivity: {
    structural: 7,
  },
  by_intent_source: {
    schema_description: 7,
  },
  by_intent_profile: {},
};

function fixtureData() {
  const coverage = {
    schema_id:
      'https://id.registrystack.org/schemas/registryctl/project-documentation/registry.project.configuration_reference_coverage.v1.schema.json',
    format_version: '1.0',
    status: 'complete',
    source_contract: sourceContract,
    coverage: counts,
    prose_required_count: 7,
    prose_covered_count: 7,
    missing_intent: [],
  };
  const reference = {
    schema_id:
      'https://id.registrystack.org/schemas/registryctl/project-documentation/registry.project.configuration_reference.v1.schema.json',
    format_version: '1.0',
    source_contract: sourceContract,
    coverage: counts,
    fields: schemas.map((schema) => ({
      address: {
        schema,
        pointer: '',
        ...(schema === 'relay' || schema === 'notary' ? { key_path: '' } : {}),
        path_kind: 'root',
      },
      purpose: `Documents the reviewed ${schema} configuration contract root and its exact operational intent.`,
      ...(schema === 'relay' || schema === 'notary'
        ? { intent_profile: `${schema}_runtime_root` }
        : {}),
      default: { behavior: 'not_applicable' },
      example: { contains_country_values: false },
    })),
  };
  reference.coverage.by_intent_profile = {
    relay_runtime_root: 1,
    notary_runtime_root: 1,
  };
  coverage.coverage.by_intent_profile = reference.coverage.by_intent_profile;
  return { reference, coverage };
}

function fixtureExecutor(data) {
  return async (_repoRoot, args) =>
    `${JSON.stringify(args.includes('--coverage') ? data.coverage : data.reference)}\n`;
}

test('accepts one complete, value-safe field reference per covered configuration path', async () => {
  const data = fixtureData();
  const built = await buildAuthoringReference('/unused', fixtureExecutor(data));

  assert.deepEqual(built, data);
  assert.doesNotThrow(() => validateAuthoringReference(data.reference, data.coverage));
});

test('publishes identical internal and raw public artifacts only after validation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'registry-doc-reference-'));
  try {
    const data = fixtureData();
    const exactUint64Maximum = '18446744073709551615';
    data.reference.fields[0].constraints = [
      { keyword: 'maximum', value: exactUint64Maximum },
    ];
    const execute = async (_repoRoot, args) => {
      if (args.includes('--coverage')) return `${JSON.stringify(data.coverage)}\n`;
      return `${JSON.stringify(data.reference).replace(
        `"${exactUint64Maximum}"`,
        exactUint64Maximum,
      )}\n`;
    };
    await generateAuthoringReference(root, '/unused', execute);

    for (const [internal, raw] of [
      [
        'src/data/generated/configuration-reference.json',
        'public/generated/configuration-reference.v1.json',
      ],
      [
        'src/data/generated/configuration-reference-coverage.json',
        'public/generated/configuration-reference-coverage.v1.json',
      ],
    ]) {
      assert.equal(
        await readFile(resolve(root, internal), 'utf8'),
        await readFile(resolve(root, raw), 'utf8'),
      );
    }
    assert.match(
      await readFile(
        resolve(root, 'src/data/generated/configuration-reference.json'),
        'utf8',
      ),
      /"maximum","value":18446744073709551615/,
      'publication preserves integers larger than the JavaScript safe-integer range as opaque CLI JSON',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('fails closed on incomplete prose coverage before requesting the reference', async () => {
  const data = fixtureData();
  data.coverage.status = 'incomplete';
  data.coverage.prose_covered_count = 4;
  data.coverage.missing_intent = [
    { schema: 'project', pointer: '/properties/version', path_kind: 'property' },
  ];
  const calls = [];
  const execute = async (_repoRoot, args) => {
    calls.push(args);
    if (args.includes('--coverage')) return JSON.stringify(data.coverage);
    throw new Error('reference command must not run');
  };

  await assert.rejects(
    buildAuthoringReference('/unused', execute),
    /coverage is incomplete \(1 missing intents\)/,
  );
  assert.deepEqual(calls, [['authoring', 'reference', '--coverage']]);
});

test('rejects duplicated paths and country-value-bearing example metadata', () => {
  const data = fixtureData();
  data.reference.fields[1].address = data.reference.fields[0].address;
  assert.throws(
    () => validateAuthoringReference(data.reference, data.coverage),
    /repeats project#/,
  );

  const unsafe = fixtureData();
  unsafe.reference.fields[0].example.contains_country_values = true;
  assert.throws(
    () => validateAuthoringReference(unsafe.reference, unsafe.coverage),
    /lacks reviewed, safe intent/,
  );
});

test('rejects runtime paths without exact profiles or with exposed default values', () => {
  const missingProfile = fixtureData();
  delete missingProfile.reference.fields.find(
    (field) => field.address.schema === 'relay',
  ).intent_profile;
  assert.throws(
    () => validateAuthoringReference(missingProfile.reference, missingProfile.coverage),
    /must have an exact product-owned runtime intent profile/,
  );

  const exposedDefault = fixtureData();
  exposedDefault.reference.fields.find(
    (field) => field.address.schema === 'notary',
  ).default.schema_value = 'COUNTRY_VALUE_SENTINEL';
  assert.throws(
    () => validateAuthoringReference(exposedDefault.reference, exposedDefault.coverage),
    /exposes a runtime default value/,
  );
});

test('keeps JSON Schema pointers distinct from runtime configuration key paths', () => {
  const missingKeyPath = fixtureData();
  delete missingKeyPath.reference.fields.find(
    (field) => field.address.schema === 'relay',
  ).address.key_path;
  assert.throws(
    () => validateAuthoringReference(missingKeyPath.reference, missingKeyPath.coverage),
    /has an invalid address/,
  );

  const authoredKeyPath = fixtureData();
  authoredKeyPath.reference.fields.find(
    (field) => field.address.schema === 'project',
  ).address.key_path = 'project';
  assert.throws(
    () => validateAuthoringReference(authoredKeyPath.reference, authoredKeyPath.coverage),
    /has an invalid address/,
  );

  const dottedPointer = fixtureData();
  dottedPointer.reference.fields.find(
    (field) => field.address.schema === 'notary',
  ).address.pointer = 'auth.api_keys[]';
  assert.throws(
    () => validateAuthoringReference(dottedPointer.reference, dottedPointer.coverage),
    /has an invalid address/,
  );
});

test('rejects mismatched or unrecognized source provenance', () => {
  const mismatched = fixtureData();
  mismatched.reference.source_contract = {
    ...mismatched.reference.source_contract,
    human_intent: 'schemas/project-authoring/unreviewed-intent.json',
  };
  assert.throws(
    () => validateAuthoringReference(mismatched.reference, mismatched.coverage),
    /exact committed authoring-reference sources/,
  );

  const divergent = fixtureData();
  divergent.reference.source_contract = {
    ...divergent.reference.source_contract,
    reads_runtime_configuration: true,
  };
  assert.throws(
    () => validateAuthoringReference(divergent.reference, divergent.coverage),
    /must prohibit country-workspace and runtime-configuration reads/,
  );
});
