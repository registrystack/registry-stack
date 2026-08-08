import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import {
  CONTRACTS,
  buildEvidenceConfiguration,
  collectFields,
  generateEvidenceConfiguration,
  validateEvidenceConfiguration,
} from './generate-evidence-configuration.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '../../..');
const docsRoot = resolve(scriptDir, '..');

const pathsOf = (fields) => fields.map((field) => field.key_path);

test('nested properties become dotted key paths carrying their required flag', () => {
  const fields = collectFields({
    type: 'object',
    required: ['listener'],
    properties: {
      listener: {
        type: 'object',
        required: ['port'],
        properties: { port: { type: 'integer' }, label: { type: 'string' } },
      },
    },
  });
  assert.deepEqual(pathsOf(fields), ['listener', 'listener.label', 'listener.port']);
  assert.deepEqual(
    fields.map((field) => [field.key_path, field.required]),
    [
      ['listener', true],
      ['listener.label', false],
      ['listener.port', true],
    ],
  );
});

test('array items and map values use the bracket and star notation', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      requirements: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' } } } },
      sources: {
        type: 'object',
        additionalProperties: { type: 'object', properties: { origin: { type: 'string' } } },
      },
    },
  });
  assert.deepEqual(pathsOf(fields), [
    'requirements',
    'requirements[]',
    'requirements[].id',
    'sources',
    'sources.*',
    'sources.*.origin',
  ]);
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.equal(byPath.get('requirements[]').kind, 'array_item');
  assert.equal(byPath.get('sources.*').kind, 'map_value');
  assert.equal(byPath.get('sources.*.origin').kind, 'property');
});

test('a closed object contributes no map-value entry', () => {
  const fields = collectFields({
    type: 'object',
    additionalProperties: false,
    properties: { version: { const: 1 } },
  });
  assert.deepEqual(pathsOf(fields), ['version']);
});

test('local references are resolved in place', () => {
  const fields = collectFields({
    type: 'object',
    properties: { path: { $ref: '#/$defs/absolute-path' } },
    $defs: { 'absolute-path': { type: 'string', minLength: 1 } },
  });
  assert.deepEqual(pathsOf(fields), ['path']);
  assert.equal(fields[0].type, 'string');
});

test('a recursive definition is recorded once, at the point it re-enters itself', () => {
  const fields = collectFields({
    type: 'object',
    properties: { node: { $ref: '#/$defs/node' } },
    $defs: {
      node: {
        type: 'object',
        properties: { name: { type: 'string' }, child: { $ref: '#/$defs/node' } },
      },
    },
  });
  assert.deepEqual(pathsOf(fields), ['node', 'node.child', 'node.name']);
});

test('an unresolvable reference is an error rather than a silently missing field', () => {
  assert.throws(
    () => collectFields({ type: 'object', properties: { a: { $ref: '#/$defs/missing' } } }),
    /unresolved schema reference/,
  );
});

test('combinator branches merge into one entry per key path', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      signer: {
        oneOf: [
          { type: 'object', required: ['kind'], properties: { kind: { const: 'file' }, ref: { type: 'string' } } },
          { type: 'object', required: ['kind'], properties: { kind: { const: 'env' } } },
        ],
      },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.deepEqual(pathsOf(fields), ['signer', 'signer.kind', 'signer.ref']);
  assert.deepEqual(byPath.get('signer.kind').values, ['env', 'file']);
  // `ref` is required in neither branch, `kind` in both.
  assert.equal(byPath.get('signer.kind').required, true);
  assert.equal(byPath.get('signer.ref').required, false);
});

test('fixed values and validation keywords are carried onto the entry', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      port: { type: 'integer', minimum: 1, maximum: 65535 },
      mode: { enum: ['strict', 'lenient'] },
      version: { const: 1 },
      host: {
        type: 'string',
        minLength: 2,
        description: 'Loopback or private address.',
        'x-runtime-validation': 'Parsed as an IP address.',
      },
    },
  });
  const byPath = new Map(fields.map((field) => [field.key_path, field]));
  assert.deepEqual(byPath.get('port').constraints, ['maximum: 65535', 'minimum: 1']);
  assert.deepEqual(byPath.get('mode').values, ['lenient', 'strict']);
  assert.deepEqual(byPath.get('version').values, ['1']);
  assert.equal(byPath.get('host').description, 'Loopback or private address.');
  assert.equal(byPath.get('host').runtime_validation, 'Parsed as an IP address.');
  assert.equal(byPath.get('port').description, null);
});

test('validation rejects a document with repeated or missing key paths', () => {
  const entry = (key_path) => ({
    key_path,
    kind: 'property',
    type: 'string',
    required: false,
    values: null,
    constraints: [],
    description: null,
    runtime_validation: null,
  });
  const document = (fields) => ({
    format_version: '1.0',
    generator: 'npm run generate',
    contracts: CONTRACTS.map((contract, index) => {
      const entries = index === 0 ? fields : [entry('b')];
      return { ...contract, field_count: entries.length, fields: entries };
    }),
  });
  assert.throws(() => validateEvidenceConfiguration(document([entry('a'), entry('a')])), /repeats/);
  assert.throws(() => validateEvidenceConfiguration(document([])), /at least one/);
  const good = document([entry('a')]);
  assert.doesNotThrow(() => validateEvidenceConfiguration(good));
  good.contracts[0].field_count = 5;
  assert.throws(() => validateEvidenceConfiguration(good), /field_count/);
});

test('the committed contracts produce a valid reference for both configuration files', async () => {
  const document = await buildEvidenceConfiguration(repoRoot);
  validateEvidenceConfiguration(document);
  assert.deepEqual(
    document.contracts.map((contract) => contract.id),
    CONTRACTS.map((contract) => contract.id),
  );
  for (const contract of document.contracts) {
    assert.ok(contract.fields.length > 0, `${contract.id} produced no fields`);
  }
});

test('the rendered key paths match the ones CONFIG.md documents', async () => {
  // `products/evidence/scripts/check-config-key-paths.sh` owns the CONFIG.md
  // blocks. Comparing against them keeps this walk and that one from drifting
  // apart without either side going quiet.
  const reference = await readFile(
    resolve(repoRoot, 'products/evidence/reference/request-adapter/deployment-projects/CONFIG.md'),
    'utf8',
  );
  const documented = (marker) => {
    const body = reference.split(`<!-- ${marker}:start -->`)[1].split(`<!-- ${marker}:end -->`)[0];
    return body
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('```'));
  };

  const document = await buildEvidenceConfiguration(repoRoot);
  for (const contract of document.contracts) {
    const expected = documented(contract.marker);
    assert.deepEqual(pathsOf(contract.fields), expected, `${contract.id} key paths drifted`);
  }
});

test('generating writes the reference where the page reads it', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'evidence-configuration-'));
  try {
    await generateEvidenceConfiguration(scratch, repoRoot);
    const written = JSON.parse(
      await readFile(join(scratch, 'src/data/generated/evidence-configuration.json'), 'utf8'),
    );
    validateEvidenceConfiguration(written);
    const committed = JSON.parse(
      await readFile(join(docsRoot, 'src/data/generated/evidence-configuration.json'), 'utf8'),
    );
    assert.deepEqual(written, committed, 'the committed reference is stale; run npm run generate');
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});
