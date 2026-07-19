import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import YAML from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const siteRoot = resolve(here, '..');
const repositoryRoot = resolve(siteRoot, '../..');
const specPath = resolve(siteRoot, 'src/content/docs/spec/rs-op-posture.mdx');
const schemaPath = resolve(
  repositoryRoot,
  'crates/registry-platform-ops/schemas/registry.ops.posture.v1.schema.json',
);
const relayExamplePath = resolve(
  repositoryRoot,
  'crates/registry-platform-ops/examples/registry-relay.posture.valid.json',
);
const notaryExamplePath = resolve(
  repositoryRoot,
  'crates/registry-platform-ops/examples/registry-notary.posture.valid.json',
);

function frontmatter(text) {
  const end = text.indexOf('\n---\n', 4);
  assert.notEqual(end, -1, 'expected complete YAML frontmatter');
  return YAML.parse(text.slice(4, end));
}

test('RS-OP-POSTURE has a stable formal-specification identifier', () => {
  const page = readFileSync(specPath, 'utf8');
  const data = frontmatter(page);

  assert.equal(data.doc_id, 'RS-OP-POSTURE');
  assert.equal(data.doc_type, 'specification');
  assert.equal(data.category, 'normative');
  assert.equal(data.evidence, 'verified');
});

test('RS-OP-POSTURE names the shipped Relay and Notary examples', () => {
  const page = readFileSync(specPath, 'utf8');
  const relayExample = JSON.parse(readFileSync(relayExamplePath, 'utf8'));
  const notaryExample = JSON.parse(readFileSync(notaryExamplePath, 'utf8'));

  assert.equal(relayExample.schema, 'registry.ops.posture.v1');
  assert.equal(relayExample.component, 'registry-relay');
  assert.equal(relayExample.tier, 'default');
  assert.equal(notaryExample.schema, 'registry.ops.posture.v1');
  assert.equal(notaryExample.component, 'registry-notary');
  assert.equal(notaryExample.tier, 'default');
  assert.match(page, /registry-relay\.posture\.valid\.json/);
  assert.match(page, /registry-notary\.posture\.valid\.json/);
  assert.match(page, /restricted-posture\.valid\.json/);
});

test('RS-OP-POSTURE records the closed v1 schema and new-identifier rule', () => {
  const page = readFileSync(specPath, 'utf8');
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));

  assert.equal(
    schema.$id,
    'https://id.registrystack.org/schemas/registry-platform/registry.ops.posture.v1.schema.json',
  );
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.schema.const, 'registry.ops.posture.v1');
  assert.deepEqual(schema.properties.component.enum, ['registry-relay', 'registry-notary']);
  assert.match(page, /additionalProperties: false/);
  assert.match(page, /Every post-1\.0 shape change, including an additive optional property/);
  assert.match(page, /requires a new\s+schema identifier/);
});
