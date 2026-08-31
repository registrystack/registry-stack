import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { collectFields } from './configuration-reference.mjs';
import { buildServerConfiguration, generateServerConfiguration, CONTRACTS } from './generate-server-configuration.mjs';

test('Server covers every committed authoring and runtime schema', async () => {
  const root = new URL('../../../products/registry-server/generated/', import.meta.url);
  const files = (await Promise.all(['authoring', 'runtime'].map(async (directory) =>
    (await readdir(new URL(`${directory}/`, root))).map((name) => `${directory}/${name}`),
  ))).flat().sort();
  assert.deepEqual(files, CONTRACTS.map((contract) => contract.file.split('/generated/')[1]).sort());
  const document = await buildServerConfiguration();
  assert.deepEqual(document.contracts.map((contract) => contract.id), ['project', 'module', 'runtime']);
  for (const contract of document.contracts) {
    assert.equal(contract.status, 'beta');
    assert.equal(contract.field_count, new Set(contract.fields.map((field) => field.key_path)).size);
  }
});

test('Server reference includes module extensions, event conditions, and runtime delivery limits', async () => {
  const document = await buildServerConfiguration();
  const fields = (id) => new Map(document.contracts.find((contract) => contract.id === id)
    .fields.map((field) => [field.key_path, field]));
  const project = fields('project');
  const module = fields('module');
  const runtime = fields('runtime');
  assert.ok(project.has('accessProfiles[].grants[].entity'));
  assert.deepEqual(module.get('extendEntities[].events[].trigger').values, ['created', 'patched', 'tombstoned']);
  for (const path of ['changed[]', 'beforeEquals.*', 'afterEquals.*']) {
    assert.ok(module.has(`extendEntities[].events[].when.${path}`), path);
  }
  assert.ok(module.has('extendEntities[].events[].webhook.destinationId'));
  assert.ok(!module.has('extendEntities[].events[].webhook.origin'));
  assert.ok(runtime.has('eventDestinations.*.hmacSha256KeyRef'));
  assert.ok(runtime.has('eventDestinations.*.tls.clientIdentityRef'));
  assert.ok(runtime.has('eventDestinations.*.deliveryCeilings.maximumAttempts'));
  assert.deepEqual(runtime.get('eventDelivery.payloadRetentionDays').defaults, ['7']);
  assert.ok(runtime.get('eventDelivery.payloadRetentionDays').constraints.flat().includes('maximum: 30'));
});

test('schema defaults preserve false, null, collections, and referenced defaults', () => {
  const fields = collectFields({
    type: 'object',
    properties: {
      enabled: { type: 'boolean', default: false },
      optional: { type: ['string', 'null'], default: null },
      names: { type: 'array', default: [], items: { type: 'string' } },
      limit: { $ref: '#/$defs/limit' },
      missing: { type: 'string' },
      blank: { type: 'string', default: '' },
      limits: { type: 'object', default: { count: 9223372036854775807n } },
    },
    $defs: { limit: { type: 'integer', default: 5 } },
  });
  const defaults = Object.fromEntries(fields.map((field) => [field.key_path, field.defaults]));
  assert.deepEqual(defaults, {
    blank: ['""'], enabled: ['false'], limit: ['5'], limits: ['{"count":9223372036854775807}'],
    missing: [], names: ['[]'], 'names[]': [], optional: ['null'],
  });
});

test('Server reference generation is deterministic and matches committed data', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'server-configuration-'));
  try {
    await generateServerConfiguration(scratch);
    const path = join(scratch, 'src/data/generated/server-configuration.json');
    const first = await readFile(path, 'utf8');
    await generateServerConfiguration(scratch);
    assert.equal(first, await readFile(path, 'utf8'));
    assert.equal(first, await readFile(new URL('../src/data/generated/server-configuration.json', import.meta.url), 'utf8'));
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});
