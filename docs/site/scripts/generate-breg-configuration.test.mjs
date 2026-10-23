import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { collectFields } from './configuration-reference.mjs';
import {
  buildBRegConfiguration,
  CONTRACTS,
  generateBRegConfiguration,
  proposalQueryKeys,
  SERVICE_CONTRACTS,
  TOOL_CONTRACTS,
} from './generate-breg-configuration.mjs';

test('BReg covers every committed authoring and runtime schema', async () => {
  const root = new URL('../../../products/breg/generated/', import.meta.url);
  const files = (await Promise.all(['authoring', 'runtime'].map(async (directory) =>
    (await readdir(new URL(`${directory}/`, root))).map((name) => `${directory}/${name}`),
  ))).flat().sort();
  assert.deepEqual(files, CONTRACTS.map((contract) => contract.file.split('/generated/')[1]).sort());
  const document = await buildBRegConfiguration();
  assert.deepEqual(document.contracts.map((contract) => contract.id), ['project', 'module', 'runtime']);
  for (const contract of document.contracts) {
    assert.equal(contract.status, 'beta');
    assert.equal(contract.field_count, new Set(contract.fields.map((field) => field.key_path)).size);
  }
});

test('BReg reference includes module extensions, hook conditions, and runtime delivery limits', async () => {
  const document = await buildBRegConfiguration();
  const fields = (id) => new Map(document.contracts.find((contract) => contract.id === id)
    .fields.map((field) => [field.key_path, field]));
  const project = fields('project');
  const module = fields('module');
  const runtime = fields('runtime');
  assert.ok(project.has('accessProfiles[].permissions.records[].recordType'));
  assert.deepEqual(module.get('recordTypes[].hooks[].trigger').values, ['created', 'patched', 'tombstoned']);
  assert.deepEqual(module.get('recordTypes[].hooks[].phase').values, ['after', 'before']);
  assert.ok(project.has('accessProfiles[].permissions.proposals[].targets[].recordType'));
  assert.deepEqual(project.get('actions[].execution.proposal.hooks[].transitions[]').values,
    ['applied', 'cancelled', 'edited', 'rebased', 'rejected', 'retried', 'review-returned', 'revised', 'started',
      'submitted']);
  for (const path of ['changed[]', 'beforeEquals.*', 'afterEquals.*']) {
    assert.ok(module.has(`recordTypes[].hooks[].when.${path}`), path);
  }
  assert.deepEqual(module.get('recordTypes[].hooks[].handler.type').values, ['rhai', 'url', 'wasm']);
  assert.ok(module.has('recordTypes[].hooks[].handler.destinationId'));
  assert.ok(!module.has('recordTypes[].hooks[].handler.origin'));
  assert.ok(runtime.has('eventDestinations.*.hmacSha256KeyRef'));
  assert.ok(runtime.has('eventDestinations.*.tls.clientIdentityRef'));
  assert.ok(runtime.has('eventDestinations.*.deliveryCeilings.maximumAttempts'));
  assert.deepEqual(runtime.get('retention.hookPayloadRetentionDays').defaults, ['7']);
  assert.ok(runtime.get('retention.hookPayloadRetentionDays').constraints.flat().includes('maximum: 30'));
});

test('BReg covers every committed tool schema, in the order an adopter meets the files', async () => {
  const root = new URL('../../../products/breg/generated/tools/', import.meta.url);
  assert.deepEqual((await readdir(root)).map((name) => `tools/${name}`).sort(),
    TOOL_CONTRACTS.map((entry) => entry.file.split('/generated/')[1]).sort());
  assert.deepEqual(TOOL_CONTRACTS.map((entry) => entry.id), ['dev-clients', 'example-scenarios', 'journeys',
    'schema-test-credentials', 'migration-descriptor', 'backup-binding', 'model-selection']);
});

test('BReg tool and service references read the committed schemas they name', async () => {
  const document = await buildBRegConfiguration();
  assert.deepEqual(document.tools.map((entry) => entry.id), TOOL_CONTRACTS.map((entry) => entry.id));
  assert.deepEqual(document.services.map((entry) => entry.id), ['mcp-runtime', 'review-runtime']);
  const root = new URL('../../../products/breg/generated/', import.meta.url);
  for (const entry of [...TOOL_CONTRACTS, ...SERVICE_CONTRACTS]) {
    const schema = JSON.parse(await readFile(new URL(entry.file.split('/generated/')[1], root), 'utf8'));
    assert.ok(typeof schema.title === 'string' && schema.title.length > 0, entry.file);
  }
  for (const entry of [...document.tools, ...document.services]) {
    assert.ok(['tooling', 'beta'].includes(entry.status), entry.id);
    assert.equal(entry.field_count, new Set(entry.fields.map((field) => field.key_path)).size, entry.id);
  }
  const fields = (group, id) => new Map(document[group].find((entry) => entry.id === id)
    .fields.map((field) => [field.key_path, field]));

  const descriptor = fields('tools', 'migration-descriptor');
  assert.deepEqual(descriptor.get('steps[].type').values,
    ['chunked-backfill', 'field-encryption-backfill', 'transactional-sql']);
  assert.deepEqual(descriptor.get('recovery').values, ['exact-target-resume']);
  assert.deepEqual(descriptor.get('history').values, ['erase-and-rebaseline', 'retain-plaintext-history']);
  assert.deepEqual(descriptor.get('kind').values, ['BRegMigrationDescriptor']);
  assert.ok(descriptor.has('steps[].objects[].physicalName'));

  const binding = fields('tools', 'backup-binding');
  assert.deepEqual([...binding.keys()].sort(), ['apiVersion', 'backupFile', 'createdAt', 'database', 'digest',
    'kind', 'maximumAgeSeconds', 'priorPackageDigest', 'priorSchemaFingerprint', 'sizeBytes']);
  assert.ok([...binding.values()].every((field) => field.required === 'yes'));
  assert.ok(binding.get('maximumAgeSeconds').constraints.flat().includes('maximum: 2678400'));

  const journeys = fields('tools', 'journeys');
  assert.deepEqual(journeys.get('kind').values, ['BRegJourneys']);
  assert.ok(journeys.has('journeys[].steps[].expect.outcome'));
  assert.ok(fields('tools', 'dev-clients').has('clients[].accessProfiles'));

  const credentials = fields('tools', 'schema-test-credentials');
  assert.deepEqual(credentials.get('kind').values, ['BRegSchemaTestCredentials']);
  assert.deepEqual(credentials.get('bindings[].credential.type').values, ['bearer']);
  for (const key of ['bindings[].journeyId', 'bindings[].stepId', 'bindings[].credential.tokenRef']) {
    assert.equal(credentials.get(key).required, 'yes', key);
  }
  assert.ok(credentials.get('bindings[].credential.tokenRef').constraints.flat()
    .some((constraint) => constraint.startsWith('pattern: ^(?:secret:env/')));

  const scenarios = fields('tools', 'example-scenarios');
  assert.deepEqual(scenarios.get('kind').values, ['BRegExampleScenarios']);
  assert.ok(scenarios.get('scenarios[].steps[].operation').values.includes('submit'));
  assert.ok(scenarios.has('scenarios[].steps[].expect.problemCode'));

  const selection = fields('tools', 'model-selection');
  assert.deepEqual(selection.get('kind').values, ['BRegModelSelection']);
  assert.deepEqual(selection.get('model').values, ['publicschema']);
  assert.ok(selection.has('recordTypes[].properties[].name'));
  assert.deepEqual(selection.get('vocabularies[].mode').values, ['code', 'inline']);

  const gateway = fields('services', 'mcp-runtime');
  assert.deepEqual(gateway.get('resourceServer.algorithms[]').values, ['ES256', 'ES384', 'EdDSA', 'RS256', 'RS384']);
  assert.deepEqual(gateway.get('resourceServer.maximumTokenLifetimeSeconds').defaults, ['3600']);
  for (const key of ['registry.audience', 'exchange.privateKeyRef', 'service.reviewBaseUrl']) {
    assert.ok(gateway.get(key).description, key);
  }
  const review = fields('services', 'review-runtime');
  assert.deepEqual(review.get('session.maximumLifetimeSeconds').defaults, ['3600']);
  assert.ok(review.get('signIn.scopes').constraints.flat().includes('maxItems: 16'));
});

test('Proposal list query keys come from the client capability inventory', async () => {
  const document = await buildBRegConfiguration();
  const inventory = JSON.parse(await readFile(
    new URL('../../../products/breg/contracts/client-capabilities.json', import.meta.url), 'utf8'));
  assert.equal(document.client_proposal_query.file, 'products/breg/contracts/client-capabilities.json');
  assert.deepEqual(document.client_proposal_query.keys.map((entry) => entry.key),
    ['action', 'owner', 'target', 'state', 'cursor', 'limit', 'turn', 'pendingManualApplication']);
  for (const entry of document.client_proposal_query.keys) {
    assert.deepEqual(entry, { key: entry.key, ...inventory.queryOptionBindings[entry.key] });
  }
  assert.throws(() => proposalQueryKeys({}), /queryOptionBindings/);
  assert.throws(() => proposalQueryKeys({ queryOptionBindings: {
    accessProfile: { rust: ['BRegRecordOptions.access_profile'], node: [], python: [] },
  } }), /no Proposal list query key/);
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

test('BReg reference generation is deterministic and matches committed data', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'breg-configuration-'));
  try {
    await generateBRegConfiguration(scratch);
    const path = join(scratch, 'src/data/generated/breg-configuration.json');
    const first = await readFile(path, 'utf8');
    await generateBRegConfiguration(scratch);
    assert.equal(first, await readFile(path, 'utf8'));
    assert.equal(first, await readFile(new URL('../src/data/generated/breg-configuration.json', import.meta.url), 'utf8'));
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});
