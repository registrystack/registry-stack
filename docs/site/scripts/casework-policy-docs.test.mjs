import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const guide = readFileSync(resolve(here, '../src/content/docs/configure/casework.mdx'), 'utf8');

function fencedYamlUnder(heading, marker = '## ') {
  const start = guide.indexOf(`${marker}${heading}`);
  assert.notEqual(start, -1, `missing ${heading} heading`);
  const section = guide.slice(start).split(/\n## /u, 1)[0];
  const fence = section.match(/```yaml\n([\s\S]*?)\n```/u);
  assert.ok(fence, `missing YAML example under ${heading}`);
  return parse(fence[1]);
}

test('the documented local Casework callers form a complete valid directory seed', () => {
  const example = fencedYamlUnder('Local callers in `dev-clients.yaml`');
  const clients = new Map(example.clients.map((client) => [client.id, client]));

  assert.deepEqual([...clients.keys()].sort(), [
    'administrator',
    'requester',
    'staff',
    'supervisor',
  ]);
  for (const role of ['administrator', 'staff', 'supervisor']) {
    assert.equal(clients.get(role).accessProfile, role);
    assert.equal(clients.get(role).claims.registry_actor_kind, 'human');
  }
  for (const team of example.directory) {
    for (const client of [...team.staff, ...team.supervisors]) {
      assert.ok(clients.has(client), `directory references undeclared client ${client}`);
    }
  }
});

test('the documented review policy and producer use the owning schema grammar', () => {
  const example = fencedYamlUnder('### Review policies and producers', '');
  const kind = example.reviewPolicies[0];

  for (const key of [
    'id',
    'version',
    'purpose',
    'context',
    'stages',
    'retention',
    'displaySchema',
    'resultSchema',
    'outcomes',
  ]) {
    assert.ok(Object.hasOwn(kind, key), `review policy is missing ${key}`);
  }
  assert.deepEqual(kind.context, { mode: 'submitted' });
  const schema = JSON.parse(readFileSync(resolve(here, '../../../products/casework/generated/project/project.schema.json'), 'utf8'));
  for (const key of Object.keys(kind)) {
    assert.ok(Object.hasOwn(schema.$defs.ReviewPolicy.properties, key), `unknown policy key ${key}`);
  }
  assert.equal(kind.retention.terminalRetentionDays, 90);
  assert.equal(kind.retention.accountabilityRetentionDays, 365);
  for (const schema of [kind.displaySchema, kind.resultSchema]) {
    assert.equal(schema.type, 'object');
    assert.equal(schema.additionalProperties, false, 'both schemas stay closed');
    assert.ok(Object.keys(schema.properties).length > 0);
  }
  for (const property of Object.values(kind.resultSchema.properties)) {
    assert.equal(typeof property.type, 'string', 'result fields declare one inline type');
  }
  assert.deepEqual(
    new Set(Object.values(kind.outcomes).flatMap((outcome) => Object.keys(outcome))),
    new Set(['label', 'settlement', 'reasonRequired', 'publicReason', 'resultRequired']),
    'outcome keys stay within the policy grammar',
  );
  for (const [id, outcome] of Object.entries(kind.outcomes)) {
    assert.ok(
      ['required', 'optional', 'none'].includes(outcome.publicReason),
      `outcome ${id} states whether a public reason is given`,
    );
  }
  const confirmed = kind.outcomes.confirmed;
  assert.equal(confirmed.resultRequired, true);
  assert.equal(confirmed.settlement, 'answered');
  assert.equal(kind.stages[0].requiredApprovals, 1);

  const producer = example.trustedProducers.requester;
  for (const key of Object.keys(producer)) {
    assert.ok(Object.hasOwn(schema.properties.trustedProducers.additionalProperties.properties, key), `unknown producer key ${key}`);
  }
  assert.equal(producer.profile, 'requester');
  assert.deepEqual(producer.retention, { receiptRetentionDays: 30 });
  assert.deepEqual(producer.reviewPolicies, ['decision']);
  assert.deepEqual(producer.sourceNamespaces, ['standalone']);
});


test('the current-source fragment preserves the exact exported contract fields', () => {
  const example = fencedYamlUnder('Choose context custody');
  const schema = JSON.parse(readFileSync(resolve(here, '../../../products/casework/generated/project/project.schema.json'), 'utf8'));
  assert.equal(example.context.mode, 'current-source');
  assert.equal(example.context.provider, 'facility-proposal-context');
  assert.deepEqual(Object.keys(example.context.contract).sort(), schema.$defs.ReviewContextContract.required.toSorted());
  assert.deepEqual(example.displaySchema, { $ref: 'schemas/correct-address.schema.json' });
});
