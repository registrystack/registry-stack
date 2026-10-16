import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';

import { eventConfiguration } from '../src/lib/breg-event-reference.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const configuration = JSON.parse(read('../src/data/generated/breg-configuration.json'));
const tables = parse(read('../src/data/breg-events.yaml'));
const page = read('../src/content/docs/reference/breg-api.mdx');
// Webhook binding is an operator task with a page of its own, beside the
// deploy page, so the declaration side (configure) and the reference both
// point a reader at that page rather than at a section of the deploy page.
const webhookGuide = read('../src/content/docs/operate/breg-webhooks.mdx');
const configurationGuide = read('../src/content/docs/configure/breg.mdx');

test('event fields reuse both complete native schema selections without changing definitions', () => {
  const before = structuredClone(configuration);
  const selected = eventConfiguration(configuration);
  const cases = [
    ['module', 'recordTypes[].hooks[].'],
    ['project', 'actions[].execution.proposal.hooks[].'],
  ];
  assert.equal(selected.length, cases.length);
  for (const [index, [contractId, prefix]] of cases.entries()) {
    const contract = configuration.contracts.find((entry) => entry.id === contractId);
    const source = contract.fields.filter((field) => field.key_path.startsWith(prefix));
    assert.ok(source.length > 0);
    assert.equal(selected[index].file, contract.file);
    assert.deepEqual(selected[index].fields, source.map((field) => ({
      ...field, key_path: field.key_path.slice(prefix.length),
    })));
    assert.equal(selected[index].field_count, source.length);
  }
  assert.deepEqual(configuration, before);
  assert.throws(() => eventConfiguration({ contracts: [] }), /missing/);
  assert.throws(() => eventConfiguration({ contracts: [{ id: 'module', fields: [] }] }), /empty/);
});

test('protocol tables are generated, rectangular, and all included in the reference', () => {
  assert.deepEqual(JSON.parse(read('../src/data/generated/breg-events.json')), tables);
  assert.equal(new Set(tables.map((table) => table.id)).size, tables.length);
  for (const table of tables) {
    assert.ok(table.columns.length >= 2 && table.columns.length <= 5, table.id);
    assert.ok(table.rows.length > 0, table.id);
    assert.ok(table.columns.every((column) => typeof column === 'string' && column.length > 0));
    for (const row of table.rows) {
      assert.equal(row.length, table.columns.length, table.id);
      assert.ok(row.every((cell) => typeof cell === 'string' && cell.length > 0), table.id);
    }
  }
  const rendered = [...page.matchAll(/<EventReferenceTable id="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(rendered.sort(), tables.map((table) => table.id).sort());
});

test('trigger matrix covers the schema enum and the trigger-specific snapshot rules', () => {
  const fields = eventConfiguration(configuration)[0].fields;
  const trigger = fields.find((field) => field.key_path === 'trigger');
  const rows = tables.find((table) => table.id === 'triggers').rows;
  assert.deepEqual(rows.map((row) => row[0].replaceAll('`', '')), trigger.values);
  assert.deepEqual(rows.map((row) => row.slice(1)), [
    ['Not allowed', 'Not allowed', 'Allowed', 'After'],
    ['Allowed', 'Allowed', 'Allowed', 'After'],
    ['Not allowed', 'Allowed', 'Not allowed', 'Before'],
  ]);
});

test('Proposal payload fields match the closed native schema and omit retired request data', () => {
  const schema = JSON.parse(read('../../../products/breg/generated/event-schemas/proposal-lifecycle.schema.json'));
  const documented = tables.find((table) => table.id === 'proposal-payload').rows
    .flatMap((row) => [...row[0].matchAll(/`([^`]+)`/g)].map((match) => match[1]));
  assert.deepEqual(documented.sort(), [...schema.required].sort());
  const recordPayload = tables.find((table) => table.id === 'payload').rows.map((row) => row[0]);
  assert.ok(recordPayload.includes('`recordType`'));
  assert.ok(!recordPayload.includes('`entity`'));
  assert.ok(!JSON.stringify(tables).includes('request-lifecycle'));
});

test('header lookup covers the exact platform event request header inventory', () => {
  const source = read('../../../crates/registry-platform-httputil/src/destination.rs');
  const start = source.indexOf('pub fn event_delivery(');
  const end = source.indexOf('pub fn render_event(', start);
  assert.ok(start >= 0 && end > start);
  const names = [...source.slice(start, end).matchAll(/name: "([^"]+)"/g)]
    .map((match) => match[1]).sort();
  const documented = tables.find((table) => table.id === 'headers').rows
    .map((row) => row[0].replaceAll('`', '').toLowerCase()).sort();
  assert.ok(names.length > 0);
  assert.deepEqual(documented, names);
});

test('webhook setup and contract lookup have separate connected pages', () => {
  assert.match(webhookGuide, /doc_type: how-to/);
  assert.match(webhookGuide, /bregctl webhook replay/);
  assert.match(webhookGuide, /\.\.\/\.\.\/reference\/breg-api\//);
  assert.match(page, /doc_type: reference/);
  assert.match(page, /\.\.\/\.\.\/operate\/breg-webhooks\//);
  assert.doesNotMatch(page, /```sh/);
  assert.match(configurationGuide, /\.\.\/\.\.\/operate\/breg-webhooks\//);
});
