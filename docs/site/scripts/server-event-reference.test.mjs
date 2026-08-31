import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';

import { eventConfiguration } from '../src/lib/server-event-reference.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const configuration = JSON.parse(read('../src/data/generated/server-configuration.json'));
const tables = parse(read('../src/data/server-events.yaml'));
const page = read('../src/content/docs/reference/registry-server-events.mdx');

test('event fields reuse the complete module schema selection without changing definitions', () => {
  const before = structuredClone(configuration);
  const [event] = eventConfiguration(configuration);
  const module = configuration.contracts.find((contract) => contract.id === 'module');
  const source = module.fields.filter((field) => field.key_path.startsWith('entities[].events[].'));
  assert.equal(event.field_count, source.length);
  assert.ok(event.field_count > 0);
  assert.equal(event.file, module.file);
  assert.deepEqual(event.fields, source.map((field) => ({
    ...field, key_path: field.key_path.slice('entities[].events[].'.length),
  })));
  assert.deepEqual(configuration, before);
  assert.throws(() => eventConfiguration({ contracts: [] }), /missing/);
  assert.throws(() => eventConfiguration({ contracts: [{ id: 'module', fields: [] }] }), /empty/);
});

test('protocol tables are generated, rectangular, and all included in the reference', () => {
  assert.deepEqual(JSON.parse(read('../src/data/generated/server-events.json')), tables);
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
  const guide = read('../src/content/docs/configure/registry-server-webhooks.mdx');
  const configurationGuide = read('../src/content/docs/configure/registry-server.mdx');
  assert.match(guide, /doc_type: how-to/);
  assert.match(guide, /target\/debug\/registry-serverctl webhook replay/);
  assert.match(guide, /\.\.\/\.\.\/reference\/registry-server-events\//);
  assert.match(page, /doc_type: reference/);
  assert.match(page, /\.\.\/\.\.\/configure\/registry-server-webhooks\//);
  assert.doesNotMatch(page, /```sh/);
  assert.doesNotMatch(configurationGuide, /record-labelled-v1/);
  assert.match(configurationGuide, /\.\.\/registry-server-webhooks\//);
});
