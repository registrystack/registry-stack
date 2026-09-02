import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const tables = parse(read('../src/data/server-api.yaml'));
const page = read('../src/content/docs/reference/registry-server-api.mdx');

test('every ApiReferenceTable id used in the reference exists in server-api.yaml', () => {
  const referenced = [...page.matchAll(/<ApiReferenceTable id="([^"]+)"/g)].map((match) => match[1]);
  assert.ok(referenced.length > 0);
  const ids = new Set(tables.map((table) => table.id));
  for (const id of referenced) {
    assert.ok(
      ids.has(id),
      `${id} is referenced by <ApiReferenceTable> in reference/registry-server-api.mdx but missing from server-api.yaml`,
    );
  }
});

test('server-api tables are rectangular with non-empty columns and rows', () => {
  assert.equal(new Set(tables.map((table) => table.id)).size, tables.length);
  for (const table of tables) {
    assert.ok(table.columns.length > 0, `${table.id} has no columns`);
    assert.ok(table.rows.length > 0, `${table.id} has no rows`);
    for (const row of table.rows) {
      assert.equal(row.length, table.columns.length, `${table.id} has a row whose cell count does not match its column count`);
    }
  }
});

test('server-api.json is the generated output of server-api.yaml', () => {
  assert.deepEqual(JSON.parse(read('../src/data/generated/server-api.json')), tables);
});
