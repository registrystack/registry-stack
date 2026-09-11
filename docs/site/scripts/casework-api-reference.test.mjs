import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const tables = parse(read('../src/data/casework-api.yaml'));
const page = read('../src/content/docs/reference/apis/registry-casework.mdx');

test('every ApiReferenceTable id used in the Casework reference exists in casework-api.yaml', () => {
  const referenced = [...page.matchAll(/<ApiReferenceTable id="([^"]+)" source="casework-api"/g)].map((match) => match[1]);
  assert.ok(referenced.includes('problem-codes'), 'reference/apis/registry-casework.mdx should render the problem-codes table');
  assert.equal(
    [...page.matchAll(/<ApiReferenceTable /g)].length,
    referenced.length,
    'every table on the Casework reference must read casework-api.yaml, not the Base Registry Engine tables',
  );
  const ids = new Set(tables.map((table) => table.id));
  for (const id of referenced) {
    assert.ok(ids.has(id), `${id} is referenced by <ApiReferenceTable> in reference/apis/registry-casework.mdx but missing from casework-api.yaml`);
  }
});

test('casework-api tables are rectangular with non-empty columns and rows', () => {
  assert.equal(new Set(tables.map((table) => table.id)).size, tables.length);
  for (const table of tables) {
    assert.ok(table.columns.length > 0, `${table.id} has no columns`);
    assert.ok(table.rows.length > 0, `${table.id} has no rows`);
    for (const row of table.rows) {
      assert.equal(row.length, table.columns.length, `${table.id} has a row whose cell count does not match its column count`);
    }
  }
});

test('casework-api.json is the generated output of casework-api.yaml', () => {
  assert.deepEqual(JSON.parse(read('../src/data/generated/casework-api.json')), tables);
});
