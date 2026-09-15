import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const tables = parse(read('../src/data/scheduling-api.yaml'));
const page = read('../src/content/docs/reference/apis/registry-scheduling.mdx');

test('every ApiReferenceTable id used in the Scheduling reference exists in scheduling-api.yaml', () => {
  const referenced = [...page.matchAll(/<ApiReferenceTable id="([^"]+)" source="scheduling-api"/g)].map((match) => match[1]);
  assert.ok(referenced.includes('problem-codes'), 'reference/apis/registry-scheduling.mdx should render the problem-codes table');
  assert.equal(
    [...page.matchAll(/<ApiReferenceTable /g)].length,
    referenced.length,
    'every table on the Scheduling reference must read scheduling-api.yaml, not the tables of another product',
  );
  const ids = new Set(tables.map((table) => table.id));
  for (const id of referenced) {
    assert.ok(ids.has(id), `${id} is referenced by <ApiReferenceTable> in reference/apis/registry-scheduling.mdx but missing from scheduling-api.yaml`);
  }
});

test('scheduling-api tables are rectangular with non-empty columns and rows', () => {
  assert.equal(new Set(tables.map((table) => table.id)).size, tables.length);
  for (const table of tables) {
    assert.ok(table.columns.length > 0, `${table.id} has no columns`);
    assert.ok(table.rows.length > 0, `${table.id} has no rows`);
    for (const row of table.rows) {
      assert.equal(row.length, table.columns.length, `${table.id} has a row whose cell count does not match its column count`);
    }
  }
});

test('scheduling-api.json is the generated output of scheduling-api.yaml', () => {
  assert.deepEqual(JSON.parse(read('../src/data/generated/scheduling-api.json')), tables);
});

test('every problem code row matches the product problem catalogue', () => {
  const document = JSON.parse(read('../../../products/scheduling/generated/registry-scheduling.openapi.json'));
  const catalogue = new Map();
  for (const schema of Object.values(document.components.schemas)) {
    for (const part of schema.allOf ?? []) {
      const code = part.properties?.code?.const;
      if (code) catalogue.set(code, part.properties.status.const);
    }
  }
  assert.ok(catalogue.size >= 30, 'the generated document should carry the full problem catalogue');
  const rows = tables.find((table) => table.id === 'problem-codes').rows;
  assert.equal(rows.length, catalogue.size, 'the table and the catalogue hold the same number of codes');
  for (const [code, status, when] of rows) {
    const bareCode = code.replace(/`/g, '');
    assert.ok(catalogue.has(bareCode), `${bareCode} appears in scheduling-api.yaml but not in the product catalogue`);
    assert.equal(String(catalogue.get(bareCode)), status, `${bareCode} lists status ${status} but the catalogue pins ${catalogue.get(bareCode)}`);
    assert.ok(when.length > 0, `${bareCode} has an empty when sentence`);
  }
});
