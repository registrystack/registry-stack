import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const tables = parse(read('../src/data/breg-api.yaml'));
const page = read('../src/content/docs/reference/breg-api.mdx');

const table = (id) => tables.find((candidate) => candidate.id === id);

test('every ApiReferenceTable id used in the reference exists in breg-api.yaml', () => {
  const referenced = [...page.matchAll(/<ApiReferenceTable id="([^"]+)"/g)].map((match) => match[1]);
  assert.ok(referenced.length > 0);
  const ids = new Set(tables.map((table) => table.id));
  for (const id of referenced) {
    assert.ok(
      ids.has(id),
      `${id} is referenced by <ApiReferenceTable> in reference/breg-api.mdx but missing from breg-api.yaml`,
    );
  }
});

test('breg-api tables are rectangular with non-empty columns and rows', () => {
  assert.equal(new Set(tables.map((table) => table.id)).size, tables.length);
  for (const table of tables) {
    assert.ok(table.columns.length > 0, `${table.id} has no columns`);
    assert.ok(table.rows.length > 0, `${table.id} has no rows`);
    for (const row of table.rows) {
      assert.equal(row.length, table.columns.length, `${table.id} has a row whose cell count does not match its column count`);
    }
  }
});

test('routes include governed access-log, attachment, and GIS surfaces with their gates', () => {
  const routes = table('routes');
  assert.ok(routes, 'breg-api.yaml has no routes table');
  const rows = new Map(routes.rows.map((row) => [row[0], row]));
  const expected = [
    ['`GET /v1/records/{route}/{recordId}/access-log`', ['declares `accessLog`', 'current subject']],
    ['`GET /v1/records/{route}/{recordId}/attachments/{slot}`', ['declares the attachment slot', 'through `get`']],
    ['`PATCH /v1/records/{route}/{recordId}/attachments/{slot}`', ['declares the attachment slot', 'mutations are enabled', 'through `patch`']],
    ['`DELETE /v1/records/{route}/{recordId}/attachments/{slot}`', ['declares the attachment slot', 'mutations are enabled', 'through `patch`']],
    ['`GET /v1/gis`', ['`listener.publicOrigin` is configured']],
    ['`GET /v1/gis/api`', ['`listener.publicOrigin` is configured', 'visible to the caller']],
    ['`GET /v1/gis/conformance`', ['`listener.publicOrigin` is configured']],
    ['`GET /v1/gis/collections`', ['`listener.publicOrigin` is configured', 'visible to the caller']],
    ['`GET /v1/gis/collections/{collection}`', ['`listener.publicOrigin` is configured', 'governed GIS collection']],
    ['`GET /v1/gis/collections/{collection}/items`', ['`listener.publicOrigin` is configured', 'governed GIS collection']],
  ];

  for (const [route, conditions] of expected) {
    const row = rows.get(route);
    assert.ok(row, `${route} is missing from the routes table`);
    for (const condition of conditions) {
      assert.ok(
        row[2].includes(condition),
        `${route} must document its availability condition: ${condition}`,
      );
    }
  }
});

test('breg-api.json is the generated output of breg-api.yaml', () => {
  assert.deepEqual(JSON.parse(read('../src/data/generated/breg-api.json')), tables);
});
