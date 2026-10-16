import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parse } from 'yaml';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const tables = parse(read('../src/data/coordinator-api.yaml'));
const page = read('../src/content/docs/reference/apis/registry-coordinator.mdx');
const document = JSON.parse(read('../../../products/coordinator/generated/openapi/coordinator.openapi.json'));

// Codes that answer a route or a body the document does not declare, so no
// operation response carries them and their status cannot be read from the
// document. The runtime test every_problem_an_operation_can_answer_is_documented_on_one
// in crates/registry-coordinator/src/http.rs keeps the same list.
const UNDECLARED_ROUTE_CODES = new Set(['request.not-found', 'request.unprocessable']);

test('every ApiReferenceTable id used in the Coordinator reference exists in coordinator-api.yaml', () => {
  const referenced = [...page.matchAll(/<ApiReferenceTable id="([^"]+)" source="coordinator-api"/g)].map((match) => match[1]);
  assert.ok(referenced.includes('problem-codes'), 'reference/apis/registry-coordinator.mdx should render the problem-codes table');
  assert.equal(
    [...page.matchAll(/<ApiReferenceTable /g)].length,
    referenced.length,
    'every table on the Coordinator reference must read coordinator-api.yaml, not the tables of another product',
  );
  const ids = new Set(tables.map((table) => table.id));
  for (const id of referenced) {
    assert.ok(ids.has(id), `${id} is referenced by <ApiReferenceTable> in reference/apis/registry-coordinator.mdx but missing from coordinator-api.yaml`);
  }
});

test('coordinator-api tables are rectangular with non-empty columns and rows', () => {
  assert.equal(new Set(tables.map((table) => table.id)).size, tables.length);
  for (const table of tables) {
    assert.ok(table.columns.length > 0, `${table.id} has no columns`);
    assert.ok(table.rows.length > 0, `${table.id} has no rows`);
    for (const row of table.rows) {
      assert.equal(row.length, table.columns.length, `${table.id} has a row whose cell count does not match its column count`);
    }
  }
});

test('coordinator-api.json is the generated output of coordinator-api.yaml', () => {
  assert.deepEqual(JSON.parse(read('../src/data/generated/coordinator-api.json')), tables);
});

test('every problem code row matches the product problem catalogue and the statuses that answer it', () => {
  const catalogue = document.components.schemas.Problem.properties.code.enum;
  assert.ok(catalogue.length > 0, 'the generated document should carry the problem catalogue');

  // The document pins no status beside a code, so read each code's status
  // from the operation responses that answer it.
  const statuses = new Map();
  for (const operations of Object.values(document.paths)) {
    for (const operation of Object.values(operations)) {
      for (const [status, response] of Object.entries(operation.responses ?? {})) {
        for (const media of Object.values(response.content ?? {})) {
          for (const part of media.schema?.allOf ?? []) {
            for (const code of part.properties?.code?.enum ?? []) {
              if (!statuses.has(code)) statuses.set(code, new Set());
              statuses.get(code).add(status);
            }
          }
        }
      }
    }
  }

  const rows = tables.find((table) => table.id === 'problem-codes').rows;
  const listed = rows.map(([code]) => code.replace(/`/g, ''));
  assert.deepEqual([...listed].sort(), [...catalogue].sort(), 'the table and the catalogue hold the same codes');
  for (const [code, status, when] of rows) {
    const bareCode = code.replace(/`/g, '');
    assert.ok(when.length > 0, `${bareCode} has an empty when sentence`);
    if (UNDECLARED_ROUTE_CODES.has(bareCode)) {
      assert.ok(!statuses.has(bareCode), `${bareCode} now answers a declared operation; check its status against it`);
      continue;
    }
    assert.ok(statuses.has(bareCode), `${bareCode} is in the catalogue but no operation response answers it`);
    assert.deepEqual([...statuses.get(bareCode)], [status], `${bareCode} lists status ${status} but the document answers it with ${[...statuses.get(bareCode)].join(', ')}`);
  }
});

test('the routes table lists exactly the routes the document declares', () => {
  assert.match(page, /<ApiReferenceTable id="routes" source="coordinator-api" \/>/);
  const routes = tables.find((table) => table.id === 'routes');
  assert.ok(routes, 'coordinator-api.yaml should carry a routes table');
  assert.deepEqual(routes.columns.slice(0, 2), ['Method', 'Path']);
  const listed = routes.rows.map(([method, path]) => `${method.replace(/`/g, '')} ${path.replace(/`/g, '')}`);
  const declared = Object.entries(document.paths).flatMap(([path, operations]) =>
    Object.keys(operations).map((method) => `${method.toUpperCase()} ${path}`),
  );
  assert.equal(new Set(listed).size, listed.length, 'the routes table lists each route once');
  assert.deepEqual([...listed].sort(), [...declared].sort());
});
