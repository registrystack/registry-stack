import assert from 'node:assert/strict';
import { test } from 'node:test';
import { expandReferenceEntry, expandReferenceTables } from '../src/lib/reference-tables.mjs';

const sources = {
  'breg-api': [{id: 'routes', columns: ['Method', 'Path'], rows: [['GET', '`/v1/records`']]}],
  'casework-api': [{id: 'problem-codes', columns: ['Code', 'Meaning'], rows: [['review.refused', 'A | B\nNext']]}],
  'breg-events': [{id: 'headers', columns: ['Header', 'Meaning'], rows: [['traceparent', 'Trace context']]}],
};

test('expands API and event components, including explicit source and attribute order', () => {
  const result = expandReferenceTables('<ApiReferenceTable id="routes" />\n<EventReferenceTable id="headers" />\n<ApiReferenceTable source="casework-api" id="problem-codes" />', sources);
  assert.match(result, /\| GET \| `\/v1\/records` \|/);
  assert.match(result, /\| traceparent \| Trace context \|/);
  assert.match(result, /A \\\| B<br>Next/);
  assert.doesNotMatch(result, /<(Api|Event)ReferenceTable/);
});

test('refuses unknown tables, sources, dynamic attributes and unsupported attributes', () => {
  for (const body of ['<ApiReferenceTable id="missing" />', '<ApiReferenceTable id="routes" source="unknown" />', '<EventReferenceTable id={table} />', '<ApiReferenceTable id="routes" extra="value" />']) {
    assert.throws(() => expandReferenceTables(body, sources), /reference table/);
  }
});

test('keeps fenced examples and unrelated MDX unchanged', () => {
  const body = '```mdx\n<ApiReferenceTable id="missing" />\n```\n<Other id="routes" />';
  assert.equal(expandReferenceTables(body, sources), body);
});

test('stored body expansion changes its digest while retaining normal MDX render metadata', () => {
  const entry = { id: 'reference/breg-api', digest: 'source', body: '<ApiReferenceTable id="routes" />', deferredRender: true, filePath: 'reference/breg-api.mdx' };
  let digested;
  const expanded = expandReferenceEntry(entry, (value) => { digested = value; return 'expanded'; });
  assert.equal(expanded.digest, 'expanded');
  assert.match(expanded.body, /\| Route \| Operation \|/);
  assert.equal(digested.sourceDigest, 'source');
  assert.equal(digested.body, expanded.body);
  assert.equal(expanded.filePath, entry.filePath);
  assert.equal(expanded.deferredRender, true);
  assert.equal(expandReferenceEntry(expanded, () => { throw new Error('unchanged body'); }), expanded);
});
