import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { expandReferenceTables } from '../src/lib/reference-tables.mjs';

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

test('collection body expansion feeds Markdown twins and the LLM collection', () => {
  const loader = readFileSync(new URL('../src/content.config.ts', import.meta.url), 'utf8');
  assert.match(loader, /body: expandReferenceTables\(entry.body/);
  const route = readFileSync(new URL('../src/pages/[...slug].md.ts', import.meta.url), 'utf8');
  assert.match(route, /entry.body/);
});
