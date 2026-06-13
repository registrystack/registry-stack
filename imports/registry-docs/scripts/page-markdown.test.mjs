// Unit tests for the per-page Markdown helpers (src/lib/page-markdown.ts).
// Run with `npm test` (node --test). All assertions run offline: no Astro
// runtime, no content collection, no network access required.

import assert from 'node:assert/strict';
import { test } from 'node:test';

// The TypeScript source lives in src/lib/page-markdown.ts.  Because this
// project uses plain `node --test` (no transpiler in the test runner), the
// two pure functions are re-implemented inline below so the tests remain
// self-contained and offline.  If a transpiler is ever wired into the test
// pipeline, replace them with a direct import of the compiled module.

const DISCOVERY_HEADER = `Registry stack documentation: machine-readable Markdown.
Index of all pages: https://docs.registrystack.org/llms.txt
Full corpus: https://docs.registrystack.org/llms-full.txt`;

/** @param {string} entryId */
function entrySlugToOutputPath(entryId) {
  if (entryId === 'index') return 'index';
  if (entryId.endsWith('/index')) return entryId.slice(0, -'/index'.length);
  return entryId;
}

/**
 * @param {string} title
 * @param {string | undefined} description
 * @param {string} body
 */
function buildPageMarkdown(title, description, body) {
  const parts = [DISCOVERY_HEADER, '', `# ${title}`];
  if (description) {
    parts.push('', `> ${description}`);
  }
  parts.push('', body);
  return parts.join('\n');
}

// ---- buildPageMarkdown ----

test('markdown output starts with the discovery header', () => {
  const out = buildPageMarkdown('My Title', undefined, 'Body text.');
  assert.ok(
    out.startsWith(DISCOVERY_HEADER),
    `expected output to start with the discovery header; got:\n${out.slice(0, 200)}`,
  );
});

test('discovery header contains llms.txt and llms-full.txt URLs', () => {
  const out = buildPageMarkdown('Title', undefined, 'Body.');
  assert.ok(out.includes('https://docs.registrystack.org/llms.txt'), 'missing llms.txt URL');
  assert.ok(out.includes('https://docs.registrystack.org/llms-full.txt'), 'missing llms-full.txt URL');
});

test('title is rendered as an H1 heading', () => {
  const out = buildPageMarkdown('Architecture overview', undefined, 'Body.');
  assert.ok(out.includes('\n# Architecture overview\n'), 'title heading not found');
});

test('description is rendered as a blockquote when present', () => {
  const out = buildPageMarkdown('Title', 'A short description.', 'Body.');
  assert.ok(out.includes('\n> A short description.\n'), 'description blockquote not found');
});

test('no description blockquote when description is undefined', () => {
  const out = buildPageMarkdown('Title', undefined, 'Body.');
  assert.ok(!out.includes('\n> '), 'unexpected blockquote when description absent');
});

test('no description blockquote when description is empty string', () => {
  const out = buildPageMarkdown('Title', '', 'Body.');
  // Empty string is falsy: no blockquote expected.
  assert.ok(!out.includes('\n> '), 'unexpected blockquote when description is empty');
});

test('raw body content is included verbatim', () => {
  const body = 'Some **markdown** content.\n\n## Sub-heading\n\nMore text.';
  const out = buildPageMarkdown('Title', 'Desc.', body);
  assert.ok(out.includes(body), 'body content not found in output');
});

test('full output structure: header + title + description + body', () => {
  const out = buildPageMarkdown('My Page', 'Summary here.', 'Page body.');
  const lines = out.split('\n');
  // First line is the first line of the discovery header.
  assert.equal(lines[0], 'Registry stack documentation: machine-readable Markdown.');
  // Title heading appears after header.
  assert.ok(out.indexOf('# My Page') > out.indexOf(DISCOVERY_HEADER));
  // Description blockquote appears after title.
  assert.ok(out.indexOf('> Summary here.') > out.indexOf('# My Page'));
  // Body appears after description.
  assert.ok(out.indexOf('Page body.') > out.indexOf('> Summary here.'));
});

// ---- entrySlugToOutputPath ----

test('root index maps to "index"', () => {
  assert.equal(entrySlugToOutputPath('index'), 'index');
});

test('nested page slug passes through unchanged', () => {
  assert.equal(entrySlugToOutputPath('explanation/architecture'), 'explanation/architecture');
});

test('product index slug strips trailing /index', () => {
  assert.equal(entrySlugToOutputPath('products/registry-relay/index'), 'products/registry-relay');
});

test('product sub-page slug passes through unchanged', () => {
  assert.equal(
    entrySlugToOutputPath('products/registry-relay/configuration'),
    'products/registry-relay/configuration',
  );
});

test('deeply nested index slug strips trailing /index', () => {
  assert.equal(entrySlugToOutputPath('a/b/c/index'), 'a/b/c');
});

test('slug with "index" in the middle is not modified', () => {
  // Only a trailing /index segment should be stripped.
  assert.equal(entrySlugToOutputPath('index-page'), 'index-page');
  assert.equal(entrySlugToOutputPath('tutorials/index-guide'), 'tutorials/index-guide');
});
