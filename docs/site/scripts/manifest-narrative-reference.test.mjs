import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const here = dirname(fileURLToPath(import.meta.url));
const siteRoot = resolve(here, '..');
const repositoryRoot = resolve(siteRoot, '../..');
const manifestReference = readFileSync(
  resolve(repositoryRoot, 'products/manifest/docs/reference.md'),
  'utf8',
);
const narrativePages = [
  'src/content/docs/spec/rs-terms.mdx',
  'src/content/docs/reference/glossary.mdx',
  'src/content/docs/spec/rs-arc-g.mdx',
  'src/content/docs/explanation/architecture.mdx',
];

test('narrative manifest summaries defer the mutable key set to the Manifest reference', () => {
  assert.match(manifestReference, /^## Manifest top-level keys$/m);

  for (const pagePath of narrativePages) {
    const page = readFileSync(resolve(siteRoot, pagePath), 'utf8');

    assert.match(page, /Registry Manifest reference/);
    assert.match(page, /products\/registry-manifest\/reference/);
    assert.doesNotMatch(
      page,
      /describes datasets, entities, fields, public services, forms, requirements, policies,/,
    );
  }
});
