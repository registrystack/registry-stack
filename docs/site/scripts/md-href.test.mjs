// Unit tests for src/lib/md-href.ts (imported as JS, TypeScript is transpiled
// by the node --test runner via the project's tsconfig, but since we need to
// run offline we import the raw .ts file through the tsx loader when available,
// otherwise we inline an equivalent JS function).
//
// Run with: node --test scripts/md-href.test.mjs
// (also picked up by `npm test` via "scripts/**/*.test.mjs")

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

// --- Load the function ---------------------------------------------------------
// The source is TypeScript. We strip types at import time with a small inline
// transform rather than requiring tsx/ts-node, so the tests run offline with
// plain `node --test` (Node 22 supports --experimental-strip-types for .ts
// files when invoked explicitly, but that flag is experimental). Instead we
// read the .ts source, strip the type annotations with a minimal regex, and
// eval it as a module. This keeps the test self-contained and dependency-free.

const here = dirname(fileURLToPath(import.meta.url));
const srcPath = resolve(here, '../src/lib/md-href.ts');
const tsSource = readFileSync(srcPath, 'utf8');

// Strip TypeScript-only syntax: type annotations, export type, interface blocks,
// and the "export" keyword on the function (we re-export below).
// This is intentionally minimal: it only needs to handle what md-href.ts uses.
const jsSource = tsSource
  .replace(/^\/\*\*[\s\S]*?\*\//gm, '') // remove JSDoc block comments
  .replace(/:\s*string\b/g, '')          // remove ": string" type annotations
  .replace(/^export\s+function/, 'export function'); // keep export

// Use a data: URL so Node treats it as an ES module.
const dataUrl = 'data:text/javascript,' + encodeURIComponent(jsSource);
const { mdHrefForPath } = await import(dataUrl);

// --- Tests --------------------------------------------------------------------

test('root "/" maps to "/index.md"', () => {
  assert.equal(mdHrefForPath('/'), '/index.md');
});

test('root "/" with explicit base "/" maps to "/index.md"', () => {
  assert.equal(mdHrefForPath('/', '/'), '/index.md');
});

test('trailing-slash page -> strip slash + ".md"', () => {
  assert.equal(mdHrefForPath('/explanation/architecture/'), '/explanation/architecture.md');
});

test('nested product page -> correct .md path', () => {
  assert.equal(
    mdHrefForPath('/products/registry-relay/configuration/'),
    '/products/registry-relay/configuration.md',
  );
});

test('path without trailing slash also works', () => {
  assert.equal(mdHrefForPath('/explanation/architecture'), '/explanation/architecture.md');
});

test('non-root BASE_URL: base is prepended to the .md path', () => {
  assert.equal(mdHrefForPath('/docs/', '/docs/'), '/docs/index.md');
  assert.equal(
    mdHrefForPath('/docs/explanation/architecture/', '/docs/'),
    '/docs/explanation/architecture.md',
  );
});

test('non-root BASE_URL without trailing slash normalises correctly', () => {
  assert.equal(
    mdHrefForPath('/docs/explanation/architecture/', '/docs'),
    '/docs/explanation/architecture.md',
  );
});
