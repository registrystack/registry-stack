import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { buildProductionSearch } from './build-production-search.mjs';

async function fixture(t) {
  const docsRoot = await mkdtemp(resolve(tmpdir(), 'registry-production-search-'));
  t.after(() => rm(docsRoot, { recursive: true, force: true }));
  const distRoot = resolve(docsRoot, 'dist');
  await Promise.all([
    mkdir(resolve(distRoot, 'guide'), { recursive: true }),
    mkdir(resolve(distRoot, 'dev'), { recursive: true }),
    mkdir(resolve(distRoot, 'preview'), { recursive: true }),
    mkdir(resolve(distRoot, 'v/1.0.0'), { recursive: true }),
  ]);
  await writeFile(
    resolve(distRoot, 'index.html'),
    '<html><body><main data-pagefind-body><h1>Released home</h1></main></body></html>',
  );
  await writeFile(
    resolve(distRoot, 'guide/index.html'),
    '<html><body><main data-pagefind-body><h1>Released guide</h1></main></body></html>',
  );
  await writeFile(
    resolve(distRoot, 'old.html'),
    '<html><head><meta http-equiv="refresh" content="0;url=/guide/"></head><body data-pagefind-body>Old</body></html>',
  );
  for (const path of ['dev/index.html', 'preview/index.html', 'v/1.0.0/index.html']) {
    await writeFile(
      resolve(distRoot, path),
      '<html><body data-pagefind-body><h1>Non-canonical</h1></body></html>',
    );
  }
  return docsRoot;
}

function fakePagefind(indexed) {
  return {
    async createIndex() {
      return {
        errors: [],
        index: {
          async addHTMLFile(page) {
            indexed.push(page);
            return { errors: [] };
          },
          async writeFiles({ outputPath }) {
            await mkdir(outputPath, { recursive: true });
            await writeFile(resolve(outputPath, 'pagefind.js'), 'export {};\n');
            await writeFile(resolve(outputPath, 'pagefind-ui.js'), 'window.PagefindUI = class {};\n');
            await writeFile(resolve(outputPath, 'pagefind-ui.css'), '.pagefind-ui {}\n');
            return { errors: [], outputPath };
          },
          async deleteIndex() {},
        },
      };
    },
    async close() {},
  };
}

test('indexes only canonical non-redirect release pages', async (t) => {
  const docsRoot = await fixture(t);
  const indexed = [];

  const result = await buildProductionSearch({
    docsRoot,
    pagefindModule: fakePagefind(indexed),
  });

  assert.equal(result.pages, 2);
  assert.deepEqual(indexed.map((page) => page.url), ['/', '/guide/']);
});

test('rejects an existing production search destination', async (t) => {
  const docsRoot = await fixture(t);
  await mkdir(resolve(docsRoot, 'dist/pagefind'));

  await assert.rejects(
    buildProductionSearch({
      docsRoot,
      pagefindModule: fakePagefind([]),
    }),
    /production search destination already exists/,
  );
});
