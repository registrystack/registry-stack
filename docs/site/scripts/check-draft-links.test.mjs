import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';

import {
  checkDraftLinks,
  extractLinks,
  headingSlugs,
  routeForDocPath,
} from './check-draft-links.mjs';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'registry-draft-links-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const docsDir = resolve(root, 'docs');
  const publicDir = resolve(root, 'public');
  mkdirSync(join(docsDir, 'tutorials'), { recursive: true });
  mkdirSync(join(publicDir, 'examples'), { recursive: true });
  return { root, docsDir, publicDir };
}

function write(dir, relPath, content) {
  const target = resolve(dir, relPath);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

const frontmatter = (draft) => `---\ntitle: Test\ndraft: ${draft}\n---\n`;

test('routeForDocPath drops the extension and a trailing index segment', () => {
  assert.equal(routeForDocPath('tutorials/evidence-from-breg.mdx'), 'tutorials/evidence-from-breg');
  assert.equal(routeForDocPath('products/registry-evidence/index.md'), 'products/registry-evidence');
  assert.equal(routeForDocPath('index.mdx'), '');
});

test('headingSlugs slugifies headings the way rehype-slug would and dedupes repeats', () => {
  const slugs = headingSlugs('# Ask another question\n\nBody.\n\n## Ask another question\n');
  assert.deepEqual([...slugs], ['ask-another-question', 'ask-another-question-1']);
});

test('extractLinks reads markdown link and image destinations, not code spans', () => {
  const links = extractLinks(
    '[anchor](#section) and [page](../other/) and a `[not-a-link](/nope)` code span.\n',
  );
  assert.deepEqual(links, ['#section', '../other/']);
});

test('passes when every link, in-page anchor, and asset reference on a draft page resolves', (t) => {
  const { docsDir, publicDir } = fixture(t);
  write(
    docsDir,
    'tutorials/evidence-from-breg.mdx',
    `${frontmatter(true)}\n` +
      '## Start Evidence and verify an answer\n\n' +
      'See [the other selector](#ask-another-question-through-the-other-selector) below, ' +
      'the [companion deploy tutorial](../deploy-evidence-from-breg/), and ' +
      '[the starter bundle](../../examples/starter.tar.gz).\n\n' +
      '## Ask another question through the other selector\n\nBody.\n',
  );
  write(
    docsDir,
    'tutorials/deploy-evidence-from-breg.mdx',
    `${frontmatter(true)}\n# Deploy\n\nBody.\n`,
  );
  write(publicDir, 'examples/starter.tar.gz', 'fake archive\n');

  const result = checkDraftLinks({ docsDir, publicDir });
  assert.deepEqual(result.errors, []);
  assert.equal(result.checked, 3);
});

test('reports a missing in-page anchor on a draft page', (t) => {
  const { docsDir, publicDir } = fixture(t);
  write(
    docsDir,
    'tutorials/evidence-from-breg.mdx',
    `${frontmatter(true)}\n[missing](#no-such-heading)\n\n## Real heading\n`,
  );

  const result = checkDraftLinks({ docsDir, publicDir });
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /#no-such-heading has no matching heading/);
});

test('reports a cross-page link to a route with no docs page', (t) => {
  const { docsDir, publicDir } = fixture(t);
  write(docsDir, 'tutorials/evidence-from-breg.mdx', `${frontmatter(true)}\n[gone](../does-not-exist/)\n`);

  const result = checkDraftLinks({ docsDir, publicDir });
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /no docs page for route "tutorials\/does-not-exist"/);
});

test('reports a cross-page fragment that does not match a heading on the target page', (t) => {
  const { docsDir, publicDir } = fixture(t);
  write(docsDir, 'tutorials/evidence-from-breg.mdx', `${frontmatter(true)}\n[gone](../deploy-evidence-from-breg/#no-such-step)\n`);
  write(docsDir, 'tutorials/deploy-evidence-from-breg.mdx', `${frontmatter(true)}\n## A real step\n`);

  const result = checkDraftLinks({ docsDir, publicDir });
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /has no heading matching #no-such-step/);
});

test('reports a static asset reference with no file under public/', (t) => {
  const { docsDir, publicDir } = fixture(t);
  write(docsDir, 'tutorials/evidence-from-breg.mdx', `${frontmatter(true)}\n[bundle](../../examples/missing.tar.gz)\n`);

  const result = checkDraftLinks({ docsDir, publicDir });
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /no asset at public\/examples\/missing\.tar\.gz/);
});

test('ignores links on pages that are not draft', (t) => {
  const { docsDir, publicDir } = fixture(t);
  write(docsDir, 'tutorials/published.mdx', `${frontmatter(false)}\n[gone](../does-not-exist/)\n`);

  const result = checkDraftLinks({ docsDir, publicDir });
  assert.deepEqual(result, { checked: 0, errors: [] });
});
