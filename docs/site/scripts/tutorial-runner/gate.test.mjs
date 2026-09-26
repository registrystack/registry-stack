import assert from 'node:assert/strict';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { planGate } from './gate.mjs';

const BREG = /(^|[^\w-])(bregctl|breg)([^\w-]|$)/mu;

async function withDocs(pages, fn) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'tutorial-gate-test.')));
  try {
    for (const [slug, { frontmatter = '', body = '' }] of Object.entries(pages)) {
      await mkdir(join(root, slug, '..'), { recursive: true });
      await writeFile(join(root, `${slug}.mdx`), `---\ntitle: t\n${frontmatter}---\n\n${body}`);
    }
    return await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

const runsBreg = '```sh\nbregctl check project\n```\n';

test('a gate replays each chain of declared pages once, from its first page', async () => {
  const pages = {
    'tutorials/first': { frontmatter: 'tutorial_test:\n  toolset: breg\n', body: runsBreg },
    'tutorials/second': { frontmatter: 'tutorial_test:\n  toolset: breg\n  after: tutorials/first\n', body: runsBreg },
    'tutorials/alone': { frontmatter: 'tutorial_test:\n  toolset: breg\n', body: runsBreg },
    'start/later': { frontmatter: 'tutorial_test:\n  toolset: breg\n  skip: needs a production database\n', body: runsBreg },
    'tutorials/other': { body: '```sh\necho unrelated\n```\n' },
  };
  await withDocs(pages, async (root) => {
    const plan = await planGate(root, 'breg', BREG);
    assert.deepEqual(plan.errors, []);
    assert.deepEqual(plan.journeys, [['tutorials/alone'], ['tutorials/first', 'tutorials/second']]);
    assert.deepEqual(plan.skipped, [{ slug: 'start/later', reason: 'needs a production database' }]);
  });
});

test('a page that runs the toolset without declaring how it is tested fails by name', async () => {
  await withDocs({ 'tutorials/new': { body: runsBreg } }, async (root) => {
    const { errors } = await planGate(root, 'breg', BREG);
    assert.deepEqual(errors, [
      'tutorials/new.mdx runs breg commands but declares no tutorial_test; add tutorial_test with toolset breg, and a skip reason if it cannot be replayed',
    ]);
  });
});

test('declarations that cannot hold are refused', async () => {
  const pages = {
    'tutorials/quiet': { frontmatter: 'tutorial_test:\n  toolset: breg\n', body: '```sh\necho hi\n```\n' },
    'tutorials/orphan': { frontmatter: 'tutorial_test:\n  toolset: breg\n  after: tutorials/missing\n', body: runsBreg },
    'tutorials/skipped': { frontmatter: 'tutorial_test:\n  toolset: breg\n  skip: offline\n', body: runsBreg },
    'tutorials/after-skipped': { frontmatter: 'tutorial_test:\n  toolset: breg\n  after: tutorials/skipped\n', body: runsBreg },
    'tutorials/typo': { frontmatter: 'tutorial_test:\n  toolset: breg\n  aftr: tutorials/skipped\n', body: runsBreg },
    'tutorials/no-toolset': { frontmatter: 'tutorial_test:\n  skip: offline\n', body: runsBreg },
    'tutorials/loop-a': { frontmatter: 'tutorial_test:\n  toolset: breg\n  after: tutorials/loop-b\n', body: runsBreg },
    'tutorials/loop-b': { frontmatter: 'tutorial_test:\n  toolset: breg\n  after: tutorials/loop-a\n', body: runsBreg },
  };
  await withDocs(pages, async (root) => {
    const { errors } = await planGate(root, 'breg', BREG);
    assert.deepEqual(errors, [
      'tutorials/after-skipped.mdx: tutorial_test.after names tutorials/skipped, which is skipped',
      'tutorials/loop-a.mdx: tutorial_test.after leads back to itself',
      'tutorials/loop-b.mdx: tutorial_test.after leads back to itself',
      'tutorials/no-toolset.mdx: tutorial_test needs a toolset',
      'tutorials/orphan.mdx: tutorial_test.after names tutorials/missing, which no page under start/ or tutorials/ replays with breg',
      'tutorials/quiet.mdx declares toolset breg but runs no breg commands; remove its tutorial_test',
      'tutorials/typo.mdx: unknown tutorial_test key aftr (expected toolset, after, or skip)',
    ]);
  });
});
