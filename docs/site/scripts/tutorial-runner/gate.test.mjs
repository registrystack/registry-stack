import assert from 'node:assert/strict';
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { planGate } from './gate.mjs';

const TOOLSETS = {
  breg: { commands: /(^|[^\w-])(bregctl|breg)([^\w-]|$)/mu },
  casework: { commands: /(^|[^\w-])(caseworkctl|casework)([^\w-]|$)/mu, includes: ['breg'] },
  none: {},
};

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
    const plan = await planGate(root, 'breg', TOOLSETS);
    assert.deepEqual(plan.errors, []);
    assert.deepEqual(plan.journeys, [['tutorials/alone'], ['tutorials/first', 'tutorials/second']]);
    assert.deepEqual(plan.skipped, [{ slug: 'start/later', reason: 'needs a production database' }]);
  });
});

test('a page that runs the toolset without declaring how it is tested fails by name', async () => {
  await withDocs({ 'tutorials/new': { body: runsBreg } }, async (root) => {
    const { errors } = await planGate(root, 'breg', TOOLSETS);
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
    const { errors } = await planGate(root, 'breg', TOOLSETS);
    assert.deepEqual(errors, [
      'tutorials/after-skipped.mdx: tutorial_test.after names tutorials/skipped, which is skipped',
      'tutorials/loop-a.mdx: tutorial_test.after leads back to itself',
      'tutorials/loop-b.mdx: tutorial_test.after leads back to itself',
      'tutorials/no-toolset.mdx: tutorial_test needs a toolset',
      'tutorials/orphan.mdx: tutorial_test.after names tutorials/missing, which no page under start/ or tutorials/ replays with breg',
      'tutorials/quiet.mdx declares toolset breg but runs no breg commands; remove its tutorial_test',
      'tutorials/typo.mdx: unknown tutorial_test key aftr (expected toolset, after, skip, or checkout)',
    ]);
  });
});

test('a journey starts in a copy of the checkout only when its first page asks', async () => {
  const pages = {
    'tutorials/first': { frontmatter: 'tutorial_test:\n  toolset: breg\n  checkout: true\n', body: runsBreg },
    'tutorials/second': { frontmatter: 'tutorial_test:\n  toolset: breg\n  after: tutorials/first\n', body: runsBreg },
    'tutorials/alone': { frontmatter: 'tutorial_test:\n  toolset: breg\n', body: runsBreg },
  };
  await withDocs(pages, async (root) => {
    const plan = await planGate(root, 'breg', TOOLSETS);
    assert.deepEqual(plan.errors, []);
    assert.deepEqual(plan.checkout, ['tutorials/first']);
  });
  const refused = {
    'tutorials/first': { frontmatter: 'tutorial_test:\n  toolset: breg\n', body: runsBreg },
    'tutorials/second': { frontmatter: 'tutorial_test:\n  toolset: breg\n  after: tutorials/first\n  checkout: true\n', body: runsBreg },
    'tutorials/odd': { frontmatter: 'tutorial_test:\n  toolset: breg\n  checkout: yes please\n', body: runsBreg },
  };
  await withDocs(refused, async (root) => {
    const { errors } = await planGate(root, 'breg', TOOLSETS);
    assert.deepEqual(errors, [
      'tutorials/odd.mdx: tutorial_test.checkout is true or absent',
      'tutorials/second.mdx: tutorial_test.checkout belongs on tutorials/first, where the journey starts',
    ]);
  });
});

test('a page is refused, not ignored, when it names no known toolset or cannot be read', async () => {
  const pages = {
    'tutorials/typo': { frontmatter: 'tutorial_test:\n  toolset: bregg\n', body: runsBreg },
    'tutorials/broken': { frontmatter: 'tutorial_test: [unclosed\n', body: runsBreg },
    'tutorials/skipped': { frontmatter: 'tutorial_test:\n  toolset: breg\n  skip: offline\n', body: '```sh test-expcet\nbregctl check\n```\n' },
  };
  await withDocs(pages, async (root) => {
    const { errors } = await planGate(root, 'breg', TOOLSETS);
    assert.equal(errors.length, 3, errors.join('\n'));
    assert.match(errors[0], /^tutorials\/broken\.mdx: its frontmatter is not YAML: /u);
    assert.match(errors[1], /^tutorials\/skipped\.mdx: line \d+: unknown annotation test-expcet/u);
    assert.equal(errors[2], 'tutorials/typo.mdx: unknown tutorial_test toolset bregg (expected breg, casework, or none)');
  });
});

test('a page running a toolset is covered only by a toolset that serves it', async () => {
  const pages = {
    'tutorials/both': { frontmatter: 'tutorial_test:\n  toolset: casework\n', body: '```sh\ncaseworkctl init work\nbregctl check project\n```\n' },
    'tutorials/escape': { frontmatter: 'tutorial_test:\n  toolset: none\n', body: runsBreg },
  };
  await withDocs(pages, async (root) => {
    const breg = await planGate(root, 'breg', TOOLSETS);
    assert.deepEqual(breg.errors, [
      'tutorials/escape.mdx runs breg commands but declares toolset none, which does not serve them; declare toolset breg',
    ]);
    const casework = await planGate(root, 'casework', TOOLSETS);
    assert.deepEqual(casework.errors, []);
    assert.deepEqual(casework.journeys, [['tutorials/both']]);
  });
});

test('a page running the toolset under another toolset, or skipping every one of its commands, is refused', async () => {
  const pages = {
    'tutorials/escape': { frontmatter: 'tutorial_test:\n  toolset: none\n', body: runsBreg },
    'tutorials/all-skipped': {
      frontmatter: 'tutorial_test:\n  toolset: breg\n',
      body: '```sh test-skip="reaches the network"\nbregctl --version\n```\n\n```sh\necho hi\n```\n',
    },
  };
  await withDocs(pages, async (root) => {
    const { errors } = await planGate(root, 'breg', TOOLSETS);
    assert.deepEqual(errors, [
      'tutorials/all-skipped.mdx: every breg command on the page is test-skip; replay one, or give tutorial_test a skip reason',
      'tutorials/escape.mdx runs breg commands but declares toolset none, which does not serve them; declare toolset breg',
    ]);
  });
});

test('a skipped page running the commands of two toolsets, neither serving the other, may declare either', async () => {
  const toolsets = { ...TOOLSETS, evidence: { commands: /(^|[^\w./-])(evidencectl|evidence)([^\w-]|$)/mu } };
  const both = '```sh\nbregctl check project\nevidencectl source add\n```\n';
  const pages = {
    'tutorials/composed': { frontmatter: 'tutorial_test:\n  toolset: breg\n  skip: needs a container\n', body: both },
    'tutorials/replayed': { frontmatter: 'tutorial_test:\n  toolset: breg\n', body: both },
  };
  await withDocs(pages, async (root) => {
    const evidence = await planGate(root, 'evidence', toolsets);
    assert.deepEqual(evidence.errors, [
      'tutorials/replayed.mdx runs evidence commands but declares toolset breg, which does not serve them; declare toolset evidence',
    ]);
    assert.deepEqual(evidence.skipped, []);
    const breg = await planGate(root, 'breg', toolsets);
    assert.deepEqual(breg.errors, []);
    assert.deepEqual(breg.skipped, [{ slug: 'tutorials/composed', reason: 'needs a container' }]);
  });
});
