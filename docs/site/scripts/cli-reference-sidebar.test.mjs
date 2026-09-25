import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';

import { cliReferenceSidebar } from '../src/lib/cli-reference-sidebar.mjs';

const page = (title) => `---\ntitle: ${title}\n---\n`;
const draftPage = (title) => `---\ntitle: ${title}\ndraft: true\n---\n`;

test('pinned docsets expose CLI navigation only when they contain its index', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-cli-sidebar-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const index = resolve(root, 'index.mdx');

  assert.deepEqual(cliReferenceSidebar(index), []);

  // A catalog that predates a binary contains no page for it, so the binary
  // takes no seat and the navigation stays true to what the docset publishes.
  await writeFile(index, page('CLI reference'));
  await writeFile(resolve(root, 'evidence.mdx'), page('evidence command reference'));
  assert.deepEqual(
    cliReferenceSidebar(index)[0].items.map((item) => item.slug),
    ['reference/cli', 'reference/cli/evidence'],
  );

  await writeFile(index, draftPage('CLI reference'));
  assert.deepEqual(
    cliReferenceSidebar(index),
    [],
    'Starlight draft entries must not remain in the published sidebar',
  );
});

test('seats every published command page in command order', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-cli-sidebar-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const index = resolve(root, 'index.mdx');

  await writeFile(index, page('CLI reference'));
  await writeFile(resolve(root, 'breg.mdx'), page('breg command reference'));
  await writeFile(resolve(root, 'bregctl.mdx'), page('bregctl command reference'));
  await mkdir(resolve(root, 'bregctl/data'), { recursive: true });
  await writeFile(resolve(root, 'bregctl/data.mdx'), page('bregctl data command reference'));
  await writeFile(resolve(root, 'bregctl/data/import.mdx'), page('bregctl data import'));
  await writeFile(resolve(root, 'bregctl/data/export.mdx'), page('bregctl data export'));
  await writeFile(resolve(root, 'bregctl/check.mdx'), page('bregctl check command reference'));
  // A draft page is absent from the built site, so it must take no seat.
  await writeFile(resolve(root, 'bregctl/doctor.mdx'), draftPage('bregctl doctor'));

  const [group] = cliReferenceSidebar(index);

  assert.equal(group.label, 'CLI commands');
  assert.equal(group.collapsed, true);
  assert.deepEqual(group.items, [
    { label: 'Overview', slug: 'reference/cli' },
    { label: 'breg', slug: 'reference/cli/breg' },
    { label: 'bregctl', slug: 'reference/cli/bregctl' },
    { label: 'bregctl check', slug: 'reference/cli/bregctl/check' },
    { label: 'bregctl data', slug: 'reference/cli/bregctl/data' },
    { label: 'bregctl data export', slug: 'reference/cli/bregctl/data/export' },
    { label: 'bregctl data import', slug: 'reference/cli/bregctl/data/import' },
  ]);
});
