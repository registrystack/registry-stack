import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';

import { cliReferenceSidebar } from '../src/lib/cli-reference-sidebar.mjs';

test('pinned docsets expose CLI navigation only when they contain its index', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-docs-cli-sidebar-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const index = resolve(root, 'index.mdx');

  assert.deepEqual(cliReferenceSidebar(index), []);

  await writeFile(index, '---\ntitle: CLI reference\n---\n');
  assert.ok(cliReferenceSidebar(index)[0].items.every((item) => !item.slug.includes('breg')));

  await writeFile(index, '---\ntitle: CLI reference\n---\n[breg](./breg/)\n[bregctl](./bregctl/)\n');
  const [group] = cliReferenceSidebar(index);
  assert.equal(group.label, 'Command-line interfaces');
  assert.deepEqual(
    group.items.map((item) => item.slug),
    [
      'reference/cli',
      'reference/cli/breg',
      'reference/cli/bregctl',
      'reference/cli/relay',
      'reference/cli/relayctl',
      'reference/cli/evidence',
      'reference/cli/evidencectl',
      'reference/cli/mint',
      'reference/cli/evidence-oid4vci',
    ],
  );

  await writeFile(index, '---\ntitle: CLI reference\ndraft: true\n---\n');
  assert.deepEqual(
    cliReferenceSidebar(index),
    [],
    'Starlight draft entries must not remain in the published sidebar',
  );
});
