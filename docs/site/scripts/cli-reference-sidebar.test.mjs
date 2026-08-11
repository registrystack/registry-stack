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
  const [group] = cliReferenceSidebar(index);
  assert.equal(group.label, 'Command-line interfaces');
  assert.deepEqual(
    group.items.map((item) => item.slug),
    [
      'reference/cli',
      'reference/cli/relay',
      'reference/cli/relayctl',
      'reference/cli/evidence',
      'reference/cli/evidencectl',
      'reference/cli/mint',
      'reference/cli/evidence-oid4vci',
    ],
  );
});
