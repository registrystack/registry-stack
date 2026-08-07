import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

import {
  checkCurrentDocCutover,
  findRemovedSurfaces,
} from './check-current-doc-cutover.mjs';

async function writePage(root, relative, frontmatter, body) {
  const path = resolve(root, 'src/content/docs', relative);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `---\n${frontmatter}\n---\n\n${body}\n`);
}

async function withSite(run) {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-doc-cutover-'));
  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('rejects every removed command family in a current published page', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'verify/index.mdx',
      'status: current',
      [
        '`registryctl start`',
        '`registryctl authoring reference`',
        '`registryctl init --from http`',
        '`registryctl test --live`',
        '`REGISTRY_STACK_LIVE_BASE_URL`',
        'Generate a Bruno collection.',
      ].join('\n'),
    );

    const findings = await findRemovedSurfaces(root);
    assert.deepEqual(
      findings.map(({ surface }) => surface),
      [
        'removed top-level command',
        'removed top-level command',
        'removed initializer',
        'removed live test',
        'removed live-test environment',
        'removed Bruno surface',
      ],
    );
    await assert.rejects(
      checkCurrentDocCutover(root),
      /src\/content\/docs\/verify\/index\.mdx:5: removed top-level command/,
    );
  });
});

test('allows removed names in draft, historical, and sealed history pages', async () => {
  await withSite(async (root) => {
    await writePage(root, 'draft.mdx', 'status: draft\ndraft: true', '`registryctl start`');
    await writePage(root, 'history.mdx', 'status: historical', '`registryctl start`');
    await writePage(root, 'changelog.mdx', 'status: current', '`registryctl start`');
    await writePage(
      root,
      'products/example/release-notes.mdx',
      'status: current',
      '`registryctl preflight`',
    );
    await writePage(root, 'current.mdx', 'status: current', '`registryctl dev`');

    assert.deepEqual(await findRemovedSurfaces(root), []);
    await assert.doesNotReject(checkCurrentDocCutover(root));
  });
});

test('does not mistake 1.0 nested commands for removed top-level commands', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'current.mdx',
      'status: current',
      [
        '`registryctl dev status`',
        '`registryctl dev logs`',
        '`registryctl dev smoke`',
        '`registryctl review compare`',
        '`registryctl trust bundle sign`',
        '`registryctl tooling diagnostics`',
      ].join('\n'),
    );

    assert.deepEqual(await findRemovedSurfaces(root), []);
  });
});
