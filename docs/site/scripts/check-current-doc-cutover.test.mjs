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
        '```sh',
        'registryctl start',
        '```',
        '',
        'Run `registryctl authoring reference` to regenerate it.',
        '`registry-relay init`',
        '`REGISTRY_STACK_LIVE_BASE_URL`',
        'Generate a Bruno collection.',
      ].join('\n'),
    );

    const findings = await findRemovedSurfaces(root);
    assert.deepEqual(
      findings.map(({ surface }) => surface),
      [
        'removed adopter tool command',
        'removed adopter tool command',
        'removed initializer',
        'removed live-test environment',
        'removed Bruno surface',
      ],
    );
    await assert.rejects(
      checkCurrentDocCutover(root),
      /src\/content\/docs\/verify\/index\.mdx:6: removed adopter tool command/,
    );
  });
});

test('checks generated Markdown pages alongside authored MDX pages', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'products/registry-relay/generated.md',
      'status: current',
      ['```sh', 'registryctl start', '```'].join('\n'),
    );
    await writePage(root, 'reference/current.mdx', 'status: current', '`relayctl check`');

    assert.deepEqual(
      (await findRemovedSurfaces(root)).map(({ path, surface }) => ({ path, surface })),
      [
        {
          path: 'src/content/docs/products/registry-relay/generated.md',
          surface: 'removed adopter tool command',
        },
      ],
    );
  });
});

// The tool is retired, so a current page has to be able to say that it is. The
// check exists to stop a page telling a reader to run it, not to stop a page
// naming it.
test('separates a prescriptive registryctl command from naming the retired tool', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'reference/deprecation-policy.mdx',
      'status: current',
      [
        '`registryctl` was retired at v0.19.0 and `relayctl` replaced it.',
        'registryctl was retired at v0.19.0.',
        'See [Relay V1 and registryctl retirement]' +
          '(../../decisions/relay-v1-and-registryctl-retirement-2026-08-11/).',
        '`registryctl trust bundle sign` was Relay V1 tooling; Relay V2 has no',
        'equivalent command.',
        'The retired diagnostic catalog came from `registryctl tooling diagnostics`.',
      ].join('\n'),
    );

    assert.deepEqual(await findRemovedSurfaces(root), []);
    await assert.doesNotReject(checkCurrentDocCutover(root));
  });

  await withSite(async (root) => {
    await writePage(
      root,
      'operate/index.mdx',
      'status: current',
      ['```sh', '$ registryctl trust bundle sign', '```'].join('\n'),
    );

    assert.deepEqual(
      (await findRemovedSurfaces(root)).map(({ line, surface, match }) => ({
        line,
        surface,
        match,
      })),
      [{ line: 6, surface: 'removed adopter tool command', match: '$ registryctl' }],
    );
  });
});

test('allows removed names in draft, historical, and sealed history pages', async () => {
  await withSite(async (root) => {
    const command = ['```sh', 'registryctl start', '```'].join('\n');
    await writePage(root, 'draft.mdx', 'status: draft\ndraft: true', command);
    await writePage(root, 'history.mdx', 'status: historical', command);
    await writePage(root, 'changelog.mdx', 'status: current', command);
    await writePage(
      root,
      'products/example/release-notes.md',
      'status: current',
      ['```sh', 'registryctl preflight', '```'].join('\n'),
    );
    await writePage(root, 'current.mdx', 'status: current', '`relayctl check`');

    assert.deepEqual(await findRemovedSurfaces(root), []);
    await assert.doesNotReject(checkCurrentDocCutover(root));
  });
});

test('accepts the Relay V2 command surface', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'current.mdx',
      'status: current',
      [
        '`relayctl init`',
        '`relayctl inspect`',
        '`relayctl check`',
        '`relayctl generate`',
        '`relayctl test`',
        '`relayctl diff`',
        '`relayctl package`',
        '`relay serve --runtime runtime.yaml`',
        '`relay healthcheck --url http://127.0.0.1:8080/health`',
      ].join('\n'),
    );

    assert.deepEqual(await findRemovedSurfaces(root), []);
  });
});
