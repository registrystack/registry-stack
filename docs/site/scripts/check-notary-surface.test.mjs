import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

import { checkNotarySurface, findUnframedNotaryMentions } from './check-notary-surface.mjs';

async function writePage(root, relative, frontmatter, body) {
  const path = resolve(root, 'src/content/docs', relative);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `---\n${frontmatter}\n---\n\n${body}\n`);
}

async function withSite(run) {
  const root = await mkdtemp(resolve(tmpdir(), 'registry-notary-surface-'));
  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('rejects a current page that describes Notary as a product to use', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'explanation/architecture.mdx',
      'status: current',
      [
        'Registry Notary evaluates claims from compiler-pinned Relay',
        'consultations and issues credentials.',
        '',
        '| Evidence Gateway | A caller needs a status. | Registry Notary |',
      ].join('\n'),
    );

    const findings = await findUnframedNotaryMentions(root);
    assert.deepEqual(
      findings.map(({ line }) => line),
      [5, 8],
    );
    await assert.rejects(
      checkNotarySurface(root),
      /src\/content\/docs\/explanation\/architecture\.mdx:5: Registry Notary evaluates claims/u,
    );
  });
});

test('accepts a mention that says in the same block that Notary is retired', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'reference/api-stability.mdx',
      'status: current',
      [
        'Registry Notary is retired. The stability promises below cover',
        'Registry Relay, Evidence, and Registry Mint.',
        '',
        '| Registry Notary | Retired | No stability promise remains. |',
      ].join('\n'),
    );

    assert.deepEqual(await findUnframedNotaryMentions(root), []);
    await assert.doesNotReject(checkNotarySurface(root));
  });
});

test('skips the marked past, unpublished pages, and synced product docsets', async () => {
  await withSite(async (root) => {
    const claim = 'Registry Notary issues credentials through OID4VCI.';
    await writePage(root, 'unpublished.mdx', 'status: current\ndraft: true', claim);
    await writePage(root, 'old.mdx', 'status: historical', claim);
    await writePage(root, 'superseded.mdx', 'status: deprecated', claim);
    await writePage(root, 'changelog.mdx', 'status: current', claim);
    await writePage(root, 'decisions/rename-2026-05-23.mdx', 'status: current', claim);
    await writePage(root, 'products/registry-notary/migration.mdx', 'status: current', claim);

    assert.deepEqual(await findUnframedNotaryMentions(root), []);
  });
});

test('holds status: draft pages to the same rule, because they are still published', async () => {
  for (const status of ['status: draft', 'status: current']) {
    await withSite(async (root) => {
      await writePage(
        root,
        'explanation/threat-model.mdx',
        status,
        'Registry Notary owns claim evaluation and credential issuance.',
      );

      const findings = await findUnframedNotaryMentions(root);
      assert.deepEqual(
        findings.map(({ path }) => path),
        ['src/content/docs/explanation/threat-model.mdx'],
        `${status} pages are part of the product surface`,
      );
    });
  }
});

// The light-touch pass is finished, so the checker has no waiver list. Every
// current product-surface page is held to the same rule.
test('holds every current product-surface page, with no page-level waiver', async () => {
  await withSite(async (root) => {
    const claim = 'Registry Notary issues credentials through OID4VCI.';
    await writePage(root, 'operate/backup-and-restore.mdx', 'status: current', claim);
    await writePage(root, 'operate/single-node-compose-behind-proxy.mdx', 'status: current', claim);

    const findings = await findUnframedNotaryMentions(root);
    assert.deepEqual(findings.map(({ path }) => path), [
      'src/content/docs/operate/backup-and-restore.mdx',
      'src/content/docs/operate/single-node-compose-behind-proxy.mdx',
    ]);
  });
});
