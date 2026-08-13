import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';

import { checkNotarySurface, findNotaryMentions } from './check-notary-surface.mjs';

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

    const findings = await findNotaryMentions(root);
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

// The light-touch pass framed each mention as retired. The final sweep goes
// further: an adopter meets a product whose name is gone, so a current page
// carries no retirement note at all.
test('rejects a current page that names Notary only to say it is retired', async () => {
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

    const findings = await findNotaryMentions(root);
    assert.deepEqual(
      findings.map(({ line }) => line),
      [5, 8],
    );
  });
});

// The identifier outlived the product: a frozen schema, a validator, and a
// pinned image name still spell it. A page documenting one of those has to be
// able to write it down.
test('accepts a shipped identifier written as code', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'spec/rs-op-posture.mdx',
      'status: draft',
      [
        'A document declares `component` as exactly one of `registry-relay` and',
        '`registry-notary`, the retired component whose shape the frozen v1',
        'contract still models.',
        '',
        '| `registry-notary` | `notary` | `relay` |',
      ].join('\n'),
    );

    assert.deepEqual(await findNotaryMentions(root), []);
    await assert.doesNotReject(checkNotarySurface(root));
  });
});

test('rejects a block that pairs a shipped identifier with the product name', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'reference/errors.mdx',
      'status: current',
      '| The offering is not `registry-notary`, and Registry Notary is retired. |',
    );

    assert.deepEqual(
      (await findNotaryMentions(root)).map(({ path }) => path),
      ['src/content/docs/reference/errors.mdx'],
    );
  });
});

// A specification's version table is that document's own history, held to the
// same rule as the changelog and the decision records.
test('accepts a specification version-history row', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'spec/rs-sec-g.mdx',
      'status: draft',
      [
        '| Version | Date | Status | Change |',
        '| --- | --- | --- | --- |',
        '| 0.5.0 | 2026-08-03 | draft | Registry Notary is retired. Removed Section 7. |',
      ].join('\n'),
    );

    assert.deepEqual(await findNotaryMentions(root), []);
  });
});

test('skips the marked past and unpublished pages', async () => {
  await withSite(async (root) => {
    const claim = 'Registry Notary issues credentials through OID4VCI.';
    await writePage(root, 'unpublished.mdx', 'status: current\ndraft: true', claim);
    await writePage(root, 'old.mdx', 'status: historical', claim);
    await writePage(root, 'superseded.mdx', 'status: deprecated', claim);
    await writePage(root, 'changelog.md', 'status: current', claim);
    await writePage(root, 'decisions/rename-2026-05-23.mdx', 'status: current', claim);

    assert.deepEqual(await findNotaryMentions(root), []);
  });
});

// The mirrored crate docs are published at /products/<repo>/<page>/ and are as
// current as any authored page. An adopter reading the Relay runbook is on the
// product surface, so the source under `crates/` is held to the same rule.
test('holds a page mirrored from a crate doc to the same rule', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'products/registry-relay/ops.md',
      'status: current',
      'Use Registry Notary for credential issuance and signing-key operations.',
    );

    assert.deepEqual(
      (await findNotaryMentions(root)).map(({ path }) => path),
      ['src/content/docs/products/registry-relay/ops.md'],
    );
  });
});

// Editing a frozen contract needs a recorded re-approval, not a docs pass, so
// the checker cannot ask for one.
test('skips a page mirrored from a frozen Evidence Version 1 contract', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'products/registry-evidence/concept.md',
      [
        'status: draft',
        'editUrl: https://github.com/registrystack/registry-stack/blob/HEAD/products/evidence/CONCEPT.md',
      ].join('\n'),
      'Evidence is not a rewrite or reduced configuration of Registry Notary.',
    );

    assert.deepEqual(await findNotaryMentions(root), []);
  });
});

// A request example has to show the wire, and the wire still spells the
// identifier. The rule is the same one code spans get.
test('accepts a shipped identifier inside a fenced code block', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'products/registry-relay/api.mdx',
      'status: current',
      [
        'Execute only after the calling workload has pinned that contract:',
        '',
        '```http',
        'POST /v1/consultations/person-status/execute',
        'Registry-Notary-Evaluation-Id: 01JYZZZZZZZZZZZZZZZZZZZZZZ',
        '```',
      ].join('\n'),
    );

    assert.deepEqual(await findNotaryMentions(root), []);
    await assert.doesNotReject(checkNotarySurface(root));
  });
});

// A diagram is not code: its participant and message labels are the page's
// prose, and a reader meets the product name there exactly as in a sentence.
test('rejects a mermaid diagram that names the product', async () => {
  await withSite(async (root) => {
    await writePage(
      root,
      'products/registry-relay/client-integration.mdx',
      'status: current',
      [
        '```mermaid',
        'sequenceDiagram',
        '  participant Notary as Registry Notary',
        '  Client->>Notary: Submit claim or evidence',
        '```',
      ].join('\n'),
    );

    assert.deepEqual(
      (await findNotaryMentions(root)).map(({ line, excerpt }) => [line, excerpt]),
      [[6, 'sequenceDiagram']],
    );
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

      const findings = await findNotaryMentions(root);
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

    const findings = await findNotaryMentions(root);
    assert.deepEqual(findings.map(({ path }) => path), [
      'src/content/docs/operate/backup-and-restore.mdx',
      'src/content/docs/operate/single-node-compose-behind-proxy.mdx',
    ]);
  });
});
