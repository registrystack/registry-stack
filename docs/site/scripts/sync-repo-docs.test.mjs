// Unit tests for the Page-type banner stripper (scripts/sync-repo-docs.mjs).
// Run with `npm test` (node --test). The product repos carry a leading
// "> **Page type:** ..." banner under the H1 as a GitHub navigation aid; the
// aggregation pipeline drops it so it does not render on the docs site.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyDocsetMetadataOverrides,
  cloneAtRef,
  frontmatterBlock,
  stripPageTypeBanner,
  validateLastReviewed,
  validateRepoDocsMetadata,
  validateStandardsReferenced,
} from './sync-repo-docs.mjs';

const knownStandards = new Set(['openapi', 'prov-o', 'sd-jwt-vc']);
const docsets = {
  current: 'latest',
  docsets: [
    { id: 'latest', status: 'current' },
    { id: 'v0.8.4', status: 'archived' },
  ],
};

test('strips a leading Page-type banner and its trailing blank line', () => {
  const md = [
    '> **Page type:** Reference · **Product:** Registry Notary · **Audience:** operator',
    '',
    'Real content starts here.',
  ].join('\n');
  assert.equal(stripPageTypeBanner(md), 'Real content starts here.');
});

test('strips a banner that carries a stale Status marker', () => {
  const md = '> **Page type:** Concept · **Status:** draft\n\nBody.';
  assert.equal(stripPageTypeBanner(md), 'Body.');
});

test('skips leading blank lines before the banner (post H1-drop)', () => {
  const md = '\n\n> **Page type:** How-to · **Audience:** integrator\n\nBody.';
  assert.equal(stripPageTypeBanner(md), 'Body.');
});

test('leaves an ordinary leading blockquote intact', () => {
  const md = '> Note: this is a normal callout.\n\nBody.';
  assert.equal(stripPageTypeBanner(md), md);
});

test('returns content unchanged when there is no banner', () => {
  const md = '# Title\n\nBody paragraph.';
  assert.equal(stripPageTypeBanner(md), md);
});

test('validates standards_referenced ids against the standards register', () => {
  assert.deepEqual(
    validateStandardsReferenced(
      ['openapi', 'sd-jwt-vc'],
      'registry-notary: docs/api.md',
      knownStandards,
    ),
    ['openapi', 'sd-jwt-vc'],
  );
});

test('rejects omitted standards_referenced metadata with an explicit empty-list remedy', () => {
  const manifest = {
    repos: {
      'registry-relay': {
        docs: [{ src: 'docs/operator.md', last_reviewed: '2026-07-10' }],
      },
    },
  };

  assert.throws(
    () => validateRepoDocsMetadata(manifest, knownStandards, docsets),
    /registry-relay: docs\/operator\.md: standards_referenced is required; use \[\]/,
  );
});

test('accepts an explicit empty standards_referenced list', () => {
  const manifest = {
    repos: {
      'registry-relay': {
        docs: [
          {
            src: 'docs/operator.md',
            last_reviewed: '2026-07-10',
            standards_referenced: [],
            exclude_docsets: ['v0.8.4'],
          },
        ],
      },
    },
  };

  assert.equal(validateRepoDocsMetadata(manifest, knownStandards, docsets), manifest);
});

test('rejects unknown standards_referenced ids', () => {
  assert.throws(
    () =>
      validateStandardsReferenced(
        ['missing'],
        'registry-relay: docs/api.md',
        knownStandards,
      ),
    /missing.*not in src\/data\/standards.yaml/,
  );
});

test('rejects duplicate standards_referenced ids', () => {
  assert.throws(
    () =>
      validateStandardsReferenced(
        ['openapi', 'openapi'],
        'registry-relay: docs/api.md',
        knownStandards,
      ),
    /duplicated/,
  );
});

test('validates stable last_reviewed values', () => {
  assert.equal(validateLastReviewed('unreviewed', 'entry'), 'unreviewed');
  assert.equal(validateLastReviewed('2024-02-29', 'entry'), '2024-02-29');
  assert.throws(() => validateLastReviewed(undefined, 'entry'), /last_reviewed is required/);
  assert.throws(() => validateLastReviewed('2026-02-30', 'entry'), /valid calendar date/);
});

test('rejects malformed and unknown docset override metadata', () => {
  const manifest = {
    repos: {
      'registry-relay': {
        docs: [
          {
            src: 'docs/provenance.md',
            last_reviewed: '2026-07-10',
            standards_referenced: ['openapi'],
            docset_overrides: [
              {
                docsets: ['missing'],
                standards_referenced: ['prov-o'],
                last_reviewed: 'unreviewed',
                unexpected: true,
              },
            ],
          },
        ],
      },
    },
  };

  assert.throws(
    () => validateRepoDocsMetadata(manifest, knownStandards, docsets),
    /docset_overrides\[0\] has unknown field "unexpected"/,
  );
  delete manifest.repos['registry-relay'].docs[0].docset_overrides[0].unexpected;
  assert.throws(
    () => validateRepoDocsMetadata(manifest, knownStandards, docsets),
    /docset_overrides\[0\] references unknown docset "missing"/,
  );
});

test('accepts frozen metadata for a pending versioned release candidate', () => {
  const candidateDocsets = {
    current: 'latest',
    docsets: [
      { id: 'latest', status: 'current', availability: 'unreleased' },
      { id: 'v0.15.0', status: 'draft', availability: 'candidate' },
    ],
  };
  const manifest = {
    repos: {
      'registry-relay': {
        docs: [
          {
            src: 'docs/provenance.md',
            last_reviewed: '2026-07-10',
            standards_referenced: ['openapi'],
            docset_overrides: [
              {
                docsets: ['v0.15.0'],
                standards_referenced: ['prov-o'],
                last_reviewed: '2026-07-28',
              },
            ],
          },
        ],
      },
    },
  };

  assert.equal(
    validateRepoDocsMetadata(manifest, knownStandards, candidateDocsets),
    manifest,
  );
});

test('requires complete metadata for every applicable archived docset', () => {
  const manifest = {
    repos: {
      'registry-relay': {
        docs: [
          {
            src: 'docs/operator.md',
            last_reviewed: 'unreviewed',
            standards_referenced: [],
          },
        ],
      },
    },
  };

  assert.throws(
    () => validateRepoDocsMetadata(manifest, knownStandards, docsets),
    /missing complete metadata override for archived docset "v0\.8\.4"/,
  );
});

test('uses frozen standards and review metadata for a pinned historical source', () => {
  const manifest = {
    repos: {
      'registry-relay': {
        docs: [
          {
            src: 'docs/provenance.md',
            last_reviewed: '2026-07-10',
            standards_referenced: ['openapi'],
            docset_overrides: [
              {
                docsets: ['v0.8.4'],
                standards_referenced: ['prov-o'],
                last_reviewed: '2025-12-31',
              },
            ],
          },
        ],
      },
    },
  };

  validateRepoDocsMetadata(manifest, knownStandards, docsets);
  applyDocsetMetadataOverrides(manifest, docsets.docsets[1]);
  assert.deepEqual(manifest.repos['registry-relay'].docs[0].standards_referenced, ['prov-o']);
  assert.equal(manifest.repos['registry-relay'].docs[0].last_reviewed, '2025-12-31');
});

test('writes deterministic manifest metadata into generated frontmatter', () => {
  const fields = {
    title: 'API guide',
    description: 'Registry Relay API guide.',
    owner: 'registry-relay',
    doc_type: 'reference',
    last_reviewed: 'unreviewed',
    standards_referenced: ['openapi', 'dcat'],
    editUrl: 'https://example.test/repo/blob/main/docs/api.md',
  };
  const first = frontmatterBlock(fields);
  const second = frontmatterBlock(fields);

  assert.equal(first, second);
  assert.match(first, /status: draft/);
  assert.match(first, /last_reviewed: unreviewed/);
  assert.match(first, /standards_referenced:\n  - openapi\n  - dcat/);
});

test('marks source-reviewed generated pages current', () => {
  const fm = frontmatterBlock({
    title: 'API guide',
    description: 'Registry Relay API guide.',
    owner: 'registry-relay',
    doc_type: 'reference',
    last_reviewed: '2026-07-10',
    standards_referenced: [],
    editUrl: 'https://example.test/repo/blob/main/docs/api.md',
  });

  assert.match(fm, /status: current/);
});

// cloneAtRef retries only the network `git fetch` step (never the surrounding
// init/remote-add/checkout) via scripts/git-fetch-retry.mjs. These tests fake
// the git executor so they run offline and instantly; the retry-and-stderr-
// bounding policy itself is covered exhaustively in git-fetch-retry.test.mjs.

test('cloneAtRef retries a transient fetch failure and succeeds within the retry budget', async () => {
  const dest = await mkdtemp(join(tmpdir(), 'sync-repo-docs-test-'));
  try {
    let fetchCalls = 0;
    const invoked = [];
    const fakeRun = async (command, args) => {
      invoked.push(args[0]);
      if (args[0] === 'fetch') {
        fetchCalls += 1;
        if (fetchCalls < 2) {
          const error = new Error('Command failed: git fetch --quiet --depth 1 origin deadbeef');
          error.stderr = 'fatal: the remote end hung up unexpectedly';
          throw error;
        }
      }
      return { stdout: '', stderr: '' };
    };

    await cloneAtRef('demo-repo', 'https://example.test/demo.git', 'deadbeef', dest, {
      run: fakeRun,
      retryOptions: { sleep: async () => {} },
    });

    assert.equal(fetchCalls, 2);
    // init and remote-add each ran once; only fetch (the network step) retried.
    assert.deepEqual(invoked, ['init', 'remote', 'fetch', 'fetch', 'checkout']);
  } finally {
    await rm(dest, { recursive: true, force: true });
  }
});
