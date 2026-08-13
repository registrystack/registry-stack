// Focused unit tests for the product-document aggregation transformations.
// Run with `npm test` (node --test).

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createMarkdownProcessor } from '@astrojs/markdown-remark';
import remarkGfm from 'remark-gfm';

import {
  applyDocsetMetadataOverrides,
  applyRepoDisplayName,
  frontmatterBlock,
  GENERATED_PRODUCT_DOC_EXTENSION,
  rewriteLinks,
  stripPageTypeBanner,
  validateInertMarkdown,
  validateRenderedMarkdownLinks,
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

test('uses the Evidence Gateway display name in generated product prose', () => {
  const md = [
    'Evidence is the product. Evidence Gateway is already current.',
    'Evidence Type and Core Criterion and Core Evidence Vocabulary keep their formal names.',
    'OOTS uses an Evidence Broker and an Evidence Provider.',
    'Inline `Evidence` and `registry-evidence` are technical identifiers.',
    '[Evidence guidance](https://example.com/Evidence+Exchange) keeps its link target.',
    '',
    '```json',
    '{ "type": "Evidence" }',
    '```',
    '',
    '### Evidence',
    '## Request Evidence',
  ].join('\n');

  const transformed = applyRepoDisplayName(md, 'registry-evidence');
  assert.match(transformed, /Evidence Gateway is the product/);
  assert.doesNotMatch(transformed, /Evidence Gateway Gateway/);
  assert.match(transformed, /Evidence Type and Core Criterion and Core Evidence Vocabulary/);
  assert.match(transformed, /Evidence Broker and an Evidence Provider/);
  assert.match(transformed, /Inline `Evidence` and `registry-evidence`/);
  assert.match(
    transformed,
    /\[Evidence Gateway guidance\]\(https:\/\/example\.com\/Evidence\+Exchange\)/,
  );
  assert.match(transformed, /\{ "type": "Evidence" \}/);
  assert.match(transformed, /### Assertion evidence/);
  assert.match(transformed, /## Request an assertion from Evidence Gateway/);
});

test('leaves other product documentation unchanged', () => {
  const md = 'Evidence is a generic noun here.';
  assert.equal(applyRepoDisplayName(md, 'registry-relay'), md);
});

test('keeps inert HTML comments and fenced examples in plain Markdown', () => {
  const md = [
    '<!-- generated:start -->',
    '',
    '```markdown',
    '<!-- example -->',
    '```',
    '',
    '<!-- generated:end -->',
  ].join('\n');

  assert.equal(validateInertMarkdown(md), md);
});

test('emits plain Markdown so MDX modules and expressions remain inert text', () => {
  const md = [
    "import childProcess from 'node:child_process';",
    "export const value = childProcess.execSync('id');",
    '',
    '{globalThis.process.env}',
  ].join('\n');

  assert.equal(GENERATED_PRODUCT_DOC_EXTENSION, '.md');
  assert.equal(validateInertMarkdown(md), md);
});

test('rejects JSX and active HTML outside code examples', () => {
  for (const hostile of [
    '<Component value={globalThis.process.env} />',
    '<script>globalThis.alert(1)</script>',
    '<img src="x" onerror="globalThis.alert(1)">',
    '<iframe\nsrcdoc="<script>globalThis.alert(1)</script>">',
    '<!DOCTYPE html>',
  ]) {
    assert.throws(
      () => validateInertMarkdown(hostile, 'registry-example: docs/hostile.md'),
      /registry-example: docs\/hostile\.md: raw HTML is not allowed outside code examples/u,
    );
  }
});

test('preserves HTML-shaped text in inline and fenced code examples', () => {
  const md = [
    'Use `<Component />` as a literal example.',
    'A multiline code span starts with `command <input>',
    '  --output <output>` and remains inert.',
    '',
    '```html',
    '<script>example only</script>',
    '```',
  ].join('\n');

  assert.equal(validateInertMarkdown(md), md);
});

test('renders four-space and tab-indented HTML-shaped examples as escaped code', async () => {
  const examples = [
    '    <script>example only</script>',
    '\t<img src=x onerror=alert(1)>',
  ];
  const processor = await createMarkdownProcessor({
    remarkPlugins: [remarkGfm],
    syntaxHighlight: false,
  });

  for (const md of examples) {
    assert.equal(validateInertMarkdown(md), md);
    const rendered = await processor.render(md);
    assert.match(rendered.code, /<pre><code>&#x3C;/u);
    assert.doesNotMatch(rendered.code, /<(?:script|img)\b/u);
  }
});

test('rejects HTML that continues a Markdown paragraph', () => {
  const md = ['Paragraph text', '    <span>active</span>'].join('\n');

  assert.throws(
    () => validateInertMarkdown(md),
    /raw HTML is not allowed outside code examples \(line 2\)/u,
  );
});

test('rejects indented active HTML parsed as GFM footnote content', () => {
  for (const hostile of [
    '<img src=x onerror=globalThis.alert(1)>',
    '<svg onload=globalThis.alert(1)>',
    '<iframe srcdoc="<script>globalThis.alert(1)</script>"></iframe>',
  ]) {
    const md = `[^x]:\n\n    ${hostile}\n\nuse[^x]`;
    assert.throws(
      () => validateInertMarkdown(md),
      /raw HTML is not allowed outside code examples \(line 3\)/u,
    );
  }
});

test('rejects inline HTML comments while allowing standalone comment lines', () => {
  const standalone = '  <!-- generated:marker -->\t';
  assert.equal(validateInertMarkdown(standalone), standalone);
  assert.throws(
    () => validateInertMarkdown('Text <!-- hidden marker -->'),
    /raw HTML is not allowed outside code examples \(line 1\)/u,
  );
});

test('does not let an unmatched code span hide a later HTML block', () => {
  const md = ['An unmatched ` delimiter.', '<script>globalThis.alert(1)</script>'].join('\n');

  assert.throws(
    () => validateInertMarkdown(md),
    /raw HTML is not allowed outside code examples \(line 2\)/u,
  );
});

test('does not let escaped code delimiters or comments hide active HTML', () => {
  for (const md of [
    '\\`<script>globalThis.alert(1)</script>\\`',
    '<!-- ` --> <script>globalThis.alert(1)</script> `',
  ]) {
    assert.throws(
      () => validateInertMarkdown(md),
      /raw HTML is not allowed outside code examples/u,
    );
  }
});

test('preserves ordinary Markdown while rewriting allowlisted links', () => {
  const md = '# Start\n\nRead the **[guide](guide.md)** or visit <https://example.test/docs>.';
  const assetsToCopy = [];
  const rewritten = rewriteLinks(validateInertMarkdown(md), {
    repo: {
      id: 'registry-example',
      remote: 'https://github.com/registrystack/registry-example',
      ref: '0123456789abcdef',
    },
    entry: {
      src: 'docs/index.md',
      dest: 'products/registry-example/index',
    },
    destIndex: new Map([
      ['docs/guide.md', { dest: 'products/registry-example/guide' }],
    ]),
    sourceFileDir: '/repo/docs',
    repoRoot: '/repo',
    assetsToCopy,
  });

  assert.equal(
    rewritten,
    '# Start\n\nRead the **[guide](./guide/)** or visit <https://example.test/docs>.',
  );
  assert.deepEqual(assetsToCopy, []);
});

test('does not manufacture raw HTML from text adjacent to safe autolinks', async () => {
  const md = [
    'A URL stays authorable in <<https://example.test>script> prose.',
    'An email stays authorable in <<docs@example.test>iframe> prose.',
  ].join('\n');

  assert.equal(validateInertMarkdown(md), md);
  const processor = await createMarkdownProcessor({
    remarkPlugins: [remarkGfm],
    syntaxHighlight: false,
  });
  const rendered = await processor.render(md);
  assert.match(rendered.code, /href="https:\/\/example\.test"/u);
  assert.match(rendered.code, /href="mailto:docs@example\.test"/u);
  assert.equal(await validateRenderedMarkdownLinks(md, undefined, processor), md);
});

test('rejects executable reference destinations rendered by Astro', async () => {
  const processor = await createMarkdownProcessor({
    remarkPlugins: [remarkGfm],
    syntaxHighlight: false,
  });
  for (const hostile of [
    '<javascript:alert(1)>',
    '[click][payload]\n\n[payload]: javascript:alert(1)',
    '[click][]\n\n[click]: &#106;avascript&#x3A;alert(1)',
    '[payload]\n\n[payload]: &#x6a;avascript&colon;alert(1)',
  ]) {
    const rendered = await processor.render(hostile);
    assert.match(rendered.code, /href="javascript:alert\(1\)"/u);
    await assert.rejects(
      () => validateRenderedMarkdownLinks(hostile, 'registry-example: docs/hostile.md', processor),
      /registry-example: docs\/hostile\.md: rendered Markdown contains an unsafe a href destination/u,
    );
  }
});

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

test('accepts frozen metadata for versioned draft records', () => {
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

  for (const availability of ['candidate', 'failed']) {
    const versionedDraftDocsets = {
      current: 'latest',
      docsets: [
        { id: 'latest', status: 'current', availability: 'unreleased' },
        { id: 'v0.15.0', status: 'draft', availability },
      ],
    };
    assert.equal(
      validateRepoDocsMetadata(manifest, knownStandards, versionedDraftDocsets),
      manifest,
    );
  }
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
