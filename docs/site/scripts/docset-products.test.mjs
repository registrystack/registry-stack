// Guards the docset product gate: a product that a docset does not name in
// src/data/docsets.yaml publishes no page, CLI reference, navigation seat, or
// shared-page region in that docset's build.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { parse } from 'yaml';

import {
  PRODUCT_PAGES,
  isEntryGatedOut,
  omittedCliBinaries,
  productRoutes,
  remarkDocsetProducts,
  resolveDocsetProductRegions,
  selectedDocset,
} from '../src/lib/docset-products.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const docsRoot = resolve(siteRoot, 'src/content/docs');
const withMessaging = { products: { 'registry-messaging': { ref: 'HEAD' } } };
const withoutMessaging = { products: { 'registry-casework': { ref: 'HEAD' } } };
const withBregServices = { products: { 'registry-breg-services': { ref: 'HEAD' } } };
const withoutBregServices = withoutMessaging;

// Registry Messaging, breg-mcp, and breg-review first ship in v0.38.0
// (release_roster.MESSAGING_FIRST_RELEASE and BREG_SERVICES_FIRST_RELEASE).
// The prepared release docset copies the current docset's products, so the
// latest docset names them, and no docset archived before v0.38.0 does.
test('the latest docset publishes Registry Messaging and the BReg citizen services', () => {
  const manifest = parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
  const latest = manifest.docsets.find((docset) => docset.id === 'latest');
  assert.ok(latest, 'docsets.yaml must declare the latest docset');
  for (const product of ['registry-messaging', 'registry-breg-services']) {
    assert.deepEqual(
      latest.products?.[product],
      { version: 'main source (unreleased)', ref: 'HEAD' },
      product,
    );
  }
  assert.equal(selectedDocset(manifest, { DOCS_DOCSET: 'latest' }), latest);
  assert.equal(selectedDocset(manifest, {}).id, manifest.current);
  assert.throws(() => selectedDocset(manifest, { DOCS_DOCSET: 'missing' }), /"missing" not found/);
});

test('no docset archived before v0.38.0 publishes Registry Messaging or the BReg citizen services', () => {
  const manifest = parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
  const earlier = manifest.docsets.filter((docset) => {
    const match = /^v0\.(\d+)\.\d+$/.exec(docset.id);
    return match !== null && Number(match[1]) < 38;
  });
  assert.ok(earlier.length > 0, 'docsets.yaml must keep archived docsets');
  for (const docset of earlier) {
    assert.equal(docset.products?.['registry-messaging'], undefined, docset.id);
    assert.equal(docset.products?.['registry-breg-services'], undefined, docset.id);
  }
});

test('every gated page exists and maps to its route', () => {
  for (const id of Object.values(PRODUCT_PAGES).flat()) {
    const candidates = ['.md', '.mdx'].map((extension) => resolve(docsRoot, `${id}${extension}`));
    assert.ok(
      candidates.some((path) => {
        try {
          readFileSync(path);
          return true;
        } catch {
          return false;
        }
      }),
      `gated page ${id} has no source; keep PRODUCT_PAGES in step with the content tree`,
    );
  }
  assert.deepEqual(productRoutes('registry-messaging'), [
    '/start/messaging/',
    '/tutorials/first-messaging/',
    '/configure/messaging/',
    '/operate/messaging/',
    '/reference/apis/registry-messaging/',
  ]);
  assert.deepEqual(productRoutes('registry-breg-services'), [
    '/tutorials/first-citizen-mcp/',
    '/configure/breg-mcp/',
    '/operate/breg-mcp/',
  ]);
  assert.deepEqual(productRoutes('registry-unknown'), []);
});

test('drops a gated product\'s pages and CLI references from the docs collection', () => {
  for (const id of [
    ...PRODUCT_PAGES['registry-messaging'],
    'reference/cli/messaging',
    'reference/cli/messaging/serve',
    'reference/cli/messagingctl',
    'reference/cli/messagingctl/migrate',
  ]) {
    assert.equal(isEntryGatedOut(id, withoutMessaging), true, id);
    assert.equal(isEntryGatedOut(id, withMessaging), false, id);
  }
  for (const id of [
    'index',
    'reference/client-api',
    'reference/cli',
    'reference/cli/breg',
    'reference/cli/messagingx',
    'start/casework',
  ]) {
    assert.equal(isEntryGatedOut(id, withoutMessaging), false, id);
  }
  assert.deepEqual(omittedCliBinaries(withoutMessaging), ['breg-mcp', 'breg-review', 'messaging', 'messagingctl']);
  assert.deepEqual(omittedCliBinaries(withMessaging), ['breg-mcp', 'breg-review']);
});

test('drops the citizen services\' pages and CLI references from the docs collection', () => {
  for (const id of [
    ...PRODUCT_PAGES['registry-breg-services'],
    'reference/cli/breg-mcp',
    'reference/cli/breg-mcp/serve',
    'reference/cli/breg-review',
    'reference/cli/breg-review/check',
  ]) {
    assert.equal(isEntryGatedOut(id, withoutBregServices), true, id);
    assert.equal(isEntryGatedOut(id, withBregServices), false, id);
  }
  for (const id of [
    'configure/breg',
    'operate/breg',
    'reference/cli/breg',
    'reference/cli/breg/serve',
    'reference/cli/bregctl',
  ]) {
    assert.equal(isEntryGatedOut(id, withoutBregServices), false, id);
  }
  assert.deepEqual(omittedCliBinaries(withBregServices), ['messaging', 'messagingctl']);
});

function region(type, children, { absent = false, product = 'registry-messaging' } = {}) {
  const attributes = [{ type: 'mdxJsxAttribute', name: 'product', value: product }];
  if (absent) attributes.push({ type: 'mdxJsxAttribute', name: 'absent', value: null });
  return { type, name: 'DocsetProduct', attributes, children };
}

const text = (value) => ({ type: 'text', value });

function tree() {
  return {
    type: 'root',
    children: [
      { type: 'heading', depth: 2, children: [text('Kept')] },
      region('mdxJsxFlowElement', [
        { type: 'heading', depth: 2, children: [text('Registry Messaging')] },
        { type: 'paragraph', children: [text('messaging migrate')] },
      ]),
      region('mdxJsxFlowElement', [{ type: 'paragraph', children: [text('without messaging')] }], {
        absent: true,
      }),
      {
        type: 'paragraph',
        children: [
          text('five '),
          region('mdxJsxTextElement', [text('and messaging ')]),
          region('mdxJsxTextElement', [text('only ')], { absent: true }),
          text('end'),
        ],
      },
    ],
  };
}

test('the remark plugin removes a gated region, headings included, and unwraps a kept one', () => {
  const absentTree = tree();
  remarkDocsetProducts(withoutMessaging)()(absentTree);
  assert.deepEqual(absentTree, {
    type: 'root',
    children: [
      { type: 'heading', depth: 2, children: [text('Kept')] },
      { type: 'paragraph', children: [text('without messaging')] },
      { type: 'paragraph', children: [text('five '), text('only '), text('end')] },
    ],
  });

  const presentTree = tree();
  remarkDocsetProducts(withMessaging)()(presentTree);
  assert.deepEqual(presentTree, {
    type: 'root',
    children: [
      { type: 'heading', depth: 2, children: [text('Kept')] },
      { type: 'heading', depth: 2, children: [text('Registry Messaging')] },
      { type: 'paragraph', children: [text('messaging migrate')] },
      { type: 'paragraph', children: [text('five '), text('and messaging '), text('end')] },
    ],
  });
});

test('the remark plugin resolves nested regions and leaves other JSX alone', () => {
  const card = { type: 'mdxJsxFlowElement', name: 'Card', attributes: [], children: [] };
  const root = {
    type: 'root',
    children: [
      card,
      region('mdxJsxFlowElement', [
        region('mdxJsxFlowElement', [{ type: 'paragraph', children: [text('inner')] }], { absent: true }),
        { type: 'paragraph', children: [text('outer')] },
      ]),
    ],
  };
  remarkDocsetProducts(withMessaging)()(root);
  assert.deepEqual(root.children, [card, { type: 'paragraph', children: [text('outer')] }]);
});

test('the remark plugin rejects a region it cannot resolve', () => {
  const unknownAttribute = region('mdxJsxFlowElement', []);
  unknownAttribute.attributes.push({ type: 'mdxJsxAttribute', name: 'when', value: 'x' });
  const expressionProduct = region('mdxJsxFlowElement', []);
  expressionProduct.attributes[0].value = { type: 'mdxJsxAttributeValueExpression', value: 'p' };
  const missingProduct = { type: 'mdxJsxFlowElement', name: 'DocsetProduct', attributes: [], children: [] };
  for (const [node, message] of [
    [unknownAttribute, /accepts only product and absent/],
    [expressionProduct, /literal product/],
    [missingProduct, /literal product/],
  ]) {
    assert.throws(
      () => remarkDocsetProducts(withMessaging)()({ type: 'root', children: [node] }),
      message,
    );
  }
});

test('the Markdown twin resolves regions the way the rendered page does', () => {
  const body = [
    'Holds <DocsetProduct product="registry-messaging" absent>five</DocsetProduct><DocsetProduct product="registry-messaging">six</DocsetProduct> namespaces.',
    '',
    '<DocsetProduct product="registry-messaging">',
    '',
    '## Registry Messaging',
    '',
    '</DocsetProduct>',
    '',
  ].join('\n');
  assert.equal(resolveDocsetProductRegions(body, withoutMessaging), 'Holds five namespaces.\n\n\n');
  assert.equal(
    resolveDocsetProductRegions(body, withMessaging),
    'Holds six namespaces.\n\n\n\n## Registry Messaging\n\n\n',
  );
});

// Shared pages keep their Messaging text for the activation change, so every
// mention must sit inside a region the gate removes.
for (const page of ['index.mdx', 'reference/client-api.mdx', 'reference/configuration-files.mdx']) {
  test(`${page} mentions Registry Messaging only inside DocsetProduct regions`, () => {
    const source = readFileSync(resolve(docsRoot, page), 'utf8');
    assert.match(source, /<DocsetProduct product="registry-messaging">/);
    const resolved = resolveDocsetProductRegions(source, withoutMessaging);
    assert.doesNotMatch(resolved, /DocsetProduct/, 'every region must be closed and unnested');
    assert.doesNotMatch(resolved, /messaging/i);
    assert.doesNotMatch(resolveDocsetProductRegions(source, withMessaging), /DocsetProduct/);
  });
}

// The same rule for the Base Registry Engine citizen services: a docset that
// does not publish them keeps no link to their pages and no description of them.
for (const page of [
  'configure/breg.mdx',
  'reference/environment-variables.mdx',
  'reference/configuration-files.mdx',
  'changelog.mdx',
]) {
  test(`${page} mentions the citizen services only inside DocsetProduct regions`, () => {
    const source = readFileSync(resolve(docsRoot, page), 'utf8');
    assert.match(source, /<DocsetProduct product="registry-breg-services">/);
    const resolved = resolveDocsetProductRegions(source, withoutBregServices);
    assert.doesNotMatch(resolved, /DocsetProduct/, 'every region must be closed and unnested');
    assert.doesNotMatch(resolved, /breg-mcp|breg-review|first-citizen-mcp|citizen chat assistant|citizen gateway|review page/i);
    assert.doesNotMatch(resolveDocsetProductRegions(source, withBregServices), /DocsetProduct/);
  });
}
