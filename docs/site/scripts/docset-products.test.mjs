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

// Registry Messaging is merged but not released: until an activation change
// adds it to the latest docset, nothing published may describe it.
test('the latest docset does not publish Registry Messaging', () => {
  const manifest = parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
  const latest = manifest.docsets.find((docset) => docset.id === 'latest');
  assert.ok(latest, 'docsets.yaml must declare the latest docset');
  assert.equal(latest.products?.['registry-messaging'], undefined);
  assert.equal(selectedDocset(manifest, { DOCS_DOCSET: 'latest' }), latest);
  assert.equal(selectedDocset(manifest, {}).id, manifest.current);
  assert.throws(() => selectedDocset(manifest, { DOCS_DOCSET: 'missing' }), /"missing" not found/);
});

test('every gated page exists and maps to its route', () => {
  for (const id of PRODUCT_PAGES['registry-messaging']) {
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
  assert.deepEqual(omittedCliBinaries(withoutMessaging), ['messaging', 'messagingctl']);
  assert.deepEqual(omittedCliBinaries(withMessaging), []);
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
for (const page of ['index.mdx', 'reference/client-api.mdx']) {
  test(`${page} mentions Registry Messaging only inside DocsetProduct regions`, () => {
    const source = readFileSync(resolve(docsRoot, page), 'utf8');
    assert.match(source, /<DocsetProduct product="registry-messaging">/);
    const resolved = resolveDocsetProductRegions(source, withoutMessaging);
    assert.doesNotMatch(resolved, /DocsetProduct/, 'every region must be closed and unnested');
    assert.doesNotMatch(resolved, /messaging/i);
    assert.doesNotMatch(resolveDocsetProductRegions(source, withMessaging), /DocsetProduct/);
  });
}
