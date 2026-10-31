// Guards the docset product gate: a product that a docset does not name in
// src/data/docsets.yaml publishes no page, CLI reference, navigation seat, or
// shared-page region in that docset's build.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
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
import {
  releaseLabelErrors,
  releaseProductVersion,
  UNRELEASED_PRODUCT_VERSION,
} from './docset-release-products.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const docsRoot = resolve(siteRoot, 'src/content/docs');
const withMessaging = { products: { 'registry-messaging': { ref: 'HEAD' } } };
const withoutMessaging = { products: { 'registry-casework': { ref: 'HEAD' } } };
const withBregServices = { products: { 'registry-breg-services': { ref: 'HEAD' } } };
const withoutBregServices = withoutMessaging;
const withCoordinator = { products: { 'registry-coordinator': { ref: 'HEAD' } } };
const withoutCoordinator = withoutMessaging;
const withDocuments = { products: { 'registry-documents': { ref: 'HEAD' } } };
const withoutDocuments = withoutMessaging;
const withAdapter = { products: { 'registry-adapter': { ref: 'HEAD' } } };
const withoutAdapter = withoutMessaging;
const withSchedulingAndRender = {
  products: { 'registry-scheduling': { ref: 'HEAD' }, 'registry-render': { ref: 'HEAD' } },
};
const withoutSchedulingAndRender = withoutMessaging;

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

// Registry Coordinator is unreleased: no release manifest ships its
// coordinator artifact. The latest docset publishes it from main source, and
// no docset archived before v0.41.0 names it.
test('the latest docset publishes Registry Coordinator', () => {
  const manifest = parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
  const latest = manifest.docsets.find((docset) => docset.id === 'latest');
  assert.deepEqual(
    latest.products?.['registry-coordinator'],
    { version: 'main source (unreleased)', ref: 'HEAD' },
  );
});

// The Document Store is unreleased and held out of releases. The latest
// docset publishes it from main source, and no archived docset names it.
test('the latest docset alone publishes the Document Store', () => {
  const manifest = parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
  for (const docset of manifest.docsets) {
    assert.deepEqual(
      docset.products?.['registry-documents'],
      docset.id === 'latest' ? { version: 'main source (unreleased)', ref: 'HEAD' } : undefined,
      docset.id,
    );
  }
});

test('no docset archived before v0.41.0 publishes Registry Coordinator', () => {
  const manifest = parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
  const earlier = manifest.docsets.filter((docset) => {
    const match = /^v0\.(\d+)\.\d+$/.exec(docset.id);
    return match !== null && Number(match[1]) < 41;
  });
  assert.ok(earlier.length > 0, 'docsets.yaml must keep archived docsets');
  for (const docset of earlier) {
    assert.equal(docset.products?.['registry-coordinator'], undefined, docset.id);
  }
});

const repoRoot = resolve(siteRoot, '../..');

function loadReleaseManifests() {
  const manifests = new Map();
  const directory = resolve(repoRoot, 'release/manifests');
  for (const name of readdirSync(directory)) {
    if (!/^registry-stack-.+\.yaml$/.test(name)) continue;
    const manifest = parse(readFileSync(resolve(directory, name), 'utf8'));
    if (manifest?.stack?.source_tag) manifests.set(manifest.stack.source_tag, manifest);
  }
  return manifests;
}

const releaseArtifacts = parse(readFileSync(resolve(siteRoot, 'src/data/docset-release-artifacts.yaml'), 'utf8'));

// Release preparation labels a product the selected manifest does not ship
// `main source (unreleased)`, as the latest docset does. Docsets archived
// before applies_from are frozen as published.
test('no archived docset labels a product with a release version its manifest does not ship', () => {
  const docsets = parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
  assert.deepEqual(releaseLabelErrors({ docsets, manifests: loadReleaseManifests(), releaseArtifacts }), []);
});

test('the release label check refuses a release version for an unshipped product', () => {
  const ref = 'a'.repeat(40);
  const manifests = new Map([['v9.0.0', {
    stack: { version: '9.0.0', source_tag: 'v9.0.0', source_ref: ref },
    artifacts: { 'registry-docs': '9.0.0' },
    external: {},
  }]]);
  const docset = (coordinator) => ({ docsets: [{
    id: 'v9.0.0', status: 'archived', availability: 'released',
    products: { 'registry-stack': { version: 'v9.0.0', ref }, 'registry-coordinator': { version: coordinator, ref } },
  }] });
  assert.deepEqual(releaseLabelErrors({ docsets: docset(UNRELEASED_PRODUCT_VERSION), manifests, releaseArtifacts }), []);
  assert.deepEqual(releaseLabelErrors({ docsets: docset('v9.0.0'), manifests, releaseArtifacts }), [
    "docset v9.0.0 labels registry-coordinator 'v9.0.0' but release manifest v9.0.0 ships no coordinator artifact; label it 'main source (unreleased)'",
  ]);
  const unmapped = docset(UNRELEASED_PRODUCT_VERSION);
  unmapped.docsets[0].products['registry-unknown'] = { version: 'v9.0.0', ref };
  assert.deepEqual(releaseLabelErrors({ docsets: unmapped, manifests, releaseArtifacts }), [
    'docset v9.0.0 product registry-unknown names no release artifact in docset-release-artifacts.yaml',
  ]);
});

test('a shipped product label comes from its manifest artifact version', () => {
  const artifacts = { products: { 'registry-discovery': 'discovery' } };
  const manifest = { artifacts: { discovery: '1.4.2' } };

  assert.equal(
    releaseProductVersion('registry-discovery', 'v2.0.0', manifest, artifacts),
    'v1.4.2',
  );
});

test('the release label check leaves docsets before applies_from as published', () => {
  const ref = 'a'.repeat(40);
  const manifests = new Map([['v0.42.0', {
    stack: { version: '0.42.0', source_tag: 'v0.42.0', source_ref: ref },
    artifacts: { 'registry-docs': '0.42.0' },
    external: {},
  }]]);
  const docsets = { docsets: [{
    id: 'v0.42.0', status: 'archived', availability: 'released',
    products: { 'registry-coordinator': { version: 'v0.42.0', ref } },
  }] };
  assert.equal(releaseArtifacts.applies_from, 'v0.43.0');
  assert.deepEqual(releaseLabelErrors({ docsets, manifests, releaseArtifacts }), []);
});

// Registry Scheduling and Registry Render first ship in v0.33.0.
test('no docset archived before v0.33.0 publishes Registry Scheduling or Registry Render', () => {
  const manifest = parse(readFileSync(resolve(siteRoot, 'src/data/docsets.yaml'), 'utf8'));
  const earlier = manifest.docsets.filter((docset) => {
    const match = /^v0\.(\d+)\.\d+$/.exec(docset.id);
    return match !== null && Number(match[1]) < 33;
  });
  assert.ok(earlier.length > 0, 'docsets.yaml must keep archived docsets');
  for (const docset of earlier) {
    assert.equal(docset.products?.['registry-scheduling'], undefined, docset.id);
    assert.equal(docset.products?.['registry-render'], undefined, docset.id);
  }
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
    '/explanation/how-messaging-works/',
    '/configure/messaging/',
    '/operate/messaging/',
    '/reference/messaging-configuration/',
    '/reference/apis/registry-messaging/',
  ]);
  assert.deepEqual(productRoutes('registry-breg-services'), ['/configure/breg-mcp/']);
  assert.deepEqual(productRoutes('registry-scheduling'), [
    '/start/scheduling/',
    '/tutorials/first-scheduling/',
    '/explanation/how-scheduling-works/',
    '/configure/scheduling/',
    '/operate/scheduling/',
    '/reference/scheduling-configuration/',
    '/reference/apis/registry-scheduling/',
  ]);
  assert.deepEqual(productRoutes('registry-render'), [
    '/start/registry-render/',
    '/tutorials/first-render-document/',
    '/explanation/render-determinism/',
    '/operate/registry-render/',
    '/reference/render-configuration/',
  ]);
  assert.deepEqual(productRoutes('registry-coordinator'), [
    '/start/coordinator/',
    '/explanation/how-coordinator-works/',
    '/configure/coordinator/',
    '/operate/coordinator/',
    '/reference/coordinator-configuration/',
    '/reference/apis/registry-coordinator/',
  ]);
  assert.deepEqual(productRoutes('registry-documents'), [
    '/start/documents/',
    '/tutorials/first-documents/',
    '/operate/documents/',
    '/reference/documents-configuration/',
    '/reference/apis/registry-documents/',
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
  assert.deepEqual(omittedCliBinaries(withoutMessaging), [
    'breg-mcp', 'breg-review', 'scheduling', 'schedulingctl', 'registry-render',
    'messaging', 'messagingctl', 'coordinator', 'coordinatorctl', 'documents', 'documentsctl',
    'adapter', 'adapterctl',
  ]);
  assert.deepEqual(omittedCliBinaries(withMessaging), [
    'breg-mcp', 'breg-review', 'scheduling', 'schedulingctl', 'registry-render', 'coordinator', 'coordinatorctl', 'documents', 'documentsctl',
    'adapter', 'adapterctl',
  ]);
});

test('drops Registry Scheduling\'s and Registry Render\'s pages and CLI references from the docs collection', () => {
  for (const id of [
    ...PRODUCT_PAGES['registry-scheduling'],
    ...PRODUCT_PAGES['registry-render'],
    'reference/cli/scheduling',
    'reference/cli/scheduling/serve',
    'reference/cli/schedulingctl',
    'reference/cli/schedulingctl/package',
    'reference/cli/registry-render',
    'reference/cli/registry-render/render',
  ]) {
    assert.equal(isEntryGatedOut(id, withoutSchedulingAndRender), true, id);
    assert.equal(isEntryGatedOut(id, withSchedulingAndRender), false, id);
  }
  for (const id of ['index', 'reference/apis', 'reference/cli/schedulingx', 'start/casework']) {
    assert.equal(isEntryGatedOut(id, withoutSchedulingAndRender), false, id);
  }
  assert.deepEqual(omittedCliBinaries(withSchedulingAndRender), [
    'breg-mcp', 'breg-review', 'messaging', 'messagingctl', 'coordinator', 'coordinatorctl', 'documents', 'documentsctl',
    'adapter', 'adapterctl',
  ]);
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
  assert.deepEqual(omittedCliBinaries(withBregServices), [
    'scheduling', 'schedulingctl', 'registry-render', 'messaging', 'messagingctl', 'coordinator', 'coordinatorctl', 'documents', 'documentsctl',
    'adapter', 'adapterctl',
  ]);
});

test('drops Registry Coordinator\'s pages and CLI references from the docs collection', () => {
  for (const id of [
    ...PRODUCT_PAGES['registry-coordinator'],
    'reference/cli/coordinator',
    'reference/cli/coordinatorctl',
    'reference/cli/coordinatorctl/start',
  ]) {
    assert.equal(isEntryGatedOut(id, withoutCoordinator), true, id);
    assert.equal(isEntryGatedOut(id, withCoordinator), false, id);
  }
  for (const id of ['index', 'reference/apis', 'reference/configuration-files', 'reference/cli/coordinatorx']) {
    assert.equal(isEntryGatedOut(id, withoutCoordinator), false, id);
  }
  assert.deepEqual(omittedCliBinaries(withCoordinator), [
    'breg-mcp', 'breg-review', 'scheduling', 'schedulingctl', 'registry-render', 'messaging', 'messagingctl',
    'documents', 'documentsctl', 'adapter', 'adapterctl',
  ]);
});

test('drops the Registry Adapter\'s CLI references from the docs collection', () => {
  for (const id of [
    'reference/cli/adapter',
    'reference/cli/adapter/serve',
    'reference/cli/adapterctl',
    'reference/cli/adapterctl/check',
  ]) {
    assert.equal(isEntryGatedOut(id, withoutAdapter), true, id);
    assert.equal(isEntryGatedOut(id, withAdapter), false, id);
  }
  for (const id of ['index', 'reference/cli', 'reference/configuration-files', 'reference/cli/adapterx']) {
    assert.equal(isEntryGatedOut(id, withoutAdapter), false, id);
  }
  assert.ok(!omittedCliBinaries(withAdapter).includes('adapterctl'));
});

test('drops the Document Store\'s pages and CLI references from the docs collection', () => {
  for (const id of [
    ...PRODUCT_PAGES['registry-documents'],
    'reference/cli/documents',
    'reference/cli/documentsctl',
    'reference/cli/documentsctl/package',
  ]) {
    assert.equal(isEntryGatedOut(id, withoutDocuments), true, id);
    assert.equal(isEntryGatedOut(id, withDocuments), false, id);
  }
  for (const id of ['index', 'reference/apis', 'reference/glossary', 'reference/cli/documentsx']) {
    assert.equal(isEntryGatedOut(id, withoutDocuments), false, id);
  }
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
    // Native authoring no longer describes the separately deployed citizen services.
    if (page !== 'configure/breg.mdx') {
      assert.match(source, /<DocsetProduct product="registry-breg-services">/);
    }
    const resolved = resolveDocsetProductRegions(source, withoutBregServices);
    assert.doesNotMatch(resolved, /DocsetProduct/, 'every region must be closed and unnested');
    assert.doesNotMatch(resolved, /breg-mcp|breg-review|first-citizen-mcp|citizen chat assistant|citizen gateway|review page/i);
    assert.doesNotMatch(resolveDocsetProductRegions(source, withBregServices), /DocsetProduct/);
  });
}

// A docset that does not publish the Document Store keeps no link to its
// pages and no description of it on the shared pages.
for (const page of ['index.mdx', 'reference/apis/index.mdx', 'reference/client-api.mdx', 'reference/configuration-files.mdx']) {
  test(`${page} mentions the Document Store only inside DocsetProduct regions`, () => {
    const source = readFileSync(resolve(docsRoot, page), 'utf8');
    assert.match(source, /<DocsetProduct product="registry-documents">/);
    const resolved = resolveDocsetProductRegions(source, withoutDocuments);
    assert.doesNotMatch(resolved, /DocsetProduct product="registry-documents"/, 'every region must be closed and unnested');
    assert.doesNotMatch(resolved, /Document Store|documentsctl|registry-documents-client|start\/documents|apis\/documents|documents-configuration/);
    assert.doesNotMatch(resolveDocsetProductRegions(source, withDocuments), /DocsetProduct product="registry-documents"/);
  });
}

// A docset that does not publish Registry Coordinator keeps no link to its
// pages and no description of it on the shared pages.
for (const page of ['index.mdx', 'reference/apis/index.mdx', 'reference/configuration-files.mdx']) {
  test(`${page} mentions Registry Coordinator only inside DocsetProduct regions`, () => {
    const source = readFileSync(resolve(docsRoot, page), 'utf8');
    assert.match(source, /<DocsetProduct product="registry-coordinator">/);
    const resolved = resolveDocsetProductRegions(source, withoutCoordinator);
    assert.doesNotMatch(resolved, /DocsetProduct product="registry-coordinator"/, 'every region must be closed and unnested');
    assert.doesNotMatch(resolved, /coordinator/i);
    assert.doesNotMatch(resolveDocsetProductRegions(source, withCoordinator), /DocsetProduct product="registry-coordinator"/);
  });
}
