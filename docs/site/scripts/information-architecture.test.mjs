// Guards the Registry Stack 1.0 product outcomes and their stable entry points.

import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { cliReferenceSidebar } from '../src/lib/cli-reference-sidebar.mjs';
import { omittedCliBinaries, productRoutes } from '../src/lib/docset-products.mjs';
import {
  buildRelayRetirementRedirects,
  RELAY_RETIREMENT,
  RETIRED_RELAY_ROUTES,
} from '../src/lib/relay-retirement-redirects.mjs';
import { flattenSidebarGroups } from '../src/lib/sidebar.mjs';
import { docsetPublishesBregOpenApi, docsetPublishesEvidenceOid4vciOpenApi } from './fetch-openapi.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const configSource = readFileSync(resolve(siteRoot, 'astro.config.mjs'), 'utf8');
const fetchOpenapiSource = readFileSync(resolve(siteRoot, 'scripts/fetch-openapi.mjs'), 'utf8');
const contextSource = configSource.match(/export function resolveDocsetBuildContext[\s\S]*?^}\n/m)?.[0];
const redirectsSource = configSource.match(/export function caseworkRedirects[\s\S]*?^}\n/m)?.[0];
const caseworkRoutesSource = configSource.match(/const caseworkRoutes = \[[\s\S]*?\];/)?.[0];
assert.ok(contextSource && redirectsSource && caseworkRoutesSource,
  'could not isolate Casework docset routing');
const resolveDocsetBuildContext = new Function(
  `${contextSource.replace(/^export /, '')}; return resolveDocsetBuildContext;`,
)();
const caseworkRedirects = new Function(
  `${caseworkRoutesSource}; ${redirectsSource.replace(/^export /, '')}; return caseworkRedirects;`,
)();
const schedulingRedirectsSource = configSource.match(/export function schedulingRedirects[\s\S]*?^}\n/m)?.[0];
const schedulingRoutesSource = configSource.match(/const schedulingRoutes = productRoutes\('registry-scheduling'\);/)?.[0];
assert.ok(schedulingRedirectsSource && schedulingRoutesSource,
  'could not isolate Scheduling docset routing');
const schedulingRedirects = new Function(
  'productRoutes',
  `${schedulingRoutesSource}; ${schedulingRedirectsSource.replace(/^export /, '')}; return schedulingRedirects;`,
)(productRoutes);
const renderRedirectsSource = configSource.match(/export function renderRedirects[\s\S]*?^}\n/m)?.[0];
const renderRoutesSource = configSource.match(/const renderRoutes = productRoutes\('registry-render'\);/)?.[0];
assert.ok(renderRedirectsSource && renderRoutesSource,
  'could not isolate Render docset routing');
const renderRedirects = new Function(
  'productRoutes',
  `${renderRoutesSource}; ${renderRedirectsSource.replace(/^export /, '')}; return renderRedirects;`,
)(productRoutes);
const messagingRedirectsSource = configSource.match(/export function messagingRedirects[\s\S]*?^}\n/m)?.[0];
const messagingRoutesSource = configSource.match(/const messagingRoutes = productRoutes\('registry-messaging'\);/)?.[0];
assert.ok(messagingRedirectsSource && messagingRoutesSource,
  'could not isolate Messaging docset routing');
const messagingRedirects = new Function(
  'productRoutes',
  `${messagingRoutesSource}; ${messagingRedirectsSource.replace(/^export /, '')}; return messagingRedirects;`,
)(productRoutes);
const coordinatorRedirectsSource = configSource.match(/export function coordinatorRedirects[\s\S]*?^}\n/m)?.[0];
const coordinatorRoutesSource = configSource.match(/const coordinatorRoutes = productRoutes\('registry-coordinator'\);/)?.[0];
assert.ok(coordinatorRedirectsSource && coordinatorRoutesSource,
  'could not isolate Coordinator docset routing');
const coordinatorRedirects = new Function(
  'productRoutes',
  `${coordinatorRoutesSource}; ${coordinatorRedirectsSource.replace(/^export /, '')}; return coordinatorRedirects;`,
)(productRoutes);
const bregRewriteRedirectsSource = configSource.match(/export function bregRewriteRedirects[\s\S]*?^}\n/m)?.[0];
const bregRewriteMovesSource = configSource.match(/const bregRewriteMoves = \[[\s\S]*?\n\];/)?.[0];
assert.ok(bregRewriteRedirectsSource && bregRewriteMovesSource,
  'could not isolate the Base Registry Engine rewrite redirects');
const bregRewriteRedirects = new Function(
  `${bregRewriteMovesSource}; ${bregRewriteRedirectsSource.replace(/^export /, '')}; return bregRewriteRedirects;`,
)();
const homepageSource = readFileSync(resolve(siteRoot, 'src/content/docs/index.mdx'), 'utf8');
const sidebarSource = configSource.match(/sidebar: \[([\s\S]*?)\n      \],\n    \}\),/)?.[1];

assert.ok(sidebarSource, 'could not isolate the Starlight sidebar configuration');

// Evaluate the trusted local sidebar expression without loading Astro or
// requiring generated artifacts. Nested product fixtures exercise the actual
// config's flattening; the OpenAPI plugin owns its generated tag hierarchy.
const generatedProducts = new Map(['Manifest', 'Registry Evidence'].map((label) => [
  label,
  {
    label,
    items: [{
      label: 'Guides',
      items: [
        { label: 'Introduction', slug: `products/${label}/intro`, badge: 'Beta' },
        {
          label: 'Details',
          items: [{ label: 'Contract', link: `/products/${label}/contract/`, attrs: { class: 'contract' } }],
        },
      ],
    }],
  },
]));
const apiConfigSource = configSource.match(/starlightOpenAPI\((\[[\s\S]*?\])\),/)?.[1];
assert.ok(apiConfigSource, 'could not isolate the OpenAPI plugin configuration');
// Each product's operations fill their own createOpenAPISidebarGroup()
// placeholder, which the plugin replaces with the generated group. The
// fixture names the base in the generated tag, so two groups with the same
// label never compare equal.
function openApiGroup(base, label) {
  return { label, collapsed: true, items: [{ label: `Generated tag (${base})`, items: [] }] };
}
function openApiSchema(base, group) {
  return { base, schema: `./openapi/${base.slice('reference/apis/'.length)}.openapi.json`,
    sidebar: { group, label: group.label, collapsed: true } };
}
const evidenceOpenApiSidebarGroup = openApiGroup('reference/apis/evidence', 'API operations');
const evidenceOpenApiSchema = openApiSchema('reference/apis/evidence', evidenceOpenApiSidebarGroup);
const evidenceOid4vciOpenApiSidebarGroup = openApiGroup('reference/apis/evidence-oid4vci', 'API operations (wallet delivery)');
const evidenceOid4vciOpenApiSchema = openApiSchema('reference/apis/evidence-oid4vci', evidenceOid4vciOpenApiSidebarGroup);
const caseworkOpenApiSidebarGroup = openApiGroup('reference/apis/casework', 'API operations');
const caseworkOpenApiSchema = openApiSchema('reference/apis/casework', caseworkOpenApiSidebarGroup);
const schedulingOpenApiSidebarGroup = openApiGroup('reference/apis/scheduling', 'API operations');
const schedulingOpenApiSchema = openApiSchema('reference/apis/scheduling', schedulingOpenApiSidebarGroup);
const messagingOpenApiSidebarGroup = openApiGroup('reference/apis/messaging', 'API operations');
const messagingOpenApiSchema = openApiSchema('reference/apis/messaging', messagingOpenApiSidebarGroup);
const coordinatorOpenApiSidebarGroup = openApiGroup('reference/apis/coordinator', 'API operations');
const coordinatorOpenApiSchema = openApiSchema('reference/apis/coordinator', coordinatorOpenApiSidebarGroup);
const bregOpenApiSidebarGroup = openApiGroup('reference/apis/breg', 'API operations (facility template)');
const bregOpenApiSchema = openApiSchema('reference/apis/breg', bregOpenApiSidebarGroup);
// The product groups in the order the sidebar factory takes them; BReg's
// group is a separate parameter.
const productOpenApiSidebarGroups = [
  evidenceOpenApiSidebarGroup,
  evidenceOid4vciOpenApiSidebarGroup,
  caseworkOpenApiSidebarGroup,
  schedulingOpenApiSidebarGroup,
  messagingOpenApiSidebarGroup,
  coordinatorOpenApiSidebarGroup,
];
const openApiSidebarGroups = [...productOpenApiSidebarGroups, bregOpenApiSidebarGroup];
const apiSchemaFactory = new Function(
  'hasEvidenceOid4vciOpenApi',
  'hasBregOpenApi',
  'hasCasework',
  'hasScheduling',
  'hasMessaging',
  'hasCoordinator',
  'evidenceOpenApiSchema',
  'evidenceOid4vciOpenApiSchema',
  'caseworkOpenApiSchema',
  'schedulingOpenApiSchema',
  'messagingOpenApiSchema',
  'coordinatorOpenApiSchema',
  'bregOpenApiSchema',
  `return ${apiConfigSource};`,
);
const apiSchemaArguments = [
  evidenceOpenApiSchema,
  evidenceOid4vciOpenApiSchema,
  caseworkOpenApiSchema,
  schedulingOpenApiSchema,
  messagingOpenApiSchema,
  coordinatorOpenApiSchema,
  bregOpenApiSchema,
];
const apiSchemas = apiSchemaFactory(true, true, true, true, true, true, ...apiSchemaArguments);
assert.ok(apiSchemas.includes(bregOpenApiSchema), 'the current docset registers the BReg OpenAPI schema');
const sidebarFactory = new Function(
  'cliReferenceSidebar',
  'generatedProduct',
  'optionalGeneratedProduct',
  'flattenSidebarGroups',
  'omittedCliBinaries',
  'hasCasework',
  'hasScheduling',
  'hasRender',
  'hasMessaging',
  'hasBregServices',
  'hasCoordinator',
  'selectedDocset',
  'hasBregOpenApi',
  'bregOpenApiSidebarGroup',
  'hasEvidenceOid4vciOpenApi',
  'evidenceOpenApiSidebarGroup',
  'evidenceOid4vciOpenApiSidebarGroup',
  'caseworkOpenApiSidebarGroup',
  'schedulingOpenApiSidebarGroup',
  'messagingOpenApiSidebarGroup',
  'coordinatorOpenApiSidebarGroup',
  `return [${sidebarSource}];`,
);
const sidebarArguments = [
  cliReferenceSidebar,
  (label) => {
    assert.ok(generatedProducts.has(label), `unexpected generated product: ${label}`);
    return generatedProducts.get(label);
  },
  (label) => generatedProducts.get(label) ?? null,
  flattenSidebarGroups,
  omittedCliBinaries,
];
// The whole-site sidebar publishes every product, so every page is seated.
const everyProductDocset = {
  products: {
    'registry-casework': {},
    'registry-scheduling': {},
    'registry-render': {},
    'registry-messaging': {},
    'registry-breg-services': {},
    'registry-coordinator': {},
  },
};
const sidebar = sidebarFactory(...sidebarArguments, true, true, true, true, true, true, everyProductDocset,
  true, bregOpenApiSidebarGroup, true, ...productOpenApiSidebarGroups);

const messagingPageRoutes = [
  '/start/messaging/',
  '/tutorials/first-messaging/',
  '/explanation/how-messaging-works/',
  '/configure/messaging/',
  '/operate/messaging/',
  '/reference/messaging-configuration/',
  '/reference/apis/registry-messaging/',
];
const coordinatorPageRoutes = [
  '/start/coordinator/',
  '/explanation/how-coordinator-works/',
  '/configure/coordinator/',
  '/operate/coordinator/',
  '/reference/coordinator-configuration/',
  '/reference/apis/registry-coordinator/',
];

function section(label) {
  const group = sidebar.find((item) => item.label === label);
  assert.ok(group, `missing sidebar section: ${label}`);
  return group;
}

function topLevelLabels(source) {
  return [...source.matchAll(/^          label: '([^']+)',$/gm)].map((match) => match[1]);
}

function topLevelSection(source, label) {
  const matches = [...source.matchAll(/^          label: '([^']+)',$/gm)];
  const position = matches.findIndex((match) => match[1] === label);
  if (position === -1) return null;
  const start = matches[position].index;
  const end = matches[position + 1]?.index ?? source.length;
  return source.slice(start, end);
}

function hasDocForSlug(slug) {
  return [
    resolve(siteRoot, 'src/content/docs', `${slug}.mdx`),
    resolve(siteRoot, 'src/content/docs', slug, 'index.mdx'),
  ].some((path) => existsSync(path) && !/^draft: true$/m.test(readFileSync(path, 'utf8')));
}

// Every slug the built site publishes from the hand-authored content
// collection, in the form the sidebar uses to address it: `start/breg-quickstart`
// for a leaf file, `configure` for a directory index, and the empty string for
// the homepage. Starlight's `draft: true` is what removes a page from the built
// site, so a draft page is not published and is not expected to be navigable.
//
// Product documentation under `products/` is pulled from the source repos by
// scripts/sync-repo-docs.mjs and seated by scripts/generate-sidebar.mjs, which
// generate-sidebar.test.mjs already pins doc-for-doc against the manifest. It
// is also a build artifact, absent until `npm run generate` runs, so this walk
// skips it rather than asserting on a tree that may not exist.
function publishedSlugs() {
  const root = resolve(siteRoot, 'src/content/docs');
  const slugs = [];

  function walk(directory, prefix) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        if (prefix === '' && entry.name === 'products') continue;
        walk(path, `${prefix}${entry.name}/`);
        continue;
      }
      if (!/\.mdx?$/.test(entry.name)) continue;
      if (/^draft: true$/m.test(readFileSync(path, 'utf8'))) continue;
      const name = entry.name.replace(/\.mdx?$/, '');
      slugs.push(name === 'index' ? prefix.slice(0, -1) : `${prefix}${name}`);
    }
  }

  walk(root, '');
  return slugs.sort();
}

// Every slug the hand-authored sidebar addresses. Three sources feed it,
// because three things put an entry in that array.
function seatedSlugs() {
  const seated = new Set([...sidebarSource.matchAll(/slug: '([^']+)'/g)].map((m) => m[1]));
  // The homepage is seated by route rather than by slug.
  if (/link: '\/'/.test(sidebarSource)) seated.add('');
  // The command-line reference group is spread in from
  // src/lib/cli-reference-sidebar.mjs, so its slugs never appear in the config
  // text. That module returns [] while the generated index carries
  // `draft: true`, which is the same state in which the generated CLI pages are
  // themselves draft and so are not published either.
  //
  // That group seats the index, the binaries, and every subcommand page the
  // docset publishes, which the module reads from the generated tree, so a
  // catalog that adds a command seats it without an edit here.
  for (const group of cliReferenceSidebar()) {
    for (const item of group.items) seated.add(item.slug);
  }
  return seated;
}

// Published pages the sidebar deliberately does not seat, each with the reason
// it is acceptable that it stays unreachable from the navigation.
//
// The sidebar is the whole of this site's navigation: RegistryHeader.astro
// renders a wordmark, search, the docset switcher, a theme selector, and a
// GitHub link, and nothing else. A published page with no seat is reachable
// only by search or by already knowing its URL, so an entry here is a debt,
// not a category. Add one only with the decision that keeps the page
// published, and delete it the moment the page gets a seat.
const UNSEATED_PUBLISHED_PAGES = new Map([]);

function assertOrdered(source, expectations, label) {
  let position = -1;
  for (const expectation of expectations) {
    const next = source.indexOf(expectation, position + 1);
    assert.ok(next > position, `missing or misplaced ${label}: ${expectation}`);
    position = next;
  }
}

// Product names give readers a short, stable place to return to. Start helps
// readers choose a product before they enter its tutorials or references.
test('uses the product navigation in its published order', () => {
  assert.deepEqual(topLevelLabels(sidebarSource), [
    'Start',
    'Registry Evidence',
    'Base Registry Engine',
    'Registry Casework',
    'Registry Scheduling',
    'Registry Render',
    'Registry Messaging',
    'Registry Coordinator',
    'Registry Discovery',
    'Operations',
    'Design',
    'Reference',
  ]);
});

test('selects Casework routes, sidebar, and API from the docset product manifest', () => {
  const docsets = {
    current: 'latest',
    released: 'v0.29.0',
    docsets: [
      { id: 'latest', status: 'current', availability: 'unreleased', path: '/dev/', products: { 'registry-casework': { ref: 'HEAD' }, 'registry-scheduling': { ref: 'HEAD' }, 'registry-render': { ref: 'HEAD' } } },
      // The last archive that predates the OID4VCI supporting service's document.
      { id: 'v0.19.0', status: 'archived', availability: 'released', path: '/v/0.19.0/', products: {} },
      { id: 'v0.29.0', status: 'archived', availability: 'released', path: '/v/0.29.0/', products: {} },
      { id: 'v0.30.0', status: 'archived', availability: 'candidate', path: '/v/0.30.0/', products: { 'registry-casework': { ref: 'v0.30.0' } } },
      // A docset that carries Messaging without Scheduling, so the Messaging
      // operations are not the last of every registered schema.
      // It also carries the Base Registry Engine citizen services.
      { id: 'v0.31.0', status: 'archived', availability: 'candidate', path: '/v/0.31.0/', products: { 'registry-casework': { ref: 'v0.31.0' }, 'registry-messaging': { ref: 'v0.31.0' }, 'registry-breg-services': { ref: 'v0.31.0' } } },
      // A docset that carries the Coordinator after Messaging and without
      // Scheduling, so the Coordinator operations follow a skipped schema.
      { id: 'v0.41.0', status: 'archived', availability: 'candidate', path: '/v/0.41.0/', products: { 'registry-casework': { ref: 'v0.41.0' }, 'registry-messaging': { ref: 'v0.41.0' }, 'registry-coordinator': { ref: 'v0.41.0' } } },
      // The first archive that publishes the Base Registry Engine facility API.
      { id: 'v0.42.0', status: 'archived', availability: 'candidate', path: '/v/0.42.0/', products: {} },
    ],
  };
  for (const [id, env, hasCasework, hasScheduling, hasRender, hasMessaging, hasBregServices, hasCoordinator] of [
    ['latest', {}, true, true, true, false, false, false],
    ['v0.19.0', {}, false, false, false, false, false, false],
    ['v0.29.0', {}, false, false, false, false, false, false],
    ['v0.30.0', {}, true, false, false, false, false, false],
    ['v0.30.0', { DOCS_RELEASED_ARCHIVE: 'true' }, true, false, false, false, false, false],
    ['v0.31.0', {}, true, false, false, true, true, false],
    ['v0.41.0', {}, true, false, false, true, false, true],
    ['v0.42.0', {}, false, false, false, false, false, false],
  ]) {
    const context = resolveDocsetBuildContext(docsets, { DOCS_DOCSET: id, ...env });
    const hasBregOpenApi = docsetPublishesBregOpenApi(context.selectedDocset, docsets.current);
    const hasEvidenceOid4vciOpenApi = docsetPublishesEvidenceOid4vciOpenApi(context.selectedDocset, docsets.current);
    assert.equal(context.hasCasework, hasCasework, id);
    assert.equal(context.hasScheduling, hasScheduling, id);
    assert.equal(context.hasRender, hasRender, id);
    assert.equal(context.hasMessaging, hasMessaging, id);
    assert.equal(context.hasBregServices, hasBregServices, id);
    assert.equal(context.hasCoordinator, hasCoordinator, id);
    const docsetSidebar = sidebarFactory(
      ...sidebarArguments,
      context.hasCasework,
      context.hasScheduling,
      context.hasRender,
      context.hasMessaging,
      context.hasBregServices,
      context.hasCoordinator,
      context.selectedDocset,
      hasBregOpenApi,
      bregOpenApiSidebarGroup,
      hasEvidenceOid4vciOpenApi,
      ...productOpenApiSidebarGroups,
    );
    assert.equal(docsetSidebar.some((item) => item.label === 'Registry Casework'), hasCasework, id);
    assert.equal(docsetSidebar.some((item) => item.label === 'Registry Scheduling'), hasScheduling, id);
    assert.equal(docsetSidebar.some((item) => item.label === 'Registry Render'), hasRender, id);
    assert.equal(docsetSidebar.some((item) => item.label === 'Registry Messaging'), hasMessaging, id);
    assert.equal(docsetSidebar.some((item) => item.label === 'Registry Coordinator'), hasCoordinator, id);
    // The citizen services are seated inside the Base Registry Engine section,
    // which every docset publishes.
    const docsetBreg = docsetSidebar.find((item) => item.label === 'Base Registry Engine');
    assert.ok(docsetBreg, id);
    assert.equal(docsetBreg.items.some((item) => item.label === 'Citizen chat assistant'), hasBregServices, id);
    // The BReg facility API is published by the current docset and by release
    // docsets from v0.42.0 onward, archived or not.
    assert.equal(hasBregOpenApi, id === 'latest' || id === 'v0.42.0', id);
    assert.equal(docsetBreg.items.includes(bregOpenApiSidebarGroup), hasBregOpenApi, id);
    // The OID4VCI document is published by the current docset and by release
    // docsets from v0.20.0 onward.
    assert.equal(hasEvidenceOid4vciOpenApi, id !== 'v0.19.0', id);
    const docsetSchemas = apiSchemaFactory(
      hasEvidenceOid4vciOpenApi,
      hasBregOpenApi,
      context.hasCasework,
      context.hasScheduling,
      context.hasMessaging,
      context.hasCoordinator,
      ...apiSchemaArguments,
    );
    assert.equal(
      docsetSchemas.length,
      1 + Number(hasEvidenceOid4vciOpenApi) + Number(hasCasework) + Number(hasScheduling) +
        Number(hasMessaging) + Number(hasCoordinator) + Number(hasBregOpenApi),
      id,
    );
    // Each product group seats the group of its own schema and no other,
    // whichever products come before it in this docset.
    const seatedGroups = (group) => group.items.filter((item) => openApiSidebarGroups.includes(item));
    const docsetEvidence = docsetSidebar.find((item) => item.label === 'Registry Evidence');
    assert.deepEqual(
      seatedGroups(docsetEvidence),
      hasEvidenceOid4vciOpenApi
        ? [evidenceOpenApiSidebarGroup, evidenceOid4vciOpenApiSidebarGroup]
        : [evidenceOpenApiSidebarGroup],
      id,
    );
    assert.deepEqual(seatedGroups(docsetBreg), hasBregOpenApi ? [bregOpenApiSidebarGroup] : [], id);
    for (const [label, present, group] of [
      ['Registry Casework', hasCasework, caseworkOpenApiSidebarGroup],
      ['Registry Scheduling', hasScheduling, schedulingOpenApiSidebarGroup],
      ['Registry Messaging', hasMessaging, messagingOpenApiSidebarGroup],
      ['Registry Coordinator', hasCoordinator, coordinatorOpenApiSidebarGroup],
    ]) {
      if (!present) continue;
      assert.deepEqual(seatedGroups(docsetSidebar.find((item) => item.label === label)), [group], `${id} ${label}`);
    }
    // Every registered schema is seated exactly once, and nothing else is.
    const seated = docsetSidebar.flatMap(seatedGroups);
    assert.equal(seated.length, docsetSchemas.length, id);
    assert.deepEqual(new Set(seated), new Set(docsetSchemas.map((schema) => schema.sidebar.group)), id);
    const redirects = caseworkRedirects(context.hasCasework, context.currentDocsetRedirect);
    assert.equal(redirects['/operate/casework/'] !== undefined, !hasCasework, id);
    assert.equal(redirects['/tutorials/first-casework.md'] !== undefined, !hasCasework, id);
    const schedulingRedirectsResult = schedulingRedirects(context.hasScheduling, context.currentDocsetRedirect);
    assert.equal(schedulingRedirectsResult['/reference/apis/registry-scheduling/'] !== undefined, !hasScheduling, id);
    assert.equal(schedulingRedirectsResult['/tutorials/first-scheduling.md'] !== undefined, !hasScheduling, id);
    const renderRedirectsResult = renderRedirects(context.hasRender, context.currentDocsetRedirect);
    assert.equal(renderRedirectsResult['/reference/render-configuration/'] !== undefined, !context.hasRender, id);
    assert.equal(renderRedirectsResult['/tutorials/first-render-document.md'] !== undefined, !context.hasRender, id);
    const messagingRedirectsResult = messagingRedirects(
      context.hasMessaging,
      context.currentHasMessaging,
      context.currentDocsetRedirect,
    );
    // The current docset does not publish Messaging, so a docset without it
    // sends every Messaging route, and its Markdown twin, to the current
    // docset's home page instead of redirecting a route to itself.
    const home = context.currentDocsetRedirect('/');
    for (const route of messagingPageRoutes) {
      const twin = `${route.slice(0, -1)}.md`;
      assert.equal(messagingRedirectsResult[route], hasMessaging ? undefined : home, `${id} ${route}`);
      assert.equal(messagingRedirectsResult[twin], hasMessaging ? undefined : home, `${id} ${twin}`);
    }
    // The same rule for the Coordinator pages while the current docset does
    // not publish the Coordinator.
    const coordinatorRedirectsResult = coordinatorRedirects(
      context.hasCoordinator,
      context.currentHasCoordinator,
      context.currentDocsetRedirect,
    );
    for (const route of coordinatorPageRoutes) {
      const twin = `${route.slice(0, -1)}.md`;
      assert.equal(coordinatorRedirectsResult[route], hasCoordinator ? undefined : home, `${id} ${route}`);
      assert.equal(coordinatorRedirectsResult[twin], hasCoordinator ? undefined : home, `${id} ${twin}`);
    }
  }
  // When the current docset publishes Messaging, a docset without it sends each
  // Messaging route to the same route of the current docset.
  const activated = {
    ...docsets,
    docsets: docsets.docsets.map((docset) => docset.id === 'latest'
      ? { ...docset, products: { ...docset.products, 'registry-messaging': { ref: 'HEAD' } } }
      : docset),
  };
  for (const [id, env, expected] of [
    ['latest', {}, {}],
    ['v0.29.0', {}, Object.fromEntries(messagingPageRoutes.flatMap((route) => {
      const target = `https://docs.registrystack.org/dev${route}`;
      return [[route, target], [`${route.slice(0, -1)}.md`, target]];
    }))],
  ]) {
    const context = resolveDocsetBuildContext(activated, { DOCS_DOCSET: id, ...env });
    assert.equal(context.currentHasMessaging, true, id);
    assert.deepEqual(
      messagingRedirects(context.hasMessaging, context.currentHasMessaging, context.currentDocsetRedirect),
      expected,
      id,
    );
  }
  // A non-archived build without Messaging never redirects a route to itself.
  const unpublished = resolveDocsetBuildContext(docsets, { DOCS_DOCSET: 'latest', DOCS_BASE: '/dev/' });
  for (const [route, target] of Object.entries(messagingRedirects(
    unpublished.hasMessaging,
    unpublished.currentHasMessaging,
    unpublished.currentDocsetRedirect,
  ))) {
    assert.equal(target, '/dev/', route);
  }
  // When the current docset publishes the Coordinator, a docset without it
  // sends each Coordinator route to the same route of the current docset.
  const coordinatorActivated = {
    ...docsets,
    docsets: docsets.docsets.map((docset) => docset.id === 'latest'
      ? { ...docset, products: { ...docset.products, 'registry-coordinator': { ref: 'HEAD' } } }
      : docset),
  };
  for (const [id, env, expected] of [
    ['latest', {}, {}],
    ['v0.29.0', {}, Object.fromEntries(coordinatorPageRoutes.flatMap((route) => {
      const target = `https://docs.registrystack.org/dev${route}`;
      return [[route, target], [`${route.slice(0, -1)}.md`, target]];
    }))],
  ]) {
    const context = resolveDocsetBuildContext(coordinatorActivated, { DOCS_DOCSET: id, ...env });
    assert.equal(context.currentHasCoordinator, true, id);
    assert.deepEqual(
      coordinatorRedirects(context.hasCoordinator, context.currentHasCoordinator, context.currentDocsetRedirect),
      expected,
      id,
    );
  }
  const coordinatorUnpublished = resolveDocsetBuildContext(docsets, { DOCS_DOCSET: 'latest', DOCS_BASE: '/dev/' });
  for (const [route, target] of Object.entries(coordinatorRedirects(
    coordinatorUnpublished.hasCoordinator,
    coordinatorUnpublished.currentHasCoordinator,
    coordinatorUnpublished.currentDocsetRedirect,
  ))) {
    assert.equal(target, '/dev/', route);
  }
  assert.match(fetchOpenapiSource, /\(repoId === 'registry-casework' \|\| repoId === 'registry-scheduling' \|\| repoId === 'registry-messaging' \|\| repoId === 'registry-coordinator'\) && !docset\.products\[repoId\]/);
  for (const route of [
    '/start/casework/',
    '/tutorials/first-casework/',
    '/tutorials/review-breg-changes-in-casework/',
    '/configure/casework/',
    '/operate/casework/',
    '/reference/apis/registry-casework/',
  ]) {
    assert.match(configSource, new RegExp(`'${route}'`));
  }
  assert.match(configSource, /\.\.\.caseworkRedirects\(hasCasework, currentDocsetRedirect\)/);
  assert.match(configSource, /\.\.\.schedulingRedirects\(hasScheduling, currentDocsetRedirect\)/);
  assert.match(configSource, /\.\.\.renderRedirects\(hasRender, currentDocsetRedirect\)/);
  assert.match(configSource, /\.\.\.messagingRedirects\(hasMessaging, currentHasMessaging, currentDocsetRedirect\)/);
  assert.match(configSource, /\.\.\.coordinatorRedirects\(hasCoordinator, currentHasCoordinator, currentDocsetRedirect\)/);
});

test('starts with only Start expanded and all secondary groups collapsed', () => {
  for (const group of sidebar) {
    assert.equal(
      group.collapsed === true,
      group.label !== 'Start',
      `unexpected initial expansion for ${group.label}`,
    );
    for (const item of group.items.filter((item) => item.items)) {
      assert.equal(item.collapsed, true, `${group.label} / ${item.label} must start collapsed`);
    }
  }
});

test('requires at most two groups to reach a hand-authored page', () => {
  function walk(items, parents = []) {
    for (const item of items) {
      if (openApiSidebarGroups.includes(item)) continue;
      if (!item.items) continue;
      const path = [...parents, item.label];
      assert.ok(path.length <= 2, `sidebar adds a third group: ${path.join(' / ')}`);
      walk(item.items, path);
    }
  }
  walk(sidebar);
});

test('keeps consumer and wallet-provider guidance in separate Evidence groups', () => {
  const evidence = section('Registry Evidence');
  const consumer = evidence.items.find((item) => item.label === 'Use from applications');
  const wallet = evidence.items.find((item) => item.label === 'Wallet delivery');
  assert.ok(consumer, 'Evidence must provide an application-consumer entry point');
  assert.ok(wallet, 'Evidence must provide a separate wallet-provider entry point');
  assert.deepEqual(consumer.items.map((item) => item.slug), [
    'tutorials/request-evidence-from-an-application',
    'configure/request-an-access-token',
    'tutorials/verify-an-assertion-as-a-consumer',
    'tutorials/manage-evidence-verifier-trust',
  ]);
  assert.deepEqual(wallet.items.map((item) => item.slug), [
    'configure/enable-sd-jwt-vc',
    'configure/evidence-oid4vci',
  ]);
  assert.equal(evidence.items[1].slug, 'tutorials/first-evidence-assertion');
  assert.equal(evidence.items[2].slug, 'explanation/how-evidence-works');
  assert.equal(evidence.items[3].label, 'Tutorials', 'the tutorials continue the first assertion');
  assert.equal(evidence.items[4], consumer, 'consumer entry point follows the tutorials it builds on');
});

test('seats generated product references directly below Reference without losing leaf attributes', () => {
  const reference = section('Reference');
  for (const [label, product] of [
    ['Registry Manifest', 'Manifest'],
    ['Registry Evidence', 'Registry Evidence'],
  ]) {
    const group = reference.items.find((item) => item.label === label);
    assert.ok(group, `missing generated reference group: ${label}`);
    const fixture = generatedProducts.get(product).items[0].items;
    assert.deepEqual(group.items, [fixture[0], fixture[1].items[0]]);
  }
});

test('uses the formal product names for top-level sections', () => {
  for (const product of [
    'Registry Evidence',
    'Base Registry Engine',
    'Registry Casework',
    'Registry Scheduling',
    'Registry Render',
    'Registry Messaging',
    'Registry Coordinator',
    'Registry Discovery',
  ]) {
    assert.ok(topLevelSection(sidebarSource, product), `could not isolate ${product}`);
  }

  // Short forms are what made one product look like several. `BReg` and
  // `Discovery` are ordinary inside a page that has already named
  // the product; a top-level label is where a reader arrives, so it carries
  // the full name or none at all.
  for (const label of topLevelLabels(sidebarSource)) {
    for (const [shortForm, formal] of [
      ['Discovery', 'Registry Discovery'],
      ['Render', 'Registry Render'],
      ['BReg', 'Base Registry Engine'],
      ['Evidence', 'Registry Evidence'],
    ]) {
      if (!label.includes(shortForm)) continue;
      assert.ok(
        label.includes(formal),
        `top-level label "${label}" uses ${shortForm} where the formal name is ${formal}`,
      );
    }
  }
});

test('publishes one overview route for every section that has one', () => {
  for (const [label, route] of [
    ['Start', "link: '/'"],
    ['Registry Evidence', "slug: 'start/evidence-quickstart'"],
    ['Base Registry Engine', "slug: 'start/breg-quickstart'"],
    ['Registry Casework', "slug: 'start/casework'"],
    ['Registry Render', "slug: 'start/registry-render'"],
    ['Registry Messaging', "slug: 'start/messaging'"],
    ['Registry Coordinator', "slug: 'start/coordinator'"],
    ['Operations', "slug: 'operate/advanced'"],
    ['Reference', "slug: 'reference'"],
  ]) {
    const section = topLevelSection(sidebarSource, label);
    assert.ok(section, `could not isolate ${label}`);
    assert.match(section, new RegExp(route.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

// A page that names one product belongs under that product while the reader is
// still adopting it, so a reader following one adoption path never leaves it.
// Operations is the exception the operator earns: after handoff the
// reader is on call for a running deployment, not choosing a product, so pages
// that name a runtime sit beside the ones that do not.
test('files adoption-time pages under their product', () => {
  // Registry Evidence's security model is product-scoped, so it stays with the
  // product rather than in the cross-product security group.
  const security = topLevelSection(sidebarSource, 'Operations');
  assert.doesNotMatch(security, /slug: 'security\/evidence'/);
  const evidence = topLevelSection(sidebarSource, 'Registry Evidence');
  assert.match(evidence, /slug: 'security\/evidence'/);
});

test('publishes the Relay retirement decision without a current product lane', () => {
  const start = topLevelSection(sidebarSource, 'Start');
  assert.doesNotMatch(start, /slug: 'tutorials\//);
  assert.equal(topLevelSection(sidebarSource, 'Registry Relay'), null);
  assert.match(sidebarSource, /slug: 'decisions\/registry-relay-retirement-2026-10-03'/);
  assert.doesNotMatch(homepageSource, /publish-governed-sqlite-registry|query-relay-client/);
});

test('gives Registry Evidence a lane on both front doors without a retired Notary path', () => {
  assert.match(homepageSource, /\]\(start\/evidence-quickstart\/\)/);
  assert.match(homepageSource, /tutorials\/first-evidence-assertion/);
  assert.doesNotMatch(homepageSource, /Expose Notary|verify-claim-registry-api/);
});

// The BReg section follows the shape the Registry Evidence section proved: an
// overview, one first tutorial in the open, then each later phase behind the
// group it belongs to. A reader who has finished one phase finds the next one
// beside it, and a reader who has not is not shown its vocabulary yet.
test('keeps the BReg guide and references in one adoption path', () => {
  const breg = topLevelSection(sidebarSource, 'Base Registry Engine');
  assert.ok(breg, 'could not isolate the Base Registry Engine section');
  const slugs = [...breg.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]);
  assert.deepEqual(slugs, [
    'start/breg-quickstart',
    'tutorials/first-breg',
    'explanation/configuration-defined-registry',
    'tutorials/change-a-registry-with-an-action',
    'tutorials/extend-a-registry-with-a-module',
    'tutorials/derive-a-registry-from-publicschema',
    'tutorials/query-breg-client',
    'configure/breg',
    'explanation/registry-modeling-patterns',
    'configure/breg-access',
    'configure/breg-actions',
    'configure/breg-field-encryption',
    'configure/breg-statistics',
    'configure/breg-journeys',
    'operate/breg',
    'operate/breg-changes',
    'operate/breg-monitor',
    'operate/breg-retention',
    'operate/breg-data',
    'operate/breg-webhooks',
    'reference/breg-client-capabilities',
    'reference/client-api',
    'reference/breg-api',
    'reference/bregctl-publicschema-wizard',
    'explanation/esignet-authentication-over-breg',
    'tutorials/send-registry-events-to-a-webhook',
    'tutorials/evidence-from-breg',
    'tutorials/review-breg-changes-in-casework',
    'configure/breg-mcp',
    'reference/breg-configuration',
  ]);
  for (const slug of slugs) {
    assert.ok(hasDocForSlug(slug), `${slug} must be reachable from the BReg journey`);
  }
  assertOrdered(
    breg,
    [
      "slug: 'tutorials/first-breg'",
      "label: 'Tutorials'",
      "label: 'Author a registry'",
      "label: 'Deploy and operate'",
      "label: 'Use from applications'",
      "label: 'Compose'",
      "slug: 'reference/breg-configuration'",
    ],
    'Base Registry Engine',
  );

  // The homepage names the doors into the path, not every room: the overview,
  // the first tutorial, the deployment page, and the tutorial
  // an application developer arrives for. Requiring every BReg slug there
  // produced an eleven-link wall that read as a feature list, not a way in.
  for (const slug of [
    'start/breg-quickstart',
    'tutorials/first-breg',
    'operate/breg',
    'tutorials/query-breg-client',
  ]) {
    const escaped = slug.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(
      homepageSource,
      new RegExp(`\\]\\(${escaped}/\\)`),
      `${slug} must be linked from the homepage`,
    );
  }
});

// Both runtime products ask an adopter for infrastructure before they serve
// anything: PostgreSQL, a token issuer, and a signing process for Base Registry
// Engine; a Transit proxy, an identity provider, and durable audit storage for
// Registry Evidence. That is deployment planning, so it opens each product's
// Deploy group. It is not a first encounter, so Start carries none of it: a
// first visit meets the overview and the page that explains how the products
// fit together, and reaches every product through its own overview. The two
// retired Start seats redirect to the Deploy pages that replaced them.
test('keeps operating requirements in each product Deploy group, not in Start', () => {
  const start = topLevelSection(sidebarSource, 'Start');
  assert.ok(start, 'could not isolate Start');
  assert.deepEqual(
    [...start.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]),
    ['start/concepts'],
  );

  const evidence = topLevelSection(sidebarSource, 'Registry Evidence');
  assertOrdered(
    evidence,
    [
      "label: 'Prove and deploy'",
      "slug: 'tutorials/prove-an-evidence-project'",
      "slug: 'tutorials/build-and-deploy-evidence-project'",
      "slug: 'operate/evidence-audit'",
    ],
    'Registry Evidence Prove and deploy group',
  );
  // Base Registry Engine states its requirements at the top of Deploy and
  // serve, so that page opens its Deploy and operate group; the separate
  // requirements page it absorbed redirects there.
  const breg = topLevelSection(sidebarSource, 'Base Registry Engine');
  assertOrdered(
    breg,
    [
      "label: 'Deploy and operate'",
      "slug: 'operate/breg'",
      "slug: 'operate/breg-changes'",
    ],
    'Base Registry Engine Deploy and operate group',
  );
  for (const slug of ['explanation/how-evidence-works', 'operate/breg']) {
    assert.ok(hasDocForSlug(slug), `${slug} must be a published page`);
  }

  // Evidence's requirements page was absorbed by the one page that explains
  // how the product works.
  for (const retired of [
    'start/evaluate-evidence',
    'start/evaluate-breg',
    'operate/breg-requirements',
    'operate/evidence-requirements',
  ]) {
    assert.equal(hasDocForSlug(retired), false, `${retired} must not be a published page`);
    assert.doesNotMatch(sidebarSource, new RegExp(retired));
  }
  for (const route of ['/start/evaluate-evidence/', '/operate/evidence-requirements/']) {
    assert.match(
      configSource,
      new RegExp(`'${route.replaceAll('/', '\\/')}': internalRedirect\\('\\/explanation\\/how-evidence-works\\/'\\)`),
    );
  }
  assert.match(
    configSource,
    /'\/start\/evaluate-breg\/': internalRedirect\('\/operate\/breg\/'\)/,
  );
  assert.equal(bregRewriteRedirects((path) => path)['/operate/breg-requirements/'], '/operate/breg/');
});

test('redirects each page the Base Registry Engine rewrite retired and its Markdown twin to one target', () => {
  assert.match(configSource, /\.\.\.bregRewriteRedirects\(internalRedirect\),/);
  const redirects = bregRewriteRedirects((path) => `/dev${path}`);
  const routes = Object.keys(redirects).filter((route) => route.endsWith('/'));
  assert.equal(routes.length, 14);
  for (const route of routes) {
    assert.equal(redirects[`${route.slice(0, -1)}.md`], redirects[route], route);
    assert.equal(hasDocForSlug(route.slice(1, -1)), false, `${route} must not be a published page`);
  }
  assert.equal(redirects['/explanation/governed-registry-actions.md'], '/dev/configure/breg-actions/');
  assert.equal(Object.keys(redirects).length, 2 * routes.length);
});

test('redirects each page the Evidence and Casework rewrite retired and its Markdown twin to one target', () => {
  for (const [route, target] of [
    ['/operate/evidence-requirements/', '/explanation/how-evidence-works/'],
    ['/tutorials/refuse-unsafe-evidence-requests/', '/tutorials/control-who-can-request-evidence/'],
    ['/configure/evidence/', '/tutorials/build-and-deploy-evidence-project/'],
    ['/reference/evidencectl/', '/reference/cli/evidencectl/'],
    ['/tutorials/issue-fhir-evidence-as-vcs/', '/tutorials/connect-an-institution-source/'],
    ['/explanation/integration-patterns/', '/start/concepts/'],
    ['/tutorials/run-oid4vci-interoperability-checks/', '/configure/evidence-oid4vci/'],
    ['/explanation/disclosure-modes-and-computed-answers/', '/explanation/how-evidence-works/'],
  ]) {
    const twin = `${route.slice(0, -1)}.md`;
    for (const path of [route, twin]) {
      const entry = `'${path}': internalRedirect('${target}'),`;
      assert.ok(configSource.includes(entry), `${entry} must be a redirect`);
    }
    assert.equal(hasDocForSlug(route.slice(1, -1)), false, `${route} must not be a published page`);
  }
});

test('redirects the retired Server webhook, history, and event pages to their merged pages', () => {
  assert.match(
    configSource,
    /'\/configure\/breg-webhooks\/': internalRedirect\('\/operate\/breg-webhooks\/'\)/,
  );
  assert.match(
    configSource,
    /'\/reference\/breg-history\/': internalRedirect\('\/reference\/breg-api\/'\)/,
  );
  assert.match(
    configSource,
    /'\/reference\/breg-events\/': internalRedirect\('\/reference\/breg-api\/'\)/,
  );
  for (const retired of [
    'configure/breg-webhooks',
    'reference/breg-history',
    'reference/breg-events',
  ]) {
    assert.equal(hasDocForSlug(retired), false, `${retired} must not be a published page`);
  }
});

test('redirects the retired deprecation policy page and its Markdown twin to the stability page', () => {
  assert.match(
    configSource,
    /'\/reference\/deprecation-policy\/': internalRedirect\('\/reference\/api-stability\/'\)/,
  );
  assert.match(
    configSource,
    /'\/reference\/deprecation-policy\.md': internalRedirect\('\/reference\/api-stability\/'\)/,
  );
  assert.equal(
    hasDocForSlug('reference/deprecation-policy'),
    false,
    'reference/deprecation-policy must not be a published page',
  );
  assert.ok(hasDocForSlug('reference/api-stability'), 'reference/api-stability must be a published page');
});

test('organizes Registry Evidence tasks without publishing the obsolete Relay composition', () => {
  const evidence = topLevelSection(sidebarSource, 'Registry Evidence');
  assertOrdered(
    evidence,
    [
      // The first hands-on tutorial sits beside the overview, so opening the
      // product section reveals both starting points.
      "slug: 'tutorials/first-evidence-assertion'",
      "label: 'Tutorials'",
      "label: 'Use from applications'",
      "label: 'Connect a source'",
      "label: 'Prove and deploy'",
      "label: 'Wallet delivery'",
      // Reference a reader opens with the deployment in front of them, so it
      // ends this section instead of starting a Reference lookup.
      "slug: 'reference/evidence-configuration'",
      "slug: 'reference/evidence-problems'",
      "slug: 'reference/apis/registry-evidence'",
      'evidenceOpenApiSidebarGroup,',
      // The wallet-facing supporting service's operations follow the Evidence
      // operations and never leave the Evidence section.
      'evidenceOid4vciOpenApiSidebarGroup',
    ],
    'Registry Evidence task group',
  );
  assert.doesNotMatch(evidence, /label: 'Verify and trust'/);
  // Token issuance stays with the deployment's identity provider. The Evidence
  // consumer group is separate from provider authoring and wallet-delivery guidance.
  assert.doesNotMatch(evidence, /label: 'Verify as a relying party'/);
  // explanation/integration-patterns was retired: its composition rules live
  // on the cross-product concepts page and its same-key retry rules on the
  // client API reference.
  assert.equal(hasDocForSlug('explanation/integration-patterns'), false);
  assert.doesNotMatch(sidebarSource, /explanation\/integration-patterns/);
  assert.match(
    configSource,
    /'\/explanation\/integration-patterns\/': internalRedirect\('\/start\/concepts\/'\)/,
  );
  // How Evidence works has one seat, right after the first tutorial, and the
  // tutorials that follow it sit in the order each one's `after:` chains them.
  assert.equal(
    [...sidebarSource.matchAll(/slug: 'explanation\/how-evidence-works'/g)].length,
    1,
  );
  assertOrdered(
    evidence,
    [
      "slug: 'tutorials/first-evidence-assertion'",
      "slug: 'explanation/how-evidence-works'",
      "slug: 'tutorials/return-a-governed-value'",
      "slug: 'tutorials/control-who-can-request-evidence'",
      "slug: 'tutorials/assert-a-role-bound-relationship'",
      "slug: 'tutorials/request-evidence-as-sd-jwt-vc'",
    ],
    'Registry Evidence tutorial order',
  );
  // The refusal tutorial was folded into the access-control tutorial.
  assert.equal(hasDocForSlug('tutorials/refuse-unsafe-evidence-requests'), false);
  assert.doesNotMatch(sidebarSource, /refuse-unsafe-evidence-requests/);
  assert.match(
    configSource,
    /'\/tutorials\/refuse-unsafe-evidence-requests\/': internalRedirect\('\/tutorials\/control-who-can-request-evidence\/'\)/,
  );
  assert.doesNotMatch(evidence, /first-run-with-solmara-lab|Relay-protected|over a Relay/);
  assert.equal(hasDocForSlug('tutorials/first-run-with-solmara-lab'), false);
  assert.ok(RETIRED_RELAY_ROUTES.includes('/tutorials/first-run-with-solmara-lab/'));
});

test('keeps the Casework journey in one product lane', () => {
  const casework = topLevelSection(sidebarSource, 'Registry Casework');
  assert.ok(casework, 'could not isolate the Registry Casework section');
  const slugs = [...casework.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]);
  assert.deepEqual(slugs, [
    'start/casework',
    'tutorials/first-casework',
    'explanation/how-casework-works',
    'configure/casework',
    'configure/casework-directory',
    'operate/casework',
    'operate/change-a-casework-package',
    'operate/casework-retention',
    'tutorials/review-breg-changes-in-casework',
    'reference/apis/registry-casework',
    'reference/client-api',
  ]);
  assertOrdered(
    casework,
    [
      "slug: 'tutorials/first-casework'",
      "label: 'Author a policy'",
      "label: 'Deploy and operate'",
      "label: 'Compose'",
      "slug: 'reference/apis/registry-casework'",
    ],
    'Registry Casework',
  );
  for (const slug of slugs) {
    assert.ok(hasDocForSlug(slug), `${slug} must be reachable from the Casework journey`);
  }
  assert.match(casework, /caseworkOpenApiSidebarGroup,/);
});

// The Coordinator configuration reference has one seat, in the Coordinator
// lane, so a reader adopting the Coordinator never leaves it.
test('keeps the Coordinator journey in one product lane', () => {
  const coordinator = topLevelSection(sidebarSource, 'Registry Coordinator');
  assert.ok(coordinator, 'could not isolate the Registry Coordinator section');
  const slugs = [...coordinator.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]);
  assert.deepEqual(slugs, [
    'start/coordinator',
    'tutorials/review-an-application-and-send-a-notice',
    'explanation/how-coordinator-works',
    'configure/coordinator',
    'operate/coordinator',
    'reference/coordinator-configuration',
    'reference/apis/registry-coordinator',
  ]);
  for (const slug of slugs) {
    assert.ok(hasDocForSlug(slug), `${slug} must be reachable from the Coordinator journey`);
  }
  assert.equal(
    [...sidebarSource.matchAll(/slug: 'reference\/coordinator-configuration'/g)].length,
    1,
  );
  assert.match(coordinator, /coordinatorOpenApiSidebarGroup,/);
});

// The plugin maps every schema without its own group to one shared
// placeholder, so a product seat for that placeholder would show every
// product's operations. Each schema names its own created group instead, and
// the sidebar seats each group once.
test('seats each product OpenAPI schema in its own created group', () => {
  assert.match(configSource, /import starlightOpenAPI, \{ createOpenAPISidebarGroup \} from 'starlight-openapi'/);
  assert.doesNotMatch(sidebarSource, /openAPISidebarGroups/);
  for (const schema of apiSchemas) {
    assert.ok(schema.sidebar.group, `${schema.base} registers no sidebar group`);
  }
  assert.equal(new Set(apiSchemas.map((schema) => schema.sidebar.group)).size, apiSchemas.length);
  const seats = sidebar.flatMap((group) => group.items.filter((item) => openApiSidebarGroups.includes(item)));
  assert.equal(seats.length, apiSchemas.length);
  assert.equal(new Set(seats).size, seats.length);
});

// The glossary is a lookup a reader opens from a term, not a first encounter,
// so it ends Reference instead of opening Start.
test('ends Reference with the glossary', () => {
  const reference = section('Reference');
  assert.equal(reference.items.at(-1).slug, 'reference/glossary');
  assert.equal([...sidebarSource.matchAll(/slug: 'reference\/glossary'/g)].length, 1);
  const start = section('Start');
  assert.deepEqual(start.items.map((item) => item.slug ?? item.link), ['/', 'start/concepts']);
});

test('does not publish the retired pre-1.0 cutover page', () => {
  assert.equal(
    existsSync(resolve(siteRoot, 'src/content/docs/start/pre-1.0-cutover.mdx')),
    false,
  );
  assert.doesNotMatch(sidebarSource, /pre-1\.0-cutover/);
  assert.doesNotMatch(homepageSource, /pre-1\.0-cutover/);
});

// `start/quickstart` and `start/when-to-use` were product choosers: each told
// a reader which product answered their problem, which the homepage does too.
// Both are retired rather than repurposed, so their routes, which were
// published and so have readers holding links to them, land on the homepage,
// and so do the redirects that used to point at the chooser.
test('does not publish a product chooser beside the homepage', () => {
  for (const page of ['start/quickstart.mdx', 'start/when-to-use.mdx']) {
    assert.equal(existsSync(resolve(siteRoot, 'src/content/docs', page)), false, page);
  }
  assert.doesNotMatch(sidebarSource, /start\/(quickstart|when-to-use)/);
  assert.doesNotMatch(homepageSource, /start\/(quickstart|when-to-use)/);
  assert.match(configSource, /'\/start\/quickstart\/': internalRedirect\('\/'\)/);
  assert.match(configSource, /'\/start\/when-to-use\/': internalRedirect\('\/'\)/);
  assert.doesNotMatch(configSource, /internalRedirect\('\/start\/when-to-use\/'\)/);
});

test('every hand-authored sidebar slug resolves to a published documentation page', () => {
  const slugs = [...sidebarSource.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]);
  const missing = [...new Set(slugs)].filter((slug) => !hasDocForSlug(slug));

  assert.deepEqual(missing, []);
});

// The inverse of the assertion above, and the one whose absence let three
// security seats disappear in 6a73ea65f without a single check going red.
// A seat that points nowhere breaks the build; a page that nothing points at
// breaks only the reader, silently.
test('every published page has a sidebar seat or a reasoned allowlist entry', () => {
  const seated = seatedSlugs();
  const orphans = publishedSlugs().filter(
    (slug) => !seated.has(slug) && !UNSEATED_PUBLISHED_PAGES.has(slug),
  );

  assert.deepEqual(
    orphans,
    [],
    'published pages the sidebar does not reach, so a reader finds them only by '
      + 'search or by already knowing the URL: '
      + `${orphans.join(', ')}. Give each one a seat in astro.config.mjs, or add it `
      + 'to UNSEATED_PUBLISHED_PAGES with the decision that keeps it published.',
  );
});

test('keeps the unseated-page allowlist free of stale entries', () => {
  const seated = seatedSlugs();
  const published = new Set(publishedSlugs());

  for (const [slug, reason] of UNSEATED_PUBLISHED_PAGES) {
    assert.ok(
      published.has(slug),
      `${slug} is allowlisted as unseated but is not a published page: drop the entry`,
    );
    assert.ok(
      !seated.has(slug),
      `${slug} now has a sidebar seat: drop its UNSEATED_PUBLISHED_PAGES entry`,
    );
    assert.ok(reason.trim().length > 0, `${slug} needs a reason, not an empty string`);
  }
});

test('legacy Relay entry points redirect to the retirement decision', () => {
  assert.match(configSource, /'\/start\/': internalRedirect\('\/'\)/);
  for (const retired of [
    '/products/registry-relay/',
    '/configure/relay/',
    '/operate/relay/',
    '/reference/relayctl/',
    '/spec/rs-pr-relay/',
    '/tutorials/publish-spreadsheet-secured-registry-api/',
  ]) {
    assert.ok(RETIRED_RELAY_ROUTES.includes(retired), `${retired} must remain redirected`);
  }
  assert.notEqual(RELAY_RETIREMENT, '/');
  assert.match(configSource, /buildRelayRetirementRedirects\(currentDocsetRedirect\)/);
  assert.match(configSource, /buildNotaryRetirementRedirects\(currentDocsetRedirect\)/);
});

// A redirect outranks a content page at the same route, so a retired route
// that a page still publishes would stop that page and its `.md` twin from
// rendering. The check reads the content tree as it is on disk, which after
// `npm run generate` includes the pulled product pages and the generated
// command reference.
test('retires no Relay route that a content page still publishes', () => {
  const redirects = buildRelayRetirementRedirects((target) => target);
  const shadowing = Object.keys(redirects).filter((source) => {
    const slug = source.replace(/\.md$/, '').replace(/^\/|\/$/g, '');
    return ['.mdx', '.md', '/index.mdx', '/index.md'].some((suffix) => (
      existsSync(resolve(siteRoot, 'src/content/docs', `${slug}${suffix}`))
    ));
  });
  assert.deepEqual(shadowing, []);
});

test('redirects every retired Relay page and its Markdown twin to the retirement decision', () => {
  const redirects = buildRelayRetirementRedirects((target) => target);
  const retiredPages = [
    // Hand-authored pages.
    '/configure/',
    '/configure/relay/',
    '/decisions/relay-v1-and-registryctl-retirement-2026-08-11/',
    '/explanation/governed-registry-publication/',
    '/explanation/relay-semantics-and-disclosure/',
    '/operate/relay/',
    '/reference/relayctl/',
    '/spec/rs-op-posture/',
    '/spec/rs-pr-relay/',
    '/spec/rs-pr-relayctl/',
    '/tutorials/first-run-with-solmara-lab/',
    '/tutorials/publish-governed-sqlite-registry/',
    '/tutorials/query-relay-client/',
    '/verify/',
    // Pulled product pages.
    '/products/registry-relay/',
    '/products/registry-relay/standards-alignment/',
    // Generated command reference for the `relay` and `relayctl` binaries.
    '/reference/cli/relay/',
    '/reference/cli/relay/check/',
    '/reference/cli/relay/healthcheck/',
    '/reference/cli/relay/serve/',
    '/reference/cli/relayctl/',
    '/reference/cli/relayctl/check/',
    '/reference/cli/relayctl/diff/',
    '/reference/cli/relayctl/generate/',
    '/reference/cli/relayctl/init/',
    '/reference/cli/relayctl/inspect/',
    '/reference/cli/relayctl/package/',
    '/reference/cli/relayctl/test/',
    '/reference/cli/relayctl/tooling/',
    '/reference/cli/relayctl/tooling/editor/',
    '/reference/cli/relayctl/tooling/language-server/',
    // Routes that already redirected to a Relay page.
    '/configure/oauth-client-credentials/',
    '/products/registry-relay/standards-assumptions/',
  ];

  for (const route of retiredPages) {
    assert.equal(redirects[route], RELAY_RETIREMENT, `${route} has no retirement redirect`);
    const twin = `${route.slice(0, -1)}.md`;
    assert.equal(redirects[twin], RELAY_RETIREMENT, `${twin} has no retirement redirect`);
  }
});

test('keeps source-assurance artifacts out of the adopter navigation', () => {
  assert.doesNotMatch(sidebarSource, /label: 'Journeys'|label: 'Source assurance'/);
  assert.doesNotMatch(sidebarSource, /slug: 'journeys/);
  assert.match(configSource, /'\/journeys\/': internalRedirect\('\/'\)/);
});
