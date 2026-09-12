// Guards the Registry Stack 1.0 product outcomes and their stable entry points.

import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { cliReferenceSidebar } from '../src/lib/cli-reference-sidebar.mjs';
import { RETIRED_RELAY_ROUTE_TARGETS } from '../src/lib/relay-v2-retirement-redirects.mjs';
import { flattenSidebarGroups } from '../src/lib/sidebar.mjs';

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
const homepageSource = readFileSync(resolve(siteRoot, 'src/content/docs/index.mdx'), 'utf8');
const validationSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/verify/index.mdx'),
  'utf8',
);
const sidebarSource = configSource.match(/sidebar: \[([\s\S]*?)\n      \],\n    \}\),/)?.[1];

assert.ok(sidebarSource, 'could not isolate the Starlight sidebar configuration');

// Evaluate the trusted local sidebar expression without loading Astro or
// requiring generated artifacts. Nested product fixtures exercise the actual
// config's flattening; the OpenAPI plugin owns its generated tag hierarchy.
const generatedProducts = new Map(['Relay', 'Manifest', 'Evidence Gateway'].map((label) => [
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
const caseworkOpenApiSchema = {
  base: 'reference/apis/casework',
  schema: './openapi/registry-casework.openapi.json',
  sidebar: { label: 'API operations', collapsed: true },
};
const apiSchemas = new Function(
  'hasCasework',
  'caseworkOpenApiSchema',
  `return ${apiConfigSource};`,
)(true, caseworkOpenApiSchema);
const generatedAPI = apiSchemas.map((schema) => ({
  ...schema.sidebar,
  items: [{ label: 'Generated tag', items: [] }],
}));
const sidebarFactory = new Function(
  'cliReferenceSidebar',
  'generatedProduct',
  'optionalGeneratedProduct',
  'openAPISidebarGroups',
  'flattenSidebarGroups',
  'hasCasework',
  `return [${sidebarSource}];`,
);
const sidebarArguments = [
  cliReferenceSidebar,
  (label) => {
    assert.ok(generatedProducts.has(label), `unexpected generated product: ${label}`);
    return generatedProducts.get(label);
  },
  (label) => generatedProducts.get(label) ?? null,
  generatedAPI,
  flattenSidebarGroups,
];
const sidebar = sidebarFactory(...sidebarArguments, true);

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
    'Evidence Gateway',
    'Registry Relay',
    'Base Registry Engine',
    'Registry Casework',
    'Registry Mint',
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
      { id: 'latest', status: 'current', availability: 'unreleased', path: '/dev/', products: { 'registry-casework': { ref: 'HEAD' } } },
      { id: 'v0.29.0', status: 'archived', availability: 'released', path: '/v/0.29.0/', products: {} },
      { id: 'v0.30.0', status: 'archived', availability: 'candidate', path: '/v/0.30.0/', products: { 'registry-casework': { ref: 'v0.30.0' } } },
    ],
  };
  for (const [id, env, hasCasework] of [
    ['latest', {}, true],
    ['v0.29.0', {}, false],
    ['v0.30.0', {}, true],
    ['v0.30.0', { DOCS_RELEASED_ARCHIVE: 'true' }, true],
  ]) {
    const context = resolveDocsetBuildContext(docsets, { DOCS_DOCSET: id, ...env });
    assert.equal(context.hasCasework, hasCasework, id);
    assert.equal(sidebarFactory(...sidebarArguments, context.hasCasework)
      .some((item) => item.label === 'Registry Casework'), hasCasework, id);
    assert.equal(new Function('hasCasework', 'caseworkOpenApiSchema', `return ${apiConfigSource};`)
      (context.hasCasework, caseworkOpenApiSchema).length, hasCasework ? 2 : 1, id);
    const redirects = caseworkRedirects(context.hasCasework, context.currentDocsetRedirect);
    assert.equal(redirects['/operate/casework/'] !== undefined, !hasCasework, id);
    assert.equal(redirects['/tutorials/first-casework.md'] !== undefined, !hasCasework, id);
  }
  assert.match(fetchOpenapiSource, /repoId === 'registry-casework' && !docset\.products\[repoId\]/);
  for (const route of [
    '/start/casework/',
    '/tutorials/first-casework/',
    '/configure/casework/',
    '/operate/casework/',
    '/reference/apis/registry-casework/',
  ]) {
    assert.match(configSource, new RegExp(`'${route}'`));
  }
  assert.match(configSource, /\.\.\.caseworkRedirects\(hasCasework, currentDocsetRedirect\)/);
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
      if (generatedAPI.includes(item)) continue;
      if (!item.items) continue;
      const path = [...parents, item.label];
      assert.ok(path.length <= 2, `sidebar adds a third group: ${path.join(' / ')}`);
      walk(item.items, path);
    }
  }
  walk(sidebar);
});

test('keeps consumer and wallet-provider guidance in separate Evidence groups', () => {
  const evidence = section('Evidence Gateway');
  const consumer = evidence.items.find((item) => item.label === 'Use from applications');
  const wallet = evidence.items.find((item) => item.label === 'Wallet delivery');
  assert.ok(consumer, 'Evidence must provide an application-consumer entry point');
  assert.ok(wallet, 'Evidence must provide a separate wallet-provider entry point');
  assert.deepEqual(consumer.items.map((item) => item.slug), [
    'tutorials/request-evidence-from-an-application',
    'tutorials/verify-an-assertion-as-a-consumer',
    'tutorials/manage-evidence-verifier-trust',
    'explanation/openfn-adaptors',
  ]);
  assert.deepEqual(wallet.items.map((item) => item.slug), [
    'configure/enable-sd-jwt-vc',
    'configure/evidence-oid4vci',
    'tutorials/run-oid4vci-interoperability-checks',
  ]);
  assert.equal(evidence.items[1].slug, 'tutorials/first-evidence-assertion');
  assert.equal(evidence.items[2], consumer, 'consumer entry point must precede provider phases');
});

test('seats generated product references directly below Reference without losing leaf attributes', () => {
  const reference = section('Reference');
  for (const [label, product] of [
    ['Registry Relay', 'Relay'],
    ['Registry Manifest', 'Manifest'],
    ['Evidence Gateway', 'Evidence Gateway'],
  ]) {
    const group = reference.items.find((item) => item.label === label);
    assert.ok(group, `missing generated reference group: ${label}`);
    const fixture = generatedProducts.get(product).items[0].items;
    assert.deepEqual(group.items, [fixture[0], fixture[1].items[0]]);
  }
});

// One product used to carry a different public name on every surface, and the
// sidebar group that served it carried none of them: a reader told to "use
// Registry Relay" scanned the navigation and found no such words. Every
// top-level section that one product serves names that product, with the
// formal name docs/style-guide.md prescribes.
test('uses the formal product names for top-level sections', () => {
  for (const product of [
    'Evidence Gateway',
    'Registry Relay',
    'Base Registry Engine',
    'Registry Casework',
    'Registry Mint',
    'Registry Discovery',
  ]) {
    assert.ok(topLevelSection(sidebarSource, product), `could not isolate ${product}`);
  }

  // Short forms are what made one product look like several. `Relay`, `BReg`,
  // `Mint`, and `Discovery` are ordinary inside a page that has already named
  // the product; a top-level label is where a reader arrives, so it carries
  // the full name or none at all.
  for (const label of topLevelLabels(sidebarSource)) {
    for (const [shortForm, formal] of [
      ['Relay', 'Registry Relay'],
      ['Mint', 'Registry Mint'],
      ['Discovery', 'Registry Discovery'],
      ['BReg', 'Base Registry Engine'],
      ['Evidence', 'Evidence Gateway'],
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
    ['Evidence Gateway', "slug: 'start/evidence-quickstart'"],
    ['Registry Relay', "slug: 'configure'"],
    ['Base Registry Engine', "slug: 'start/breg-quickstart'"],
    ['Registry Casework', "slug: 'start/casework'"],
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
  const relay = topLevelSection(sidebarSource, 'Registry Relay');
  const operate = topLevelSection(sidebarSource, 'Operations');
  assert.match(
    relay,
    /slug: 'operate\/relay' \}/,
    'running a Relay deployment is a Relay page and belongs in the Relay section',
  );
  assert.doesNotMatch(operate, /slug: 'operate\/relay' \}/);
  // The operator handoff is the entry to the operator's own section, and it
  // named Relay only because that is where it used to sit.
  assert.match(operate, /slug: 'operate' \}/);
  assert.doesNotMatch(relay, /slug: 'operate' \}/);

  // Evidence Gateway's security model is product-scoped, so it stays with the
  // product rather than in the cross-product security group.
  const security = topLevelSection(sidebarSource, 'Operations');
  assert.doesNotMatch(security, /slug: 'security\/evidence'/);
  const evidence = topLevelSection(sidebarSource, 'Evidence Gateway');
  assert.match(evidence, /slug: 'security\/evidence'/);
});

test('publishes one Relay reader journey without the retired V1 routes', () => {
  const start = topLevelSection(sidebarSource, 'Start');
  assert.doesNotMatch(
    start,
    /slug: 'tutorials\//,
  );
  const connect = topLevelSection(sidebarSource, 'Registry Relay');
  assertOrdered(
    connect,
    [
      "slug: 'explanation/governed-registry-publication'",
      "slug: 'tutorials/publish-governed-sqlite-registry'",
      "slug: 'configure/relay'",
      "slug: 'explanation/relay-semantics-and-disclosure'",
      "slug: 'operate/relay'",
    ],
    'Relay reader journey',
  );
  // The section mirrors the Evidence Gateway shape: an overview and the first
  // hands-on tutorial in the open, then the deeper phases grouped behind the
  // phase they belong to.
  assertOrdered(
    connect,
    ["label: 'Author a project'", "label: 'Use from applications'"],
    'Relay phase group',
  );
  // The caller's half of Relay is its own group: authoring and operating pages
  // address the institution publishing the API, not the application calling it.
  assert.match(connect, /slug: 'reference\/client-api'/);
  // Relay's operational posture specification is a Relay page, so it is seated
  // here rather than a second time in the Reference specification register.
  assert.match(connect, /slug: 'spec\/rs-op-posture'/);
  // Relay V2 is the only Relay the site documents, so the section carries no
  // preview group beside the maintained journey and none of the V1 source
  // tutorials it replaced.
  assert.doesNotMatch(connect, /label: 'Relay V2 preview'/);
  for (const retired of [
    'tutorials/publish-spreadsheet-secured-registry-api',
    'tutorials/use-your-spreadsheet',
    'tutorials/author-registry-project',
    'tutorials/configure-project-script-adapter',
    'tutorials/verify-opencrvs-claims',
  ]) {
    assert.doesNotMatch(sidebarSource, new RegExp(retired));
    assert.doesNotMatch(homepageSource, new RegExp(retired));
  }
  assert.match(homepageSource, /\]\(tutorials\/publish-governed-sqlite-registry\/\)/);
  assert.doesNotMatch(homepageSource, /tutorials\/verify-claim-registry-api/);
});

test('gives Evidence Gateway a lane on both front doors without a retired Notary path', () => {
  assert.match(homepageSource, /\]\(start\/evidence-quickstart\/\)/);
  assert.match(homepageSource, /tutorials\/first-evidence-assertion/);
  assert.doesNotMatch(homepageSource, /Expose Notary|verify-claim-registry-api/);
});

// The BReg section follows the shape the Evidence Gateway section proved: an
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
    'tutorials/extend-a-registry-with-a-module',
    'tutorials/derive-a-registry-from-publicschema',
    'tutorials/review-registry-changes',
    'tutorials/send-registry-events-to-a-webhook',
    'tutorials/query-a-spatial-registry-from-qgis',
    'configure/breg',
    'configure/breg-access',
    'configure/breg-change-control',
    'configure/breg-journeys',
    'explanation/registry-modeling-patterns',
    'explanation/governed-registry-actions',
    'explanation/native-field-patterns',
    'explanation/membership-read-boundaries',
    'explanation/deriving-a-registry-from-a-model',
    'operate/breg-requirements',
    'tutorials/build-a-breg-production-candidate',
    'operate/breg',
    'operate/breg-webhooks',
    'operate/breg-changes',
    'operate/breg-retention',
    'operate/breg-data',
    'tutorials/query-breg-client',
    'reference/client-api',
    'reference/breg-client-capabilities',
    'explanation/esignet-authentication-over-breg',
    'explanation/openfn-adaptors',
    'reference/breg-configuration',
    'reference/breg-api',
    'reference/bregctl-publicschema-wizard',
  ]);
  for (const slug of slugs) {
    assert.ok(hasDocForSlug(slug), `${slug} must be reachable from the BReg journey`);
  }
  assertOrdered(
    breg,
    [
      "slug: 'tutorials/first-breg'",
      "label: 'Tutorials'",
      "label: 'Model a registry'",
      "label: 'Deploy'",
      "label: 'Operate'",
      "label: 'Use from applications'",
      "slug: 'reference/breg-configuration'",
    ],
    'Base Registry Engine',
  );

  // The homepage names the doors into the path, not every room: the overview,
  // the first tutorial, the bridge to a deployable package, and the tutorial
  // an application developer arrives for. Requiring every BReg slug there
  // produced an eleven-link wall that read as a feature list, not a way in.
  for (const slug of [
    'start/breg-quickstart',
    'tutorials/first-breg',
    'tutorials/build-a-breg-production-candidate',
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
// Evidence Gateway. That is deployment planning, so it opens each product's
// Deploy group. It is not a first encounter, so Start carries none of it: a
// first visit meets the overview, the product chooser, and the glossary, and
// reaches every product through its own overview. The two retired Start seats
// redirect to the Deploy pages that replaced them.
test('keeps operating requirements in each product Deploy group, not in Start', () => {
  const start = topLevelSection(sidebarSource, 'Start');
  assert.ok(start, 'could not isolate Start');
  assert.deepEqual(
    [...start.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]),
    ['reference/glossary'],
  );

  const evidence = topLevelSection(sidebarSource, 'Evidence Gateway');
  assertOrdered(
    evidence,
    [
      "label: 'Deploy'",
      "slug: 'operate/evidence-requirements'",
      "slug: 'tutorials/prove-an-evidence-project'",
    ],
    'Evidence Gateway Deploy group',
  );
  const breg = topLevelSection(sidebarSource, 'Base Registry Engine');
  assertOrdered(
    breg,
    [
      "label: 'Deploy'",
      "slug: 'operate/breg-requirements'",
      "slug: 'tutorials/build-a-breg-production-candidate'",
    ],
    'Base Registry Engine Deploy group',
  );
  for (const slug of ['operate/evidence-requirements', 'operate/breg-requirements']) {
    assert.ok(hasDocForSlug(slug), `${slug} must be a published page`);
  }

  for (const retired of ['start/evaluate-evidence', 'start/evaluate-breg']) {
    assert.equal(hasDocForSlug(retired), false, `${retired} must not be a published page`);
    assert.doesNotMatch(sidebarSource, new RegExp(retired));
  }
  assert.match(
    configSource,
    /'\/start\/evaluate-evidence\/': internalRedirect\('\/operate\/evidence-requirements\/'\)/,
  );
  assert.match(
    configSource,
    /'\/start\/evaluate-breg\/': internalRedirect\('\/operate\/breg-requirements\/'\)/,
  );
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

test('organizes Evidence Gateway tasks without publishing the obsolete Relay composition', () => {
  const evidence = topLevelSection(sidebarSource, 'Evidence Gateway');
  assertOrdered(
    evidence,
    [
      // The first hands-on tutorial sits beside the overview, so opening the
      // product section reveals both starting points.
      "slug: 'tutorials/first-evidence-assertion'",
      "label: 'Use from applications'",
      "label: 'Tutorials'",
      "label: 'Connect a source'",
      "label: 'Source examples'",
      "label: 'Deploy'",
      "label: 'Wallet delivery'",
      // Reference a reader opens with the deployment in front of them, so it
      // ends this section instead of starting a Reference lookup.
      "slug: 'reference/evidence-configuration'",
      "slug: 'reference/evidence-problems'",
      "slug: 'reference/apis/registry-evidence'",
      '...openAPISidebarGroups.slice(0, 1)',
    ],
    'Evidence Gateway task group',
  );
  assert.doesNotMatch(evidence, /label: 'Verify and trust'/);
  // Token issuance stays with Registry Mint. The Evidence consumer group is
  // separate from provider authoring and wallet-delivery guidance.
  assert.doesNotMatch(evidence, /label: 'Registry Mint'/);
  assert.doesNotMatch(evidence, /label: 'Verify as a relying party'/);
  // explanation/integration-patterns held two seats, which left Starlight
  // unable to say which one is the active page and made prev/next ambiguous.
  // Its one seat is the advanced half of connecting a source.
  assert.equal(
    [...sidebarSource.matchAll(/slug: 'explanation\/integration-patterns'/g)].length,
    1,
  );
  assert.match(evidence, /slug: 'explanation\/integration-patterns'/);
  assert.doesNotMatch(evidence, /first-run-with-solmara-lab|Relay-protected|over a Relay/);
  assert.equal(hasDocForSlug('tutorials/first-run-with-solmara-lab'), false);
  assert.match(
    configSource,
    /'\/tutorials\/first-run-with-solmara-lab\/': internalRedirect\('\/start\/evidence-quickstart\/'\)/,
  );
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
    'operate/casework',
    'operate/casework-retention',
    'reference/apis/registry-casework',
    'reference/client-api',
  ]);
  for (const slug of slugs) {
    assert.ok(hasDocForSlug(slug), `${slug} must be reachable from the Casework journey`);
  }
  assert.match(casework, /\.\.\.openAPISidebarGroups\.slice\(1, 2\)/);
});

test('keeps validation on the offline relayctl commands', () => {
  // relayctl has one flat command set and the validation page may present them
  // in whatever order reads best, so assert presence rather than order.
  for (const command of ['check', 'test', 'generate', 'diff']) {
    assert.match(
      validationSource,
      new RegExp(`^relayctl ${command}\\b`, 'm'),
      `validation page must show relayctl ${command}`,
    );
  }
  // The offline claim the page has to keep making, in relayctl's own terms:
  // the checks read but never write, and ambient product configuration cannot
  // select a different Registry or deployment.
  assert.match(validationSource, /read-only/);
  assert.match(validationSource, /defines no product-specific environment-variable configuration/);
  // registryctl is retired, and relayctl runs no service: nothing on this page
  // may present a start, stop, or live-run command as a validation step.
  assert.doesNotMatch(validationSource, /\bregistryctl\b/);
  assert.doesNotMatch(
    validationSource,
    /\brelayctl (?:start|stop|restart|status|open|smoke|logs|dev|doctor|build|review)\b/,
  );
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

test('legacy first-run entry points redirect to supported 1.0 paths', () => {
  assert.match(configSource, /'\/start\/': internalRedirect\('\/'\)/);
  assert.match(
    configSource,
    /'\/start\/see-it-live\/': internalRedirect\('\/'\)/,
  );
  assert.match(
    configSource,
    /'\/start\/your-first-call\/': internalRedirect\('\/tutorials\/publish-governed-sqlite-registry\/'\)/,
  );
  assert.match(
    configSource,
    /'\/tutorials\/first-run-with-registry-lab\/': internalRedirect\('\/'\)/,
  );
  // The retired V1 source tutorials still resolve: their redirects moved into
  // the Relay V2 retirement module, so assert that map rather than the config
  // text, where a search for the old keys would now pass for the wrong reason.
  for (const retired of [
    '/tutorials/publish-spreadsheet-secured-registry-api/',
    '/tutorials/use-your-spreadsheet/',
    '/tutorials/author-registry-project/',
  ]) {
    assert.equal(
      RETIRED_RELAY_ROUTE_TARGETS[retired],
      '/tutorials/publish-governed-sqlite-registry/',
      `${retired} must redirect to the maintained governed-registry tutorial`,
    );
  }
  assert.match(configSource, /buildRelayV2RetirementRedirects\(currentDocsetRedirect\)/);
  assert.match(configSource, /buildNotaryRetirementRedirects\(currentDocsetRedirect\)/);
});

test('keeps source-assurance artifacts out of the adopter navigation', () => {
  assert.doesNotMatch(sidebarSource, /label: 'Journeys'|label: 'Source assurance'/);
  assert.doesNotMatch(sidebarSource, /slug: 'journeys/);
  assert.match(configSource, /'\/journeys\/': internalRedirect\('\/'\)/);
});
