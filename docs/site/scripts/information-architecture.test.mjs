// Guards the Registry Stack 1.0 product outcomes and their stable entry points.

import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { cliReferenceSidebar } from '../src/lib/cli-reference-sidebar.mjs';
import { RETIRED_RELAY_ROUTE_TARGETS } from '../src/lib/relay-v2-retirement-redirects.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const configSource = readFileSync(resolve(siteRoot, 'astro.config.mjs'), 'utf8');
const homepageSource = readFileSync(resolve(siteRoot, 'src/content/docs/index.mdx'), 'utf8');
const validationSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/verify/index.mdx'),
  'utf8',
);
const sidebarSource = configSource.match(/sidebar: \[([\s\S]*?)\n      \],\n    \}\),/)?.[1];

assert.ok(sidebarSource, 'could not isolate the Starlight sidebar configuration');

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
// collection, in the form the sidebar uses to address it: `start/when-to-use`
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
  // That group seats the index and the binaries, not the subcommand pages
  // under them. Publishing the command-line reference will therefore make this
  // test name every subcommand page at once, and seating them is part of that
  // publish rather than a fault in this gate.
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

// Top level is a list of tasks an adopter can name, not a list of products.
// The product that serves a task is named inside the section, so a reader who
// does not yet know which product they need can still pick a door.
test('uses the adopter-first top-level flow in its published order', () => {
  assert.deepEqual(topLevelLabels(sidebarSource), [
    'Start',
    'Answer a bounded question',
    'Connect an existing registry',
    'Build a registry',
    'Consume and verify assertions',
    'Authenticate callers',
    'Publish a Discovery index',
    'Operate and secure',
    'Understand the design',
    'Reference',
  ]);
});

test('publishes one overview route for every task-flow section that has one', () => {
  for (const [label, route] of [
    ['Start', "link: '/'"],
    ['Answer a bounded question', "slug: 'start/evidence-quickstart'"],
    ['Connect an existing registry', "slug: 'configure'"],
    ['Build a registry', "slug: 'explanation/configuration-defined-registry'"],
    ['Operate and secure', "slug: 'operate/advanced'"],
    ['Reference', "slug: 'reference'"],
  ]) {
    const section = topLevelSection(sidebarSource, label);
    assert.ok(section, `could not isolate ${label}`);
    assert.match(section, new RegExp(route.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }

  // Consume and verify assertions ships without an overview because no page
  // yet addresses a relying party who has not chosen a product. The section is
  // three tutorials that each stand alone, so it opens on the first of them
  // rather than on a page written for a different reader.
  const consume = topLevelSection(sidebarSource, 'Consume and verify assertions');
  assert.ok(consume, 'could not isolate Consume and verify assertions');
  assert.doesNotMatch(consume, /label: 'Overview'/);
});

// A page that names one product belongs under that product while the reader is
// still adopting it, so a reader following one adoption path never leaves it.
// Operate and secure is the exception the operator earns: after handoff the
// reader is on call for a running deployment, not choosing a product, so pages
// that name a runtime sit beside the ones that do not.
test('files adoption-time pages under their product', () => {
  const relay = topLevelSection(sidebarSource, 'Connect an existing registry');
  const operate = topLevelSection(sidebarSource, 'Operate and secure');
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
  const security = topLevelSection(sidebarSource, 'Operate and secure');
  assert.doesNotMatch(security, /slug: 'security\/evidence'/);
  const evidence = topLevelSection(sidebarSource, 'Answer a bounded question');
  assert.match(evidence, /slug: 'security\/evidence'/);
});

test('publishes one Relay reader journey without the retired V1 routes', () => {
  const start = topLevelSection(sidebarSource, 'Start');
  assert.doesNotMatch(
    start,
    /slug: 'tutorials\//,
  );
  const connect = topLevelSection(sidebarSource, 'Connect an existing registry');
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
    ["label: 'Author a project'", "label: 'Call a Relay API'"],
    'Relay phase group',
  );
  // The caller's half of Relay is its own group: authoring and operating pages
  // address the institution publishing the API, not the application calling it.
  assert.match(connect, /slug: 'reference\/relay-client-api'/);
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

test('keeps the Server guide and references in one adoption path', () => {
  const server = topLevelSection(sidebarSource, 'Build a registry');
  const slugs = [...server.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]);
  assert.deepEqual(slugs, [
    'explanation/configuration-defined-registry',
    'tutorials/first-registry-server',
    'configure/registry-server',
    'configure/registry-server-webhooks',
    'reference/registry-server-configuration',
    'reference/registry-server-events',
  ]);
  for (const slug of slugs) {
    assert.ok(hasDocForSlug(slug), `${slug} must be reachable from the Server journey`);
    assert.ok(homepageSource.includes(`](${slug}/)`), `${slug} must be linked from the homepage`);
  }
});

test('organizes Evidence Gateway tasks without publishing the obsolete Relay composition', () => {
  const evidence = topLevelSection(sidebarSource, 'Answer a bounded question');
  assertOrdered(
    evidence,
    [
      // The first hands-on tutorial sits beside the overview rather than inside
      // a collapsed group, so a first-time reader reaches it without opening
      // anything.
      "slug: 'tutorials/first-evidence-assertion'",
      "label: 'Learn locally'",
      "label: 'Connect your own source'",
      "label: 'Worked examples'",
      "label: 'Prepare and deploy'",
      "label: 'Deliver to wallets'",
      // Reference a reader opens with the deployment in front of them, so it
      // ends this section instead of starting a Reference lookup.
      "slug: 'reference/evidence-configuration'",
      "slug: 'reference/evidence-problems'",
      "label: 'HTTP API'",
    ],
    'Evidence Gateway task group',
  );
  assert.doesNotMatch(evidence, /label: 'Verify and trust'/);
  // Token issuance and relying-party verification are separate audiences that
  // reach Evidence Gateway from outside it, so each is a section of its own
  // rather than a group buried in the provider's path.
  assert.doesNotMatch(evidence, /label: 'Authenticate callers'/);
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

// `start/quickstart` was a second chooser beside `start/when-to-use`: both told
// a reader which of the two products answered their problem, and only one of
// them had a seat. It is retired rather than repurposed, so the four redirects
// that pointed at it now land on the chooser that stayed, and so does its own
// route, which was published and so has readers holding links to it.
test('does not publish the retired second stack chooser', () => {
  assert.equal(
    existsSync(resolve(siteRoot, 'src/content/docs/start/quickstart.mdx')),
    false,
  );
  assert.doesNotMatch(sidebarSource, /start\/quickstart/);
  assert.doesNotMatch(homepageSource, /start\/quickstart/);
  assert.match(
    configSource,
    /'\/start\/quickstart\/': internalRedirect\('\/start\/when-to-use\/'\)/,
  );
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
    /'\/start\/see-it-live\/': internalRedirect\('\/start\/when-to-use\/'\)/,
  );
  assert.match(
    configSource,
    /'\/start\/your-first-call\/': internalRedirect\('\/tutorials\/publish-governed-sqlite-registry\/'\)/,
  );
  assert.match(
    configSource,
    /'\/tutorials\/first-run-with-registry-lab\/': internalRedirect\('\/start\/when-to-use\/'\)/,
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
