// Guards the Registry Stack 1.0 product outcomes and their stable entry points.

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

import { RETIRED_RELAY_ROUTE_TARGETS } from '../src/lib/relay-v2-retirement-redirects.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const configSource = readFileSync(resolve(siteRoot, 'astro.config.mjs'), 'utf8');
const homepageSource = readFileSync(resolve(siteRoot, 'src/content/docs/index.mdx'), 'utf8');
const quickstartSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/start/quickstart.mdx'),
  'utf8',
);
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

function assertOrdered(source, expectations, label) {
  let position = -1;
  for (const expectation of expectations) {
    const next = source.indexOf(expectation, position + 1);
    assert.ok(next > position, `missing or misplaced ${label}: ${expectation}`);
    position = next;
  }
}

test('uses the adopter-first top-level flow in its published order', () => {
  assert.deepEqual(topLevelLabels(sidebarSource), [
    'Start',
    'Answer with Evidence Gateway',
    'Connect an existing registry',
    'Operate across products',
    'Security',
    'Reference',
  ]);
});

test('publishes one overview route for every task-flow section', () => {
  for (const [label, route] of [
    ['Start', "link: '/'"],
    ['Answer with Evidence Gateway', "slug: 'start/evidence-quickstart'"],
    ['Connect an existing registry', "slug: 'configure'"],
    ['Operate across products', "slug: 'operate/advanced'"],
    ['Security', "slug: 'security'"],
    ['Reference', "slug: 'reference'"],
  ]) {
    const section = topLevelSection(sidebarSource, label);
    assert.ok(section, `could not isolate ${label}`);
    assert.match(section, new RegExp(route.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

// A page that names one product belongs under that product, so a reader
// following one adoption path never leaves it. The two cross-product sections
// keep only what applies to every deployment.
test('files product-scoped pages under their product, not under the cross-product sections', () => {
  const crossProduct = topLevelSection(sidebarSource, 'Operate across products');
  const relay = topLevelSection(sidebarSource, 'Connect an existing registry');
  for (const relayOnly of ['operate', 'operate/relay']) {
    const entry = new RegExp(`slug: '${relayOnly.replaceAll('/', '\\/')}' \\}`);
    assert.doesNotMatch(
      crossProduct,
      entry,
      `${relayOnly} documents Registry Relay and belongs in the Relay section`,
    );
    assert.match(relay, entry, `the Relay section must carry ${relayOnly}`);
  }

  const security = topLevelSection(sidebarSource, 'Security');
  assert.doesNotMatch(security, /slug: 'security\/evidence'/);
  const evidence = topLevelSection(sidebarSource, 'Answer with Evidence Gateway');
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
  // hands-on tutorial in the open, then the deeper phases collapsed behind the
  // phase they belong to.
  assertOrdered(
    connect,
    ["label: 'Author a project'", "label: 'Operate Relay'"],
    'Relay phase group',
  );
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
    assert.doesNotMatch(quickstartSource, new RegExp(retired));
  }
  assert.match(homepageSource, /\]\(tutorials\/publish-governed-sqlite-registry\/\)/);
  assert.match(
    quickstartSource,
    /\]\(\.\.\/\.\.\/tutorials\/publish-governed-sqlite-registry\/\)/,
  );
  assert.doesNotMatch(homepageSource, /tutorials\/verify-claim-registry-api/);
  assert.doesNotMatch(quickstartSource, /tutorials\/verify-claim-registry-api/);
});

test('gives Evidence Gateway a lane on both front doors without a retired Notary path', () => {
  assert.match(homepageSource, /\]\(start\/evidence-quickstart\/\)/);
  assert.match(quickstartSource, /\]\(\.\.\/evidence-quickstart\/\)/);
  assert.match(homepageSource, /tutorials\/first-evidence-assertion/);
  assert.match(quickstartSource, /tutorials\/first-evidence-assertion/);
  assert.doesNotMatch(homepageSource, /Expose Notary|verify-claim-registry-api/);
  assert.doesNotMatch(quickstartSource, /Expose Notary|verify-claim-registry-api/);
});

test('organizes Evidence Gateway tasks without publishing the obsolete Relay composition', () => {
  const evidence = topLevelSection(sidebarSource, 'Answer with Evidence Gateway');
  assertOrdered(
    evidence,
    [
      // The first hands-on tutorial sits beside the overview rather than inside
      // a collapsed group, so a first-time reader reaches it without opening
      // anything.
      "slug: 'tutorials/first-evidence-assertion'",
      "label: 'Learn locally'",
      "label: 'Connect a source'",
      "label: 'Prepare and deploy'",
      "label: 'Authenticate callers'",
      // Relying-party verification and wallet delivery are different audiences
      // with different deployments, so they are separate groups.
      "label: 'Verify as a relying party'",
      "label: 'Deliver to wallets'",
      "label: 'Operate Evidence Gateway'",
    ],
    'Evidence Gateway task group',
  );
  assert.doesNotMatch(evidence, /label: 'Verify and trust'/);
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
  // the checks read but never write, and the command line is the whole input.
  assert.match(validationSource, /read-only/);
  assert.match(validationSource, /reads no environment variables/);
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
  assert.doesNotMatch(quickstartSource, /pre-1\.0-cutover/);
});

test('every hand-authored sidebar slug resolves to a published documentation page', () => {
  const slugs = [...sidebarSource.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]);
  const missing = [...new Set(slugs)].filter((slug) => !hasDocForSlug(slug));

  assert.deepEqual(missing, []);
});

test('legacy first-run entry points redirect to supported 1.0 paths', () => {
  assert.match(configSource, /'\/start\/': internalRedirect\('\/'\)/);
  assert.match(
    configSource,
    /'\/start\/see-it-live\/': internalRedirect\('\/start\/quickstart\/'\)/,
  );
  assert.match(
    configSource,
    /'\/start\/your-first-call\/': internalRedirect\('\/tutorials\/publish-governed-sqlite-registry\/'\)/,
  );
  assert.match(
    configSource,
    /'\/tutorials\/first-run-with-registry-lab\/': internalRedirect\('\/start\/quickstart\/'\)/,
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
