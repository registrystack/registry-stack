// Guards the Registry Stack 1.0 product outcomes and their stable entry points.

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';

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
    'Operate',
    'Security',
    'Reference',
  ]);
});

test('publishes one overview route for every task-flow section', () => {
  for (const [label, route] of [
    ['Start', "link: '/'"],
    ['Answer with Evidence Gateway', "slug: 'start/evidence-quickstart'"],
    ['Connect an existing registry', "slug: 'explanation/governed-registry-publication'"],
    ['Operate', "slug: 'operate'"],
    ['Security', "slug: 'security'"],
    ['Reference', "slug: 'reference'"],
  ]) {
    const section = topLevelSection(sidebarSource, label);
    assert.ok(section, `could not isolate ${label}`);
    assert.match(section, new RegExp(route.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('keeps the compact Relay V2 reader journey under existing registries', () => {
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
      "slug: 'operate/relay'",
      "slug: 'explanation/relay-semantics-and-disclosure'",
    ],
    'Relay V2 reader journey',
  );
  assert.doesNotMatch(connect, /registryctl|author-registry-project|publish-spreadsheet/);
  assert.doesNotMatch(connect, /verify-opencrvs-claims/);
  assert.match(
    homepageSource,
    /\]\(tutorials\/publish-governed-sqlite-registry\/\)/,
  );
  assert.match(
    quickstartSource,
    /\]\(\.\.\/\.\.\/tutorials\/publish-governed-sqlite-registry\/\)/,
  );
  assert.match(homepageSource, /\]\(configure\/relay\/\)/);
  assert.match(quickstartSource, /\]\(\.\.\/\.\.\/configure\/relay\/\)/);
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
      "label: 'Learn locally'",
      "label: 'Connect a source'",
      "label: 'Prepare and deploy'",
      "label: 'Authenticate callers'",
      "label: 'Verify and trust'",
      "label: 'Operate Evidence Gateway'",
    ],
    'Evidence Gateway task group',
  );
  assert.doesNotMatch(evidence, /first-run-with-solmara-lab|Relay-protected|over a Relay/);
  assert.equal(hasDocForSlug('tutorials/first-run-with-solmara-lab'), false);
  assert.match(
    configSource,
    /'\/tutorials\/first-run-with-solmara-lab\/': internalRedirect\('\/start\/evidence-quickstart\/'\)/,
  );
});

test('keeps validation on offline test and nested development commands', () => {
  assertOrdered(
    validationSource,
    [
      'registryctl test',
      'registryctl check',
      'registryctl review compare',
      'registryctl build',
      'registryctl doctor',
      'registryctl dev --detach',
      'registryctl dev status',
      'registryctl dev smoke',
      'registryctl dev logs',
      'registryctl dev down',
    ],
    'Registryctl 1.0 validation command',
  );
  assert.match(validationSource, /without contacting a live source/);
  assert.doesNotMatch(
    validationSource,
    /registryctl (?:start|stop|restart|status|open|smoke|logs|preflight|capabilities)\b/,
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
    /'\/start\/your-first-call\/': internalRedirect\('\/tutorials\/publish-spreadsheet-secured-registry-api\/'\)/,
  );
  assert.match(
    configSource,
    /'\/tutorials\/first-run-with-registry-lab\/': internalRedirect\('\/start\/quickstart\/'\)/,
  );
  assert.doesNotMatch(
    configSource,
    /'\/tutorials\/(?:publish-spreadsheet-secured-registry-api|use-your-spreadsheet)\/':/,
  );
  assert.match(configSource, /buildNotaryRetirementRedirects\(currentDocsetRedirect\)/);
});

test('keeps source-assurance artifacts out of the adopter navigation', () => {
  assert.doesNotMatch(sidebarSource, /label: 'Journeys'|label: 'Source assurance'/);
  assert.doesNotMatch(sidebarSource, /slug: 'journeys/);
  assert.match(configSource, /'\/journeys\/': internalRedirect\('\/'\)/);
});
