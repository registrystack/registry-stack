// Guards the Phase 2 task-oriented documentation IA. The site keeps the
// existing public page URLs, so this test checks both the sidebar discovery
// path and the redirects that preserve older entry points.

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const here = dirname(fileURLToPath(import.meta.url));
const siteRoot = resolve(here, '..');
const configSource = readFileSync(resolve(siteRoot, 'astro.config.mjs'), 'utf8');
const homepageSource = readFileSync(resolve(siteRoot, 'src/content/docs/index.mdx'), 'utf8');
const firstApiSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx'),
  'utf8',
);
const firstClaimSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/tutorials/verify-claim-registry-api.mdx'),
  'utf8',
);
const spreadsheetAssuranceSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/journeys/spreadsheet-protected-api.mdx'),
  'utf8',
);
const claimAssuranceSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/journeys/registry-backed-notary-claim.mdx'),
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

function assertReleasedTaskRoute(source) {
  assert.doesNotMatch(source, /\]\([^)]*start\/test-current-source-revision/);
}

function assertReleaseFormClaimTutorial(source) {
  assert.match(source, /population-record-exists/);
  assert.match(source, /registryctl init --from snapshot --project-dir my-first-claim/);
  assert.doesNotMatch(
    source,
    /person-registration-accepted|active-registration-exists|active-or-pending-registration-exists/,
  );
  assert.doesNotMatch(source, /Unreleased Main-source tutorial|current-source test procedure/);
}

function assertReleaseFormFirstApiSequence(source) {
  const headings = [
    '## Install Registryctl',
    '## Create the canonical project',
    '## Run the required preflight',
    '## Start the API',
    '## Run the maintained checks',
    '## Make one denied request',
    '## Make one allowed request',
    '## Inspect the human-owned boundary',
    '## Stop and clean up',
  ];
  let position = -1;
  for (const heading of headings) {
    const next = source.indexOf(heading);
    assert.ok(next > position, `missing or misplaced required first-API step: ${heading}`);
    position = next;
  }
  assert.doesNotMatch(
    source,
    /Main source|test-current-source-revision|cargo install|git clone|Podman|OrbStack|Colima/,
  );
  assert.match(source, /Linux amd64/);
  assert.match(source, /Docker Engine with Compose v2/);
}

test('uses the Phase 2 top-level task flow in its published order', () => {
  assert.deepEqual(topLevelLabels(sidebarSource), [
    'Start',
    'Journeys',
    'Configure',
    'Verify',
    'Generated artifacts',
    'Operate',
    'Reference',
    'Specifications',
  ]);
});

test('publishes one stable overview route for every task-flow section', () => {
  for (const [label, route] of [
    ['Start', "link: '/'"],
    ['Journeys', "slug: 'journeys'"],
    ['Configure', "slug: 'configure'"],
    ['Verify', "slug: 'verify'"],
    ['Generated artifacts', "slug: 'generated-artifacts'"],
    ['Operate', "slug: 'operate'"],
    ['Reference', "slug: 'reference'"],
    ['Specifications', "slug: 'spec'"],
  ]) {
    const section = topLevelSection(sidebarSource, label);
    assert.ok(section, `could not isolate ${label}`);
    assert.match(section, new RegExp(route.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('puts released first-result tasks directly in Start', () => {
  const start = topLevelSection(sidebarSource, 'Start');
  assert.ok(start, 'could not isolate Start');
  assert.match(
    start,
    /label: 'Your first registry API', slug: 'tutorials\/publish-spreadsheet-secured-registry-api'/,
  );
  assert.match(
    start,
    /label: 'Your first claim check', slug: 'tutorials\/verify-claim-registry-api'/,
  );
  assert.doesNotMatch(start, /start\/test-current-source-revision/);
});

test('keeps generated Main-source journeys on the assurance rail', () => {
  const journeys = topLevelSection(sidebarSource, 'Journeys');
  assert.ok(journeys, 'could not isolate Journeys');
  assert.match(journeys, /Spreadsheet protected API assurance \(Main source\)/);
  assert.match(journeys, /Registry-backed Notary claim assurance \(Main source\)/);
  assert.doesNotMatch(journeys, /label: 'Your first registry API'/);
  assert.doesNotMatch(journeys, /label: 'Your first claim check'/);
});

test('keeps the Relay and Notary generated product navigation under Configure', () => {
  const configureSource = sidebarSource.match(
    /label: 'Configure',[\s\S]*?(?=\n        \{\n          label: 'Verify',)/,
  )?.[0];

  assert.ok(configureSource, 'could not isolate the Configure sidebar section');
  assert.match(configureSource, /label: 'Registry Relay',[\s\S]*?generatedProduct\('Relay'\)\.items/);
  assert.match(configureSource, /label: 'Registry Notary',[\s\S]*?generatedProduct\('Notary'\)\.items/);
});

test('keeps generated-artifact navigation tied to the Manifest product group', () => {
  const artifactsSource = sidebarSource.match(
    /label: 'Generated artifacts',[\s\S]*?(?=\n        \{\n          \/\/ Stack-wide operator)/,
  )?.[0];

  assert.ok(artifactsSource, 'could not isolate the Generated artifacts sidebar section');
  assert.match(artifactsSource, /label: 'Registry Manifest',[\s\S]*?generatedProduct\('Manifest'\)\.items/);
  assert.match(artifactsSource, /slug: 'reference\/contracts'/);
});

test('every hand-authored sidebar slug resolves to a published documentation page', () => {
  const slugs = [...sidebarSource.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]);
  const missing = [...new Set(slugs)].filter((slug) => !hasDocForSlug(slug));

  assert.deepEqual(missing, []);
});

test('legacy entry points redirect to released task pages', () => {
  assert.match(configSource, /'\/start\/': internalRedirect\('\/'\)/);
  assert.match(
    configSource,
    /'\/start\/see-it-live\/': internalRedirect\('\/tutorials\/publish-spreadsheet-secured-registry-api\/'\)/,
  );
  assert.match(
    configSource,
    /'\/start\/your-first-call\/': internalRedirect\('\/tutorials\/first-run-with-solmara-lab\/'\)/,
  );
  assert.match(
    configSource,
    /'\/tutorials\/first-run-with-registry-lab\/': internalRedirect\('\/tutorials\/first-run-with-solmara-lab\/'\)/,
  );
});

test('homepage and first-result tasks stay on the release-form beginner rail', () => {
  assert.match(homepageSource, /\]\(tutorials\/publish-spreadsheet-secured-registry-api\/\)/);
  assert.match(homepageSource, /\]\(tutorials\/verify-claim-registry-api\/\)/);
  assert.doesNotMatch(homepageSource, /\]\(journeys\//);
  assertReleasedTaskRoute(firstApiSource);
  assertReleasedTaskRoute(firstClaimSource);
  assertReleaseFormFirstApiSequence(firstApiSource);
  assertReleaseFormClaimTutorial(firstClaimSource);
  assert.ok(hasDocForSlug('tutorials/publish-spreadsheet-secured-registry-api'));
  assert.ok(hasDocForSlug('tutorials/verify-claim-registry-api'));
});

test('tasks and Main-source assurance pages link to each other by reader purpose', () => {
  assert.match(firstApiSource, /\]\(\.\.\/\.\.\/journeys\/spreadsheet-protected-api\/\)/);
  assert.match(firstClaimSource, /\]\(\.\.\/\.\.\/journeys\/registry-backed-notary-claim\/\)/);
  assert.match(spreadsheetAssuranceSource, /^doc_type: reference$/m);
  assert.match(claimAssuranceSource, /^doc_type: reference$/m);
  assert.match(spreadsheetAssuranceSource, /\]\(\.\.\/\.\.\/tutorials\/publish-spreadsheet-secured-registry-api\/\)/);
  assert.match(claimAssuranceSource, /\]\(\.\.\/\.\.\/tutorials\/verify-claim-registry-api\/\)/);
});

test('beginner-rail control rejects a planted Main-source route', () => {
  assert.throws(
    () => assertReleasedTaskRoute('[source test](../../start/test-current-source-revision/)'),
    /test-current-source-revision/,
  );
  assert.throws(
    () => assertReleaseFormClaimTutorial('active-registration-exists'),
    /population-record-exists/,
  );
  assert.throws(
    () => assertReleaseFormFirstApiSequence('## Install Registryctl\n## Start the API'),
    /Create the canonical project/,
  );
});
