// Guards the adopter-first documentation IA. The site keeps the
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
const registryBannerSource = readFileSync(
  resolve(siteRoot, 'src/components/RegistryBanner.astro'),
  'utf8',
);
const firstApiSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/tutorials/publish-spreadsheet-secured-registry-api.mdx'),
  'utf8',
);
const firstClaimSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/tutorials/verify-claim-registry-api.mdx'),
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

function assertOrdered(source, expectations, label) {
  let position = -1;
  for (const expectation of expectations) {
    const next = source.indexOf(expectation, position + 1);
    assert.ok(next > position, `missing or misplaced ${label}: ${expectation}`);
    position = next;
  }
}

function assertLiveClaimTutorial(source) {
  assertOrdered(
    source,
    [
      'my-first-api',
      'registryctl add notary',
      '## Start Relay and Notary',
      'registryctl start',
      'HTTP 403',
      '## Evaluate the active project',
      '## Evaluate the planned project',
      '## Check an absent record',
      '## Change the status policy',
      'registryctl restart',
      '"value": true',
      'registryctl stop',
    ],
    'live first-claim step',
  );
  for (const expected of [
    /project-record-exists/,
    /project-status-accepted/,
    /"value": "pw_001"/,
    /"value": "PW-002"/,
    /"value": "pw_999"/,
    /public-works-case-management/,
    /evidence:projects:read/,
    /http:\/\/127\.0\.0\.1:4255\/v1\/evaluations/,
    /You\s+do not edit `?\.registry-stack\//,
  ]) {
    assert.match(source, expected);
  }
  assert.doesNotMatch(
    source,
    /registryctl init --from snapshot|git clone|git switch|cargo build|registryctl build/,
  );
  assert.doesNotMatch(source, /Unreleased Main-source tutorial|current-source test procedure/);
}

function assertReleaseFormFirstApiSequence(source) {
  const headings = [
    '## Install Registryctl',
    '## Create the sample project',
    '## Check your computer and project',
    '## Start the API',
    '## Check the API',
    '## Make one denied request',
    '## Make one allowed request',
    '## See what you can edit',
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

test('uses the adopter-first top-level flow in its published order', () => {
  assert.deepEqual(topLevelLabels(sidebarSource), [
    'Start',
    'Connect your data',
    'Operate',
    'Security',
    'Reference',
  ]);
});

test('publishes one stable overview route for every task-flow section', () => {
  for (const [label, route] of [
    ['Start', "link: '/'"],
    ['Connect your data', "slug: 'configure'"],
    ['Operate', "slug: 'operate'"],
    ['Security', "slug: 'security'"],
    ['Reference', "slug: 'reference'"],
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
    /label: 'Run your first registry API', slug: 'tutorials\/publish-spreadsheet-secured-registry-api'/,
  );
  assert.match(
    start,
    /label: 'Verify a live claim', slug: 'tutorials\/verify-claim-registry-api'/,
  );
  assert.doesNotMatch(start, /start\/test-current-source-revision/);
});

test('does not expose source-assurance material as an adopter journey', () => {
  assert.doesNotMatch(sidebarSource, /label: 'Journeys'|label: 'Source assurance'/);
  assert.doesNotMatch(sidebarSource, /slug: 'journeys/);
  assert.match(configSource, /'\/journeys\/': internalRedirect\('\/'\)/);
});

test('archived pages send readers directly to the current preview docset', () => {
  assert.match(registryBannerSource, /<a href="\/preview\/">Latest<\/a>/);
  assert.doesNotMatch(registryBannerSource, /<a href="\/">Latest<\/a>/);
});

test('keeps detailed product navigation under collapsed Reference', () => {
  const reference = topLevelSection(sidebarSource, 'Reference');
  assert.ok(reference, 'could not isolate Reference');
  assert.match(reference, /label: 'Registry Relay',[\s\S]*?generatedProduct\('Relay'\)\.items/);
  assert.match(reference, /label: 'Registry Notary',[\s\S]*?generatedProduct\('Notary'\)\.items/);
  assert.match(reference, /label: 'Registry Manifest',[\s\S]*?generatedProduct\('Manifest'\)\.items/);
  assert.match(reference, /label: 'Specifications',[\s\S]*?slug: 'spec'/);
});

test('keeps validation and generated-file help available without making new rails', () => {
  const reference = topLevelSection(sidebarSource, 'Reference');
  assert.match(reference, /label: 'Validate a project', slug: 'verify'/);
  assert.match(reference, /label: 'Generated files and ownership', slug: 'generated-artifacts'/);
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
});

test('homepage and first-result tasks stay on the release-form beginner rail', () => {
  assert.match(homepageSource, /\]\(tutorials\/publish-spreadsheet-secured-registry-api\/\)/);
  assert.match(homepageSource, /\]\(tutorials\/verify-claim-registry-api\/\)/);
  assert.doesNotMatch(homepageSource, /\]\(journeys\//);
  assertReleasedTaskRoute(firstApiSource);
  assertReleasedTaskRoute(firstClaimSource);
  assertReleaseFormFirstApiSequence(firstApiSource);
  assertLiveClaimTutorial(firstClaimSource);
  assert.ok(hasDocForSlug('tutorials/publish-spreadsheet-secured-registry-api'));
  assert.ok(hasDocForSlug('tutorials/verify-claim-registry-api'));
});

test('beginner tasks link to useful next tasks, not assurance pages', () => {
  assert.doesNotMatch(firstApiSource, /journeys\//);
  assert.doesNotMatch(firstClaimSource, /journeys\//);
  assert.match(firstApiSource, /\]\(\.\.\/use-your-spreadsheet\/\)/);
  assert.match(firstClaimSource, /\]\(\.\.\/\.\.\/configure\/\)/);
});

test('beginner-rail control rejects a planted Main-source route', () => {
  assert.throws(
    () => assertReleasedTaskRoute('[source test](../../start/test-current-source-revision/)'),
    /test-current-source-revision/,
  );
  assert.throws(
    () => assertLiveClaimTutorial('registryctl add notary'),
    /my-first-api/,
  );
  assert.throws(
    () => assertReleaseFormFirstApiSequence('## Install Registryctl\n## Start the API'),
    /Create the sample project/,
  );
});
