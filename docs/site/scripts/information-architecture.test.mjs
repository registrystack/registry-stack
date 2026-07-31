// Guards the single Registry Stack 1.0 adopter path and its stable entry points.

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
const cutoverSource = readFileSync(
  resolve(siteRoot, 'src/content/docs/start/pre-1.0-cutover.mdx'),
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
    'Connect your data',
    'Operate',
    'Security',
    'Reference',
  ]);
});

test('publishes one overview route for every task-flow section', () => {
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

test('publishes one HTTP first run and one pre-1.0 cutover route', () => {
  const start = topLevelSection(sidebarSource, 'Start');
  assert.match(
    start,
    /label: 'Build an HTTP project', slug: 'tutorials\/author-registry-project'/,
  );
  assert.match(
    start,
    /label: 'Pre-1.0 cutover', slug: 'start\/pre-1\.0-cutover'/,
  );
  assert.match(
    homepageSource,
    /\]\(tutorials\/author-registry-project\/\)/,
  );
  assert.match(
    quickstartSource,
    /\]\(\.\.\/\.\.\/tutorials\/author-registry-project\/\)/,
  );
  assert.match(homepageSource, /\]\(start\/pre-1\.0-cutover\/\)/);
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

test('keeps removed command mappings on the cutover page only', () => {
  assert.match(cutoverSource, /Pre-1\.0 commands have no aliases/);
  assert.match(cutoverSource, /no automated migration path/);
  assert.match(cutoverSource, /`registryctl start`/);
  assert.match(cutoverSource, /`registryctl dev`/);
  assert.match(cutoverSource, /Bruno generation/);
  assert.match(cutoverSource, /The public 1\.0 starter is `http`/);
  assert.doesNotMatch(cutoverSource, /--template spreadsheet/);
});

test('every hand-authored sidebar slug resolves to a published documentation page', () => {
  const slugs = [...sidebarSource.matchAll(/slug: '([^']+)'/g)].map((match) => match[1]);
  const missing = [...new Set(slugs)].filter((slug) => !hasDocForSlug(slug));

  assert.deepEqual(missing, []);
});

test('legacy first-run entry points redirect to the 1.0 HTTP path', () => {
  assert.match(configSource, /'\/start\/': internalRedirect\('\/'\)/);
  assert.match(
    configSource,
    /'\/start\/see-it-live\/': internalRedirect\('\/start\/quickstart\/'\)/,
  );
  assert.match(
    configSource,
    /'\/start\/your-first-call\/': internalRedirect\('\/tutorials\/author-registry-project\/'\)/,
  );
  assert.match(
    configSource,
    /'\/tutorials\/first-run-with-registry-lab\/': internalRedirect\('\/start\/quickstart\/'\)/,
  );
  for (const route of [
    'publish-spreadsheet-secured-registry-api',
    'use-your-spreadsheet',
    'verify-claim-registry-api',
  ]) {
    assert.match(
      configSource,
      new RegExp(
        `'\\/tutorials\\/${route}\\/'` +
          `: internalRedirect\\('\\/tutorials\\/author-registry-project\\/'\\)`,
      ),
    );
  }
});

test('keeps source-assurance artifacts out of the adopter navigation', () => {
  assert.doesNotMatch(sidebarSource, /label: 'Journeys'|label: 'Source assurance'/);
  assert.doesNotMatch(sidebarSource, /slug: 'journeys/);
  assert.match(configSource, /'\/journeys\/': internalRedirect\('\/'\)/);
});
