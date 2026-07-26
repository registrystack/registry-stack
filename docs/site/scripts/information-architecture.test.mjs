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

test('legacy entry points redirect to current task-flow pages', () => {
  assert.match(configSource, /'\/start\/': internalRedirect\('\/'\)/);
  assert.match(
    configSource,
    /'\/start\/see-it-live\/': internalRedirect\('\/journeys\/spreadsheet-protected-api\/'\)/,
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

test('homepage starts with the maintained spreadsheet journey while the detailed tutorial remains available', () => {
  assert.match(homepageSource, /\]\(journeys\/spreadsheet-protected-api\/\)/);
  assert.match(sidebarSource, /slug: 'journeys\/spreadsheet-protected-api'/);
  assert.ok(hasDocForSlug('tutorials/publish-spreadsheet-secured-registry-api'));
});
