// Unit tests for the product-sidebar transform (scripts/generate-sidebar.mjs).
// Run with `npm test` (node --test). The transform is pure: manifest in,
// Starlight sidebar groups out. These tests pin the grouping rules so the
// generated navigation cannot silently drift.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import YAML from 'yaml';

import { SUBGROUP_THRESHOLD, buildProductSidebar } from './generate-sidebar.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const manifestPath = resolve(here, '../src/data/repo-docs.yaml');

// Collect every {label, slug} leaf in a sidebar tree, depth-first.
function leaves(items, acc = []) {
  for (const item of items) {
    if (Array.isArray(item.items)) leaves(item.items, acc);
    else acc.push(item);
  }
  return acc;
}

function doc(dest, doc_type, nav_order, label) {
  return { src: `docs/${dest}.md`, dest, doc_type, nav_order, label };
}

// A product with more than the threshold of non-index docs: must sub-group.
const bigRepo = {
  repos: {
    'registry-big': {
      docs: [
        doc('products/registry-big/index', 'explanation', 0, 'Registry Big'),
        doc('products/registry-big/t1', 'tutorial', 10, 'Tutorial one'),
        doc('products/registry-big/h1', 'how-to', 30, 'How-to one'),
        doc('products/registry-big/h2', 'how-to', 20, 'How-to two'),
        doc('products/registry-big/r1', 'reference', 40, 'Ref one'),
        doc('products/registry-big/e1', 'explanation', 50, 'Explain one'),
        doc('products/registry-big/h3', 'how-to', 60, 'How-to three'),
        doc('products/registry-big/h4', 'how-to', 70, 'How-to four'),
      ],
    },
  },
};

// A product at or below the threshold: must stay flat, ordered by nav_order.
const smallRepo = {
  repos: {
    'registry-small': {
      docs: [
        doc('products/registry-small/index', 'explanation', 0, 'Registry Small'),
        doc('products/registry-small/b', 'how-to', 20, 'Bravo'),
        doc('products/registry-small/a', 'reference', 10, 'Alpha'),
      ],
    },
  },
};

test('big product (> threshold non-index docs) is sub-grouped in Diataxis order', () => {
  const [group] = buildProductSidebar(bigRepo);
  assert.equal(group.label, 'Big'); // shared "Registry" prefix is stripped
  assert.equal(group.collapsed, true);

  // Overview (the /index page) is always the first item, labeled "Overview".
  assert.deepEqual(group.items[0], { label: 'Overview', slug: 'products/registry-big' });

  // Remaining items are sub-groups in canonical Diataxis order. No Reference?
  // Tutorials -> How-to -> Reference -> Explanation, omitting empty types.
  const subGroups = group.items.slice(1);
  assert.deepEqual(
    subGroups.map((g) => g.label),
    ['Tutorials', 'How-to', 'Reference', 'Explanation'],
  );

  // Within a sub-group, order is by nav_order ascending.
  const howto = subGroups.find((g) => g.label === 'How-to');
  assert.deepEqual(
    howto.items.map((i) => i.label),
    ['How-to two', 'How-to one', 'How-to three', 'How-to four'],
  );
});

test('small product (<= threshold) stays flat, Overview first, ordered by nav_order', () => {
  const [group] = buildProductSidebar(smallRepo);
  assert.equal(group.label, 'Small'); // shared "Registry" prefix is stripped
  assert.deepEqual(group.items, [
    { label: 'Overview', slug: 'products/registry-small' },
    { label: 'Alpha', slug: 'products/registry-small/a' }, // nav_order 10
    { label: 'Bravo', slug: 'products/registry-small/b' }, // nav_order 20
  ]);
});

test('the threshold is exclusive: exactly threshold non-index docs stays flat', () => {
  const docs = [doc('products/p/index', 'explanation', 0, 'P')];
  for (let i = 0; i < SUBGROUP_THRESHOLD; i += 1) {
    docs.push(doc(`products/p/h${i}`, 'how-to', (i + 1) * 10, `H${i}`));
  }
  const [group] = buildProductSidebar({ repos: { 'registry-p': { docs } } });
  // Flat: no nested sub-group items, just the Overview + leaf links.
  assert.ok(group.items.every((i) => !Array.isArray(i.items)));
  assert.equal(group.items.length, SUBGROUP_THRESHOLD + 1);
});

test('a product with no /index page emits no Overview item but still lists docs', () => {
  const [group] = buildProductSidebar({
    repos: { 'registry-x': { docs: [doc('products/registry-x/a', 'how-to', 10, 'Alpha')] } },
  });
  assert.equal(group.items[0].label, 'Alpha');
});

test('docs with an unrecognized doc_type are appended, never dropped', () => {
  const docs = [doc('products/registry-big/index', 'explanation', 0, 'Big')];
  for (let i = 0; i < SUBGROUP_THRESHOLD; i += 1) {
    docs.push(doc(`products/registry-big/h${i}`, 'how-to', (i + 1) * 10, `H${i}`));
  }
  docs.push(doc('products/registry-big/d', 'decision', 999, 'A decision'));
  const [group] = buildProductSidebar({ repos: { 'registry-big': { docs } } });
  const labels = leaves(group.items).map((l) => l.label);
  assert.ok(labels.includes('A decision'), 'unknown doc_type must survive');
});

test('repos with no docs are skipped', () => {
  const groups = buildProductSidebar({ repos: { empty: { docs: [] }, none: {} } });
  assert.equal(groups.length, 0);
});

test('product group labels drop the shared "Registry" prefix', () => {
  const manifest = YAML.parse(readFileSync(manifestPath, 'utf8'));
  const labels = buildProductSidebar(manifest).map((g) => g.label);
  assert.ok(
    labels.every((l) => !/^Registry\b/.test(l)),
    `no group label should start with "Registry": ${labels.join(', ')}`,
  );
  assert.ok(labels.includes('Relay') && labels.includes('Notary'), labels.join(', '));
});

test('the real manifest yields one group per product with every doc present exactly once', async () => {
  const manifest = YAML.parse(await readFile(manifestPath, 'utf8'));
  const groups = buildProductSidebar(manifest);

  const productCount = Object.values(manifest.repos).filter(
    (r) => Array.isArray(r.docs) && r.docs.length > 0,
  ).length;
  assert.equal(groups.length, productCount);

  // Every manifest dest (with /index stripped) appears exactly once in the tree.
  const expected = Object.values(manifest.repos)
    .flatMap((r) => r.docs ?? [])
    .map((d) => (d.dest.endsWith('/index') ? d.dest.slice(0, -'/index'.length) : d.dest))
    .sort();
  const actual = groups.flatMap((g) => leaves(g.items)).map((l) => l.slug).sort();
  assert.deepEqual(actual, expected);
});
