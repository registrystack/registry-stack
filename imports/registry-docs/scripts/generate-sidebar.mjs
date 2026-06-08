// Build-time sidebar generation (product navigation).
//
// Reads src/data/repo-docs.yaml and emits the product portion of the Starlight
// sidebar to src/data/generated/sidebar.json, which astro.config.mjs splices
// into the top-level nav. This is the single source of truth for product
// navigation: a doc added to a product repo (and allowlisted in the manifest)
// appears in the menu automatically, grouped by its Diataxis `doc_type`, with
// no hand-edit to astro.config.mjs.
//
// Structure per product (product-first IA): one top-level group per product.
// The /index page is the "Overview" item. Products with more than
// SUBGROUP_THRESHOLD non-index docs are sub-grouped by doc_type in canonical
// Diataxis order (Tutorials, How-to, Reference, Explanation); smaller products
// stay a flat list ordered by nav_order, since a one-item sub-group is noise.
//
// No silent failures: a doc whose doc_type is not a known Diataxis type is
// appended to the group rather than dropped, so nothing vanishes from the nav.

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import YAML from 'yaml';

// Products with more than this many non-index docs get Diataxis sub-groups.
export const SUBGROUP_THRESHOLD = 6;

// Canonical Diataxis ordering for the sub-groups within a product.
export const DOC_TYPE_ORDER = ['tutorial', 'how-to', 'reference', 'explanation'];

export const DOC_TYPE_LABELS = {
  tutorial: 'Tutorials',
  'how-to': 'How-to',
  reference: 'Reference',
  explanation: 'Explanation',
};

// "registry-relay" -> "Relay". The product group header. The shared "registry-"
// product-family prefix is dropped because the site title ("Registry stack
// docs") and the enclosing "Products" group already supply that context;
// repeating it on every line is noise. Page titles keep the full name.
function productLabel(repoId) {
  return repoId
    .replace(/^registry-/, '')
    .split('-')
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : part))
    .join(' ');
}

// The Starlight content slug for a manifest dest. Index pages are served at the
// parent route, so "products/x/index" -> "products/x".
function slugFromDest(dest) {
  return dest.endsWith('/index') ? dest.slice(0, -'/index'.length) : dest;
}

function byNavOrder(a, b) {
  const order = (a.nav_order ?? 0) - (b.nav_order ?? 0);
  return order !== 0 ? order : a.label.localeCompare(b.label);
}

function leaf(entry) {
  return { label: entry.label, slug: slugFromDest(entry.dest) };
}

// Transform a repo-docs manifest into the product portion of the sidebar.
// Pure: no IO, so it is unit-testable (scripts/generate-sidebar.test.mjs).
export function buildProductSidebar(manifest, opts = {}) {
  const threshold = opts.threshold ?? SUBGROUP_THRESHOLD;
  const groups = [];

  for (const [repoId, repo] of Object.entries(manifest.repos ?? {})) {
    const docs = Array.isArray(repo.docs) ? repo.docs : [];
    if (docs.length === 0) continue;

    const indexDoc = docs.find((d) => d.dest.endsWith('/index'));
    const rest = docs.filter((d) => d !== indexDoc);

    const items = [];
    if (indexDoc) items.push({ label: 'Overview', slug: slugFromDest(indexDoc.dest) });

    if (rest.length > threshold) {
      // Sub-group by doc_type in Diataxis order, omitting empty types.
      for (const type of DOC_TYPE_ORDER) {
        const inType = rest.filter((d) => d.doc_type === type).sort(byNavOrder);
        if (inType.length === 0) continue;
        items.push({ label: DOC_TYPE_LABELS[type], items: inType.map(leaf) });
      }
      // Anything with an unrecognized doc_type is appended flat, never dropped.
      const known = new Set(DOC_TYPE_ORDER);
      for (const entry of rest.filter((d) => !known.has(d.doc_type)).sort(byNavOrder)) {
        items.push(leaf(entry));
      }
    } else {
      // Small product: flat list ordered by nav_order.
      for (const entry of [...rest].sort(byNavOrder)) items.push(leaf(entry));
    }

    groups.push({ label: productLabel(repoId), collapsed: true, items });
  }

  return groups;
}

async function main() {
  const root = process.cwd();
  const manifestPath = resolve(root, 'src/data/repo-docs.yaml');
  const outDir = resolve(root, 'src/data/generated');
  const outFile = resolve(outDir, 'sidebar.json');

  const manifest = YAML.parse(await readFile(manifestPath, 'utf8'));
  if (!manifest || typeof manifest.repos !== 'object') {
    throw new Error('repo-docs.yaml must contain a top-level `repos` map');
  }

  const sidebar = buildProductSidebar(manifest);

  await mkdir(outDir, { recursive: true });
  await writeFile(outFile, `${JSON.stringify(sidebar, null, 2)}\n`);
  console.log(`Generated product sidebar (${sidebar.length} products) -> ${relative(root, outFile)}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
