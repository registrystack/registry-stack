import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { loadDocsets } from './docsets.mjs';

const distDir = resolve(process.env.DOCS_DIST_DIR || 'dist');
// v0.13.0 was sealed before selected releases became indexable. Its immutable
// bundle cannot be rewritten. The exception disappears automatically when the
// released selector advances, and no later release is allowed to inherit it.
const immutableLegacyNoindexReleasedDocsets = new Set(['v0.13.0']);

function scopeFromArgs(args) {
  if (args.length === 0) return 'all';
  if (args.length === 2 && args[0] === '--scope' && ['all', 'current'].includes(args[1])) {
    return args[1];
  }
  throw new Error('usage: check-seo.mjs [--scope current|all]');
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

async function htmlFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await htmlFiles(path));
    if (entry.isFile() && entry.name.endsWith('.html')) files.push(path);
  }
  return files;
}

function archiveRootForFile(file, archivedDocsets) {
  const rel = relative(distDir, file).replaceAll('\\', '/');
  return archivedDocsets.find((docset) => rel.startsWith(docset.path.replace(/^\//, '')));
}

const manifest = await loadDocsets();
const releasedDocset = manifest.docsets.find((docset) => docset.id === manifest.released);
const archivedDocsets = manifest.docsets.filter((docset) => docset.status === 'archived');
const historicalDocsets = archivedDocsets.filter((docset) => docset.id !== manifest.released);
const releasedHasLegacyNoindex =
  immutableLegacyNoindexReleasedDocsets.has(manifest.released);
const searchExcludedDocsets = archivedDocsets.filter(
  (docset) => docset.id !== manifest.released || releasedHasLegacyNoindex,
);
const scope = scopeFromArgs(process.argv.slice(2));
const errors = [];
let currentChecked = 0;
let archivedChecked = 0;
let releasedChecked = 0;
let redirectsChecked = 0;
const previewDir = join(distDir, 'preview');
const productionLayout = await exists(join(previewDir, 'index.html'));
const currentOutput = productionLayout ? previewDir : distDir;

if (!await exists(join(currentOutput, 'sitemap-index.xml'))) {
  errors.push(`Main sitemap is missing: ${join(currentOutput, 'sitemap-index.xml')}`);
}

if (scope === 'all') {
  for (const docset of searchExcludedDocsets) {
    const archiveDir = join(distDir, docset.path);
    const archiveSitemap = join(archiveDir, 'sitemap-index.xml');
    const archiveSitemapPage = join(archiveDir, 'sitemap-0.xml');
    if (await exists(archiveSitemap)) {
      errors.push(`Archived docset ${docset.id} must not publish sitemap-index.xml`);
    }
    if (await exists(archiveSitemapPage)) {
      errors.push(`Archived docset ${docset.id} must not publish sitemap-0.xml`);
    }
  }
}

for (const file of await htmlFiles(distDir)) {
  const html = await readFile(file, 'utf8');
  const archiveDocset = archiveRootForFile(file, archivedDocsets);
  const isArchived = Boolean(archiveDocset);
  const isReleasedArchive = archiveDocset?.id === manifest.released;
  const isProductionRedirect =
    /<meta\s+name=["']registry-docset-redirect["']\s+content=["'][^"']+["']\s*\/?>/.test(html);
  if (scope === 'current' && (isArchived || isProductionRedirect)) continue;
  const hasNoindex = /<meta\s+name=["']robots["']\s+content=["']noindex,follow["']\s*\/?>/.test(html);
  const hasSitemapLink = /<link\b(?=[^>]*\brel=["']sitemap["'])[^>]*>/i.test(html);

  if (isProductionRedirect) {
    redirectsChecked += 1;
    if (!hasNoindex) {
      errors.push(`${relative('.', file)} is a root redirect but missing robots noindex,follow`);
    }
    if (hasSitemapLink) {
      errors.push(`${relative('.', file)} is a root redirect but links a sitemap`);
    }
    const canonical = html.match(
      /<link\b(?=[^>]*\brel=["']canonical["'])(?=[^>]*\bhref=["']([^"']+)["'])[^>]*>/i,
    )?.[1];
    if (!canonical?.startsWith(`https://docs.registrystack.org${releasedDocset.path}`)) {
      errors.push(
        `${relative('.', file)} must canonically redirect into released docset ${manifest.released}`,
      );
    }
  } else if (isReleasedArchive) {
    releasedChecked += 1;
    if (releasedHasLegacyNoindex && !hasNoindex) {
      errors.push(
        `${relative('.', file)} is immutable legacy release ${manifest.released} but is missing robots noindex,follow`,
      );
    } else if (!releasedHasLegacyNoindex && hasNoindex) {
      errors.push(`${relative('.', file)} is the released docset but has robots noindex,follow`);
    }
    if (releasedHasLegacyNoindex && hasSitemapLink) {
      errors.push(
        `${relative('.', file)} is immutable legacy release ${manifest.released} but links a sitemap`,
      );
    }
  } else if (isArchived) {
    archivedChecked += 1;
    if (!hasNoindex) {
      errors.push(`${relative('.', file)} is archived but missing robots noindex,follow`);
    }
    if (hasSitemapLink) {
      errors.push(`${relative('.', file)} is archived but links a sitemap`);
    }
  } else {
    currentChecked += 1;
    if (hasNoindex) {
      errors.push(`${relative('.', file)} is Main but has robots noindex,follow`);
    }
  }
}

if (scope === 'all' && archivedDocsets.length > 0 && archivedChecked === 0) {
  if (historicalDocsets.length > 0) errors.push('No historical archive HTML files were checked.');
}
if (scope === 'all' && releasedDocset && releasedChecked === 0) {
  errors.push('No released-docset HTML files were checked.');
}
if (scope === 'all' && productionLayout && redirectsChecked === 0) {
  errors.push('No released-root redirect HTML files were checked.');
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(
  `SEO check passed: ${currentChecked} Main HTML files, ${releasedChecked} released HTML files, ${archivedChecked} historical archive HTML files, and ${redirectsChecked} released-root redirects checked.`,
);
