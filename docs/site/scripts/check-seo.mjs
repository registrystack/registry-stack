import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';

import { loadDocsets } from './docsets.mjs';
import { CURRENT_PRODUCTION_DOCSET_PATH } from '../src/lib/docset-path.mjs';

const distDir = resolve(process.env.DOCS_DIST_DIR || 'dist');
const docsOrigin = 'https://docs.registrystack.org';
const legacyPreviewPath = '/preview/';

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

function isWithinMount(file, mount) {
  const rel = relative(distDir, file).replaceAll('\\', '/');
  const root = mount.replace(/^\/|\/$/g, '');
  return rel === `${root}.html` || rel.startsWith(`${root}/`);
}

function archiveForFile(file, archivedDocsets) {
  return archivedDocsets.find((docset) => isWithinMount(file, docset.path));
}

function canonicalFromHtml(html) {
  return html.match(
    /<link\b(?=[^>]*\brel=["']canonical["'])(?=[^>]*\bhref=["']([^"']+)["'])[^>]*>/i,
  )?.[1];
}

function isCanonicalRootUrl(value) {
  if (!value?.startsWith(docsOrigin)) return false;
  const path = value.slice(docsOrigin.length) || '/';
  return ![
    CURRENT_PRODUCTION_DOCSET_PATH,
    legacyPreviewPath,
    '/v/',
  ].some((mount) => path === mount.slice(0, -1) || path.startsWith(mount));
}

async function rejectSitemap(dir, label, errors) {
  for (const name of ['sitemap-index.xml', 'sitemap-0.xml']) {
    if (await exists(join(dir, name))) {
      errors.push(`${label} must not publish ${name}`);
    }
  }
}

const manifest = await loadDocsets();
const archivedDocsets = manifest.docsets.filter((docset) => docset.status === 'archived');
const scope = scopeFromArgs(process.argv.slice(2));
const errors = [];
let developmentChecked = 0;
let archiveChecked = 0;
let canonicalChecked = 0;
let legacyRedirectsChecked = 0;
const developmentDir = join(
  distDir,
  CURRENT_PRODUCTION_DOCSET_PATH.replace(/^\/|\/$/g, ''),
);
const productionLayout = await exists(join(developmentDir, 'index.html'));
const developmentOutput = productionLayout ? developmentDir : distDir;

await rejectSitemap(developmentOutput, 'Unreleased Main documentation', errors);

if (scope === 'all' && productionLayout) {
  const rootSitemapIndex = join(distDir, 'sitemap-index.xml');
  const rootSitemapPages = join(distDir, 'sitemap-0.xml');
  if (!await exists(rootSitemapIndex)) {
    errors.push(`Canonical sitemap is missing: ${rootSitemapIndex}`);
  }
  if (!await exists(rootSitemapPages)) {
    errors.push(`Canonical sitemap page is missing: ${rootSitemapPages}`);
  } else {
    const sitemap = await readFile(rootSitemapPages, 'utf8');
    for (const match of sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)) {
      if (!isCanonicalRootUrl(match[1])) {
        errors.push(`Canonical sitemap contains a non-root URL: ${match[1]}`);
        continue;
      }
      const pathname = new URL(match[1]).pathname;
      const page = pathname === '/'
        ? join(distDir, 'index.html')
        : join(distDir, pathname, 'index.html');
      if (!await exists(page)) {
        errors.push(`Canonical sitemap points to a missing page: ${match[1]}`);
        continue;
      }
      const html = await readFile(page, 'utf8');
      if (/<meta\s+http-equiv=["']refresh["']/i.test(html)) {
        errors.push(`Canonical sitemap must not include redirect page: ${match[1]}`);
      }
    }
  }
  const robots = join(distDir, 'robots.txt');
  if (!await exists(robots)) {
    errors.push(`Production robots declaration is missing: ${robots}`);
  } else {
    const contents = await readFile(robots, 'utf8');
    if (!contents.includes(`${docsOrigin}/sitemap-index.xml`)) {
      errors.push('Production robots declaration must point to the canonical root sitemap');
    }
  }
  for (const docset of archivedDocsets) {
    await rejectSitemap(join(distDir, docset.path), `Archived docset ${docset.id}`, errors);
  }
  await rejectSitemap(
    join(distDir, legacyPreviewPath),
    'Legacy /preview/ redirects',
    errors,
  );
}

for (const file of await htmlFiles(distDir)) {
  const html = await readFile(file, 'utf8');
  const archive = archiveForFile(file, archivedDocsets);
  const isDevelopment = productionLayout
    ? isWithinMount(file, CURRENT_PRODUCTION_DOCSET_PATH)
    : !archive;
  const isLegacyRedirect = productionLayout && isWithinMount(file, legacyPreviewPath);
  const isCanonical = productionLayout && !archive && !isDevelopment && !isLegacyRedirect;
  if (
    scope === 'current' &&
    (productionLayout ? !isDevelopment : Boolean(archive))
  ) {
    continue;
  }

  const hasNoindex =
    /<meta\s+name=["']robots["']\s+content=["']noindex,follow["']\s*\/?>/i.test(html);
  const hasSitemapLink = /<link\b(?=[^>]*\brel=["']sitemap["'])[^>]*>/i.test(html);
  const canonical = canonicalFromHtml(html);

  if (isDevelopment) {
    developmentChecked += 1;
    if (!hasNoindex) {
      errors.push(`${relative('.', file)} is unreleased Main but missing robots noindex,follow`);
    }
    if (hasSitemapLink) {
      errors.push(`${relative('.', file)} is unreleased Main but links a sitemap`);
    }
  } else if (archive) {
    archiveChecked += 1;
    if (!hasNoindex) {
      errors.push(`${relative('.', file)} is archived but missing robots noindex,follow`);
    }
    if (hasSitemapLink) {
      errors.push(`${relative('.', file)} is archived but links a sitemap`);
    }
  } else if (isLegacyRedirect) {
    legacyRedirectsChecked += 1;
    if (!hasNoindex) {
      errors.push(`${relative('.', file)} is a legacy redirect but missing robots noindex,follow`);
    }
    if (hasSitemapLink) {
      errors.push(`${relative('.', file)} is a legacy redirect but links a sitemap`);
    }
    if (!html.includes('name="registry-legacy-preview-redirect"')) {
      errors.push(`${relative('.', file)} is under /preview/ but is not a declared legacy redirect`);
    }
    if (!isCanonicalRootUrl(canonical)) {
      errors.push(`${relative('.', file)} must canonicalize to the released root namespace`);
    }
  } else if (isCanonical) {
    canonicalChecked += 1;
    const isRedirectPage = /<meta\s+http-equiv=["']refresh["']/i.test(html);
    if (hasNoindex) {
      errors.push(`${relative('.', file)} is canonical release documentation but has noindex`);
    }
    if (!isRedirectPage && !hasSitemapLink) {
      errors.push(`${relative('.', file)} is canonical release documentation but has no sitemap link`);
    }
    if (!isRedirectPage && !isCanonicalRootUrl(canonical)) {
      errors.push(`${relative('.', file)} must have a canonical URL in the root namespace`);
    }
  }
}

if (developmentChecked === 0) {
  errors.push('No unreleased Main HTML files were checked.');
}
if (scope === 'all' && productionLayout) {
  if (archiveChecked === 0) errors.push('No immutable archive HTML files were checked.');
  if (canonicalChecked === 0) errors.push('No canonical release HTML files were checked.');
  if (legacyRedirectsChecked === 0) errors.push('No legacy /preview/ redirects were checked.');
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(
  `SEO check passed: ${canonicalChecked} canonical release HTML files, ${developmentChecked} unreleased Main HTML files, ${archiveChecked} immutable archive HTML files, and ${legacyRedirectsChecked} legacy redirects checked.`,
);
