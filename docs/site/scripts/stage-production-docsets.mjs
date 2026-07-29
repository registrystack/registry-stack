import { constants } from 'node:fs';
import {
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  writeFile,
} from 'node:fs/promises';
import { dirname, extname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { archiveOutputDirectory, treeDigest } from './archive-bundle.mjs';
import { loadArchiveLock, validateArchiveLock } from './archive-lock.mjs';
import { getDocset, loadDocsets } from './docsets.mjs';
import { CURRENT_PRODUCTION_DOCSET_PATH } from '../src/lib/docset-path.mjs';

const productionCurrentPath = CURRENT_PRODUCTION_DOCSET_PATH;
const legacyPreviewPath = '/preview/';
const discoveryFiles = ['llms.txt', 'llms-full.txt', 'llms-small.txt'];
const reservedRootDirectories = new Set([
  '_archive-bundles',
  'dev',
  'pagefind',
  'preview',
  'v',
]);
const generatedRootFiles = new Set([
  'CNAME',
  ...discoveryFiles,
  'robots.txt',
  'sitemap-index.xml',
  'sitemap-0.xml',
]);
const textExtensions = new Set([
  '.css',
  '.html',
  '.js',
  '.json',
  '.md',
  '.mjs',
  '.svg',
  '.txt',
  '.webmanifest',
  '.xml',
]);

async function existingInfo(path) {
  try {
    return await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function requireRealDirectory(path, label) {
  const info = await existingInfo(path);
  if (!info || info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`${label} must be a real directory: ${path}`);
  }
}

async function requireRegularFile(path, label) {
  const info = await existingInfo(path);
  if (!info || info.isSymbolicLink() || !info.isFile()) {
    throw new Error(`${label} must be a regular file: ${path}`);
  }
}

async function collectFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`released archive cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) {
      files.push(...await collectFiles(root, path));
    } else if (info.isFile()) {
      files.push(path);
    }
  }
  return files;
}

function isWithin(parent, child) {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !rel.startsWith(sep));
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function legacyRedirectDocument(docset, target) {
  const escapedTarget = escapeHtml(target);
  const escapedId = escapeHtml(docset.id);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex,follow">
    <meta name="registry-legacy-preview-redirect" content="${escapedId}">
    <meta http-equiv="refresh" content="0;url=${escapedTarget}">
    <link rel="canonical" href="https://docs.registrystack.org${escapedTarget}">
    <title>Registry Stack documentation</title>
    <script>location.replace(${JSON.stringify(target)});</script>
  </head>
  <body><a href="${escapedTarget}">Continue to the latest released documentation</a></body>
</html>
`;
}

function canonicalReleaseBanner(docset) {
  const label = escapeHtml(docset.label);
  const archivePath = escapeHtml(docset.path);
  return `<aside class="registry-preview-banner" role="note" aria-label="Site status"><p><strong>Latest release.</strong> You are viewing ${label}. For an immutable URL, use <a href="${archivePath}">${label}</a>.</p></aside>`;
}

function removeNoindex(html) {
  return html.replace(
    /\s*<meta\s+name=["']robots["']\s+content=["']noindex,follow["']\s*\/?>/gi,
    '',
  );
}

function removeSitemapLinks(html) {
  return html.replace(/\s*<link\b(?=[^>]*\brel=["']sitemap["'])[^>]*>/gi, '');
}

function addRootSitemapLink(html) {
  if (!html.includes('</head>')) return html;
  return html.replace(
    '</head>',
    '<link rel="sitemap" href="https://docs.registrystack.org/sitemap-index.xml"></head>',
  );
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function rewriteMountedPath(contents, fromPath, toPath) {
  const origin = 'https://docs.registrystack.org';
  const fromWithoutSlash = fromPath.replace(/\/$/, '');
  const toWithoutSlash = toPath === '/' ? '' : toPath.replace(/\/$/, '');
  const escapedFrom = fromPath.replaceAll('/', '\\/');
  const escapedTo = toPath.replaceAll('/', '\\/');
  const escapedFromWithoutSlash = fromWithoutSlash.replaceAll('/', '\\/');
  const escapedToWithoutSlash = toWithoutSlash.replaceAll('/', '\\/');
  const boundary = '(^|[\\s"\'(=,:>])';
  return contents
    .replaceAll(`${origin}${fromPath}`, `${origin}${toPath}`)
    .replaceAll(`${origin}${fromWithoutSlash}`, `${origin}${toWithoutSlash}`)
    .replace(
      new RegExp(`${boundary}${escapeRegExp(fromPath)}`, 'g'),
      `$1${toPath}`,
    )
    .replace(
      new RegExp(`${boundary}${escapeRegExp(fromWithoutSlash)}(?=[\\s"'?#),<]|$)`, 'g'),
      `$1${toWithoutSlash}`,
    )
    .replace(
      new RegExp(`${boundary}${escapeRegExp(escapedFrom)}`, 'g'),
      `$1${escapedTo}`,
    )
    .replace(
      new RegExp(
        `${boundary}${escapeRegExp(escapedFromWithoutSlash)}(?=[\\s"'?#),<]|$)`,
        'g',
      ),
      `$1${escapedToWithoutSlash}`,
    );
}

function rewriteReleasedText(contents, released, file) {
  let rewritten = rewriteMountedPath(contents, released.path, '/');
  rewritten = rewriteMountedPath(rewritten, legacyPreviewPath, productionCurrentPath);
  if (file.endsWith('.html')) {
    rewritten = removeNoindex(removeSitemapLinks(rewritten));
    rewritten = rewritten.replace(
      /<aside class=["']registry-preview-banner["'][\s\S]*?<\/aside>/i,
      canonicalReleaseBanner(released),
    );
    rewritten = addRootSitemapLink(rewritten);
  }
  return rewritten;
}

function canonicalRouteForIndex(archiveRoot, file) {
  const rel = relative(archiveRoot, file).replaceAll(sep, '/');
  if (rel === 'index.html') return '/';
  if (!rel.endsWith('/index.html')) return null;
  return `/${rel.slice(0, -'index.html'.length)}`;
}

function sitemapDocuments(routes) {
  const urls = routes
    .map((route) => `  <url><loc>https://docs.registrystack.org${route}</loc></url>`)
    .join('\n');
  return {
    index: `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://docs.registrystack.org/sitemap-0.xml</loc></sitemap>
</sitemapindex>
`,
    pages: `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>
`,
  };
}

function rootRobots() {
  return `User-agent: *
Allow: /

Sitemap: https://docs.registrystack.org/sitemap-index.xml
`;
}

function rewriteDevelopmentDiscoveryUrls(contents) {
  let rewritten = contents;
  for (const file of discoveryFiles) {
    rewritten = rewritten.replaceAll(
      `https://docs.registrystack.org/${file}`,
      `https://docs.registrystack.org${productionCurrentPath}${file}`,
    );
  }
  return rewritten;
}

async function rewriteDevelopmentDiscoveryFiles(currentRoot) {
  for (const file of await collectFiles(currentRoot)) {
    const rel = relative(currentRoot, file).replaceAll(sep, '/');
    if (!rel.endsWith('.md') && !discoveryFiles.includes(rel)) continue;
    const contents = await readFile(file, 'utf8');
    const rewritten = rewriteDevelopmentDiscoveryUrls(contents);
    if (rewritten !== contents) await writeFile(file, rewritten, 'utf8');
  }
}

function withoutDiscoveryHeader(markdown) {
  const firstHeading = markdown.indexOf('\n\n# ');
  return (firstHeading === -1 ? markdown : markdown.slice(firstHeading + 2)).trim();
}

function canonicalCorpusIndex(discoveryHeader) {
  return `# Registry stack docs

> Documentation for Registry Stack: tutorials, product docs, explanation, and API reference for Registry Relay and Registry Notary.

${discoveryHeader}

## Documentation Sets

- [Abridged documentation](https://docs.registrystack.org/llms-small.txt): a compact version of the released documentation
- [Complete documentation](https://docs.registrystack.org/llms-full.txt): the full released documentation

## Notes

- Both corpora are generated from the same locked release pages served at the canonical root.
- Immutable versioned archives remain unchanged.
`;
}

function canonicalCorpusDocument(kind, released, pages) {
  return `<SYSTEM>This is the ${kind} developer documentation for Registry stack docs ${released.label}</SYSTEM>

${pages.join('\n\n')}
`;
}

async function writeCanonicalCorpora(distRoot, promotedFiles, released) {
  const markdownFiles = promotedFiles
    .filter((entry) => entry.relative.endsWith('.md'))
    .sort((left, right) => left.relative.localeCompare(right.relative));
  const index = markdownFiles.find((entry) => entry.relative === 'index.md');
  if (!index) {
    throw new Error(`released archive ${released.id} contains no index.md`);
  }

  const pages = [];
  for (const entry of markdownFiles) {
    pages.push({
      relative: entry.relative,
      contents: withoutDiscoveryHeader(await readFile(entry.destination, 'utf8')),
    });
  }
  const indexContents = await readFile(index.destination, 'utf8');
  const firstHeading = indexContents.indexOf('\n\n# ');
  if (firstHeading === -1) {
    throw new Error(`released archive ${released.id} index.md has no discovery header`);
  }
  const discoveryHeader = indexContents.slice(0, firstHeading).trim();
  for (const file of ['llms.txt', 'llms-full.txt']) {
    if (!discoveryHeader.includes(`https://docs.registrystack.org/${file}`)) {
      throw new Error(
        `released archive ${released.id} index.md discovery header is missing ${file}`,
      );
    }
  }

  const abridgedPages = pages.filter(
    (page) => page.relative === 'index.md' || page.relative.startsWith('explanation/'),
  );
  await writeFile(
    resolve(distRoot, 'llms.txt'),
    canonicalCorpusIndex(discoveryHeader),
    { encoding: 'utf8', flag: 'wx' },
  );
  await writeFile(
    resolve(distRoot, 'llms-full.txt'),
    canonicalCorpusDocument(
      'full',
      released,
      pages.map((page) => page.contents),
    ),
    { encoding: 'utf8', flag: 'wx' },
  );
  await writeFile(
    resolve(distRoot, 'llms-small.txt'),
    canonicalCorpusDocument(
      'abridged',
      released,
      abridgedPages.map((page) => page.contents),
    ),
    { encoding: 'utf8', flag: 'wx' },
  );
  return discoveryFiles.length;
}

async function rejectDestinationCollisions(distRoot, destinations) {
  for (const destination of destinations) {
    if (!isWithin(distRoot, destination)) {
      throw new Error(`production destination resolves outside dist: ${destination}`);
    }
    if (await existingInfo(destination)) {
      throw new Error(`production destination already exists: ${destination}`);
    }
    let parent = dirname(destination);
    while (parent !== distRoot) {
      const info = await existingInfo(parent);
      if (info && (info.isSymbolicLink() || !info.isDirectory())) {
        throw new Error(`production destination parent is not a real directory: ${parent}`);
      }
      parent = dirname(parent);
    }
  }
}

export async function stageProductionDocsets({
  docsRoot = process.cwd(),
  dataDir = resolve(docsRoot, 'src/data'),
  lockPath = resolve(dataDir, 'archive-lock.yaml'),
} = {}) {
  const distRoot = resolve(docsRoot, 'dist');
  const currentRoot = resolve(distRoot, productionCurrentPath.slice(1, -1));
  await requireRealDirectory(distRoot, 'production dist root');
  await requireRealDirectory(currentRoot, 'unreleased Main documentation');
  await requireRegularFile(
    resolve(currentRoot, 'index.html'),
    'unreleased Main documentation entrypoint',
  );
  const cnameSource = resolve(currentRoot, 'CNAME');
  await requireRegularFile(cnameSource, 'GitHub Pages custom-domain declaration');

  const docsets = await loadDocsets({ dataDir });
  const released = getDocset(docsets, docsets.released);
  const lock = await loadArchiveLock({ lockPath });
  const lockErrors = validateArchiveLock(lock, docsets);
  if (lockErrors.length > 0) throw new Error(lockErrors.join('\n'));

  const archiveRoot = archiveOutputDirectory(docsRoot, released);
  const lockedDigest = lock.archives[released.id].tree_sha256;
  const beforeDigest = await treeDigest(archiveRoot);
  if (beforeDigest !== lockedDigest) {
    throw new Error(
      `released archive ${released.id} does not match its immutable tree lock`,
    );
  }

  const archiveFiles = await collectFiles(archiveRoot);
  const rootRouteEntries = [];
  for (const file of archiveFiles) {
    const route = canonicalRouteForIndex(archiveRoot, file);
    if (!route) continue;
    const html = await readFile(file, 'utf8');
    rootRouteEntries.push({
      route,
      isRedirect: /<meta\s+http-equiv=["']refresh["']/i.test(html),
    });
  }
  rootRouteEntries.sort((left, right) => left.route.localeCompare(right.route));
  if (rootRouteEntries.length === 0) {
    throw new Error(`released archive ${released.id} contains no index.html routes`);
  }
  const canonicalRoutes = rootRouteEntries
    .filter((entry) => !entry.isRedirect)
    .map((entry) => entry.route);
  if (canonicalRoutes.length === 0) {
    throw new Error(`released archive ${released.id} contains no canonical content routes`);
  }

  const promotedFiles = [];
  for (const source of archiveFiles) {
    const rel = relative(archiveRoot, source).replaceAll(sep, '/');
    const top = rel.split('/')[0];
    if (reservedRootDirectories.has(top)) {
      throw new Error(`released route collides with reserved production path /${top}/`);
    }
    if (generatedRootFiles.has(rel)) continue;
    promotedFiles.push({
      source,
      relative: rel,
      destination: resolve(distRoot, rel),
    });
  }

  const legacyRedirects = rootRouteEntries.map((entry) => {
    const relativeIndex = entry.route === '/'
      ? 'index.html'
      : `${entry.route.slice(1)}index.html`;
    return {
      destination: resolve(distRoot, legacyPreviewPath.slice(1), relativeIndex),
      target: entry.route,
    };
  });
  const cnameDestination = resolve(distRoot, 'CNAME');
  const robotsDestination = resolve(distRoot, 'robots.txt');
  const sitemapIndexDestination = resolve(distRoot, 'sitemap-index.xml');
  const sitemapPagesDestination = resolve(distRoot, 'sitemap-0.xml');
  const corpusDestinations = discoveryFiles.map((file) => resolve(distRoot, file));

  await rejectDestinationCollisions(
    distRoot,
    [
      cnameDestination,
      robotsDestination,
      sitemapIndexDestination,
      sitemapPagesDestination,
      ...corpusDestinations,
      ...promotedFiles.map((entry) => entry.destination),
      ...legacyRedirects.map((entry) => entry.destination),
    ],
  );

  await rewriteDevelopmentDiscoveryFiles(currentRoot);
  await writeFile(cnameDestination, await readFile(cnameSource), { flag: 'wx' });
  await writeFile(robotsDestination, rootRobots(), { encoding: 'utf8', flag: 'wx' });
  const sitemap = sitemapDocuments(canonicalRoutes);
  await writeFile(sitemapIndexDestination, sitemap.index, { encoding: 'utf8', flag: 'wx' });
  await writeFile(sitemapPagesDestination, sitemap.pages, { encoding: 'utf8', flag: 'wx' });

  for (const promoted of promotedFiles) {
    await mkdir(dirname(promoted.destination), { recursive: true });
    if (textExtensions.has(extname(promoted.relative))) {
      const contents = await readFile(promoted.source, 'utf8');
      await writeFile(
        promoted.destination,
        rewriteReleasedText(contents, released, promoted.relative),
        { encoding: 'utf8', flag: 'wx' },
      );
    } else {
      await copyFile(promoted.source, promoted.destination, constants.COPYFILE_EXCL);
    }
  }

  const corpusFiles = await writeCanonicalCorpora(distRoot, promotedFiles, released);

  for (const redirect of legacyRedirects) {
    await mkdir(dirname(redirect.destination), { recursive: true });
    await writeFile(
      redirect.destination,
      legacyRedirectDocument(released, redirect.target),
      { encoding: 'utf8', flag: 'wx' },
    );
  }

  const afterDigest = await treeDigest(archiveRoot);
  if (afterDigest !== beforeDigest) {
    throw new Error(`released archive ${released.id} changed during production staging`);
  }
  return {
    released: released.id,
    promotedFiles: promotedFiles.length,
    canonicalRoutes: canonicalRoutes.length,
    corpusFiles,
    legacyRedirects: legacyRedirects.length,
  };
}

async function main() {
  const result = await stageProductionDocsets();
  console.log(
    `Promoted ${result.promotedFiles} file(s) across ${result.canonicalRoutes} canonical content route(s) and generated ${result.corpusFiles} corpus file(s) for released docset ${result.released}; staged ${result.legacyRedirects} legacy /preview/ redirect(s); Main remains under ${productionCurrentPath}.`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
