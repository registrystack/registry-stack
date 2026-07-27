import { lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { archiveOutputDirectory, treeDigest } from './archive-bundle.mjs';
import { loadArchiveLock, validateArchiveLock } from './archive-lock.mjs';
import { getDocset, loadDocsets } from './docsets.mjs';

const productionCurrentPath = '/preview/';
const reservedRootDirectories = new Set(['_archive-bundles', 'preview', 'v']);
const discoveryUrls = ['llms.txt', 'llms-full.txt', 'llms-small.txt', 'sitemap-index.xml'];

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

async function collectIndexFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`released archive cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) {
      files.push(...await collectIndexFiles(root, path));
    } else if (info.isFile() && entry.name === 'index.html') {
      files.push(path);
    }
  }
  return files;
}

async function collectPreviewTextFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`Main-source preview cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) {
      files.push(...await collectPreviewTextFiles(root, path));
    } else if (
      info.isFile() &&
      (entry.name.endsWith('.html') ||
        entry.name.endsWith('.md') ||
        entry.name === 'robots.txt' ||
        /^llms(?:-(?:full|small))?\.txt$/.test(entry.name))
    ) {
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

function redirectDocument(docset, target) {
  const escapedTarget = escapeHtml(target);
  const escapedId = escapeHtml(docset.id);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex,follow">
    <meta name="registry-docset-redirect" content="${escapedId}">
    <meta http-equiv="refresh" content="0;url=${escapedTarget}">
    <link rel="canonical" href="https://docs.registrystack.org${escapedTarget}">
    <title>Registry Stack documentation</title>
    <script>location.replace(${JSON.stringify(target)});</script>
  </head>
  <body><a href="${escapedTarget}">Continue to released documentation</a></body>
</html>
`;
}

function rewritePreviewHtml(html, archivedPaths) {
  return html.replace(
    /(\s(?:href|src)=)(["'])(\/(?!\/)[^"']*)\2/g,
    (match, attribute, quote, value) => {
      const pathname = value.split(/[?#]/, 1)[0];
      if (
        pathname === '/preview' ||
        pathname.startsWith('/preview/') ||
        pathname === '/v' ||
        pathname.startsWith('/v/') ||
        pathname === '/_archive-bundles' ||
        pathname.startsWith('/_archive-bundles/') ||
        archivedPaths.some((path) => pathname === path.slice(0, -1) || pathname.startsWith(path))
      ) {
        return match;
      }
      return `${attribute}${quote}/preview${value}${quote}`;
    },
  );
}

function rewriteDiscoveryUrls(contents) {
  let rewritten = contents;
  for (const path of discoveryUrls) {
    rewritten = rewritten.replaceAll(
      `https://docs.registrystack.org/${path}`,
      `https://docs.registrystack.org${productionCurrentPath}${path}`,
    );
  }
  return rewritten;
}

async function rejectDestinationCollisions(distRoot, destinations) {
  for (const destination of destinations) {
    if (!isWithin(distRoot, destination)) {
      throw new Error(`production redirect resolves outside dist: ${destination}`);
    }
    const rel = relative(distRoot, destination).replaceAll(sep, '/');
    const top = rel.split('/')[0];
    if (reservedRootDirectories.has(top)) {
      throw new Error(`released route collides with reserved production path /${top}/`);
    }
    if (await existingInfo(destination)) {
      throw new Error(`production redirect destination already exists: ${destination}`);
    }
    let parent = dirname(destination);
    while (parent !== distRoot) {
      const info = await existingInfo(parent);
      if (info && (info.isSymbolicLink() || !info.isDirectory())) {
        throw new Error(`production redirect parent is not a real directory: ${parent}`);
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
  const previewRoot = resolve(distRoot, productionCurrentPath.slice(1, -1));
  await requireRealDirectory(distRoot, 'production dist root');
  await requireRealDirectory(previewRoot, 'Main-source preview');
  await requireRegularFile(resolve(previewRoot, 'index.html'), 'Main-source preview entrypoint');
  const cnameSource = resolve(previewRoot, 'CNAME');
  const cnameDestination = resolve(distRoot, 'CNAME');
  const robotsSource = resolve(previewRoot, 'robots.txt');
  const robotsDestination = resolve(distRoot, 'robots.txt');
  await requireRegularFile(cnameSource, 'GitHub Pages custom-domain declaration');
  await requireRegularFile(robotsSource, 'Main-source robots declaration');

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

  const indexFiles = await collectIndexFiles(archiveRoot);
  if (indexFiles.length === 0) {
    throw new Error(`released archive ${released.id} contains no index.html routes`);
  }
  const redirects = indexFiles.map((archiveFile) => {
    const rel = relative(archiveRoot, archiveFile);
    const route = rel === 'index.html'
      ? '/'
      : `/${dirname(rel).replaceAll(sep, '/')}/`;
    return {
      destination: resolve(distRoot, rel),
      target: `${released.path}${route.slice(1)}`,
    };
  });

  await rejectDestinationCollisions(
    distRoot,
    [cnameDestination, robotsDestination, ...redirects.map((entry) => entry.destination)],
  );
  const archivedPaths = docsets.docsets
    .filter((docset) => docset.status === 'archived')
    .map((docset) => docset.path);
  for (const file of await collectPreviewTextFiles(previewRoot)) {
    const contents = await readFile(file, 'utf8');
    const withMountedLinks = file.endsWith('.html')
      ? rewritePreviewHtml(contents, archivedPaths)
      : contents;
    const rewritten = rewriteDiscoveryUrls(withMountedLinks);
    if (rewritten !== contents) await writeFile(file, rewritten, 'utf8');
  }
  await writeFile(cnameDestination, await readFile(cnameSource), { flag: 'wx' });
  await writeFile(robotsDestination, await readFile(robotsSource), { flag: 'wx' });
  for (const redirect of redirects) {
    await mkdir(dirname(redirect.destination), { recursive: true });
    await writeFile(
      redirect.destination,
      redirectDocument(released, redirect.target),
      { encoding: 'utf8', flag: 'wx' },
    );
  }

  const afterDigest = await treeDigest(archiveRoot);
  if (afterDigest !== beforeDigest) {
    throw new Error(`released archive ${released.id} changed during production staging`);
  }
  return { released: released.id, redirects: redirects.length };
}

async function main() {
  const result = await stageProductionDocsets();
  console.log(
    `Staged ${result.redirects} root redirect(s) to released docset ${result.released}; Main remains under ${productionCurrentPath}.`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
