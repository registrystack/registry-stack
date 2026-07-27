import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  archiveOutputDirectory,
  fileDigest,
  publicArchiveBundlePath,
  treeDigest,
} from './archive-bundle.mjs';
import { loadArchiveLock, validateArchiveLock } from './archive-lock.mjs';
import { getDocset, loadDocsets } from './docsets.mjs';

const publicOrigin = 'https://docs.registrystack.org';
const reservedRootDirectories = new Set(['_archive-bundles', 'preview', 'v']);
const forbiddenArchiveNames = new Set([
  '_pagefind',
  'llms-full.txt',
  'llms-small.txt',
  'pagefind',
  'sitemap-0.xml',
  'sitemap-index.xml',
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

async function collectArchiveIndexFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`released archive cannot contain symlinks: ${path}`);
    }
    if (
      forbiddenArchiveNames.has(entry.name) ||
      /^sitemap(?:-[0-9]+|-index)?\.xml$/.test(entry.name)
    ) {
      throw new Error(`released archive contains production-excluded output: ${path}`);
    }
    if (info.isDirectory()) {
      files.push(...await collectArchiveIndexFiles(root, path));
    } else if (info.isFile()) {
      if (entry.name === 'index.html') files.push(path);
    } else {
      throw new Error(`released archive contains an unsupported filesystem entry: ${path}`);
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

function assertReleasedTarget(docset, target) {
  const canonical = new URL(target, publicOrigin);
  if (
    canonical.origin !== publicOrigin ||
    canonical.search ||
    canonical.hash ||
    canonical.pathname !== target ||
    !canonical.pathname.startsWith(docset.path)
  ) {
    throw new Error(
      `released route target must remain within ${docset.path}: ${target}`,
    );
  }
}

function redirectDocument(docset, target) {
  assertReleasedTarget(docset, target);
  const escapedTarget = escapeHtml(target);
  const escapedId = escapeHtml(docset.id);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex,follow">
    <meta name="registry-docset-redirect" content="${escapedId}">
    <meta http-equiv="refresh" content="0;url=${escapedTarget}">
    <link rel="canonical" href="${publicOrigin}${escapedTarget}">
    <title>Registry Stack documentation</title>
    <script>location.replace(${JSON.stringify(target)});</script>
  </head>
  <body><a href="${escapedTarget}">Continue to released documentation</a></body>
</html>
`;
}

function releasedDiscoveryFiles(released) {
  return {
    'robots.txt': `User-agent: *\nAllow: ${released.path}\n`,
    'llms.txt': `# Registry Stack documentation

> Selected released docset: ${released.id}.

- [${released.label}](${publicOrigin}${released.path})
`,
  };
}

function redirectRoutes(archiveRoot, indexFiles, released) {
  const destinations = new Set();
  const routes = [];
  for (const archiveFile of indexFiles) {
    const rel = relative(archiveRoot, archiveFile).replaceAll(sep, '/');
    const top = rel.split('/')[0];
    if (reservedRootDirectories.has(top)) {
      throw new Error(`released route collides with reserved production path /${top}/`);
    }
    const route = rel === 'index.html' ? '' : `${dirname(rel).replaceAll(sep, '/')}/`;
    const target = `${released.path}${route}`;
    assertReleasedTarget(released, target);
    for (const prefix of ['', 'preview/']) {
      const destination = `${prefix}${rel}`;
      if (destinations.has(destination)) {
        throw new Error(`released route has duplicate production destination: /${destination}`);
      }
      destinations.add(destination);
      routes.push({
        destination,
        mount: prefix === '' ? 'root' : 'preview',
        target,
      });
    }
  }
  return routes;
}

async function copyTree(source, destination) {
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination, {
    recursive: true,
    dereference: false,
    force: false,
    errorOnExist: true,
    preserveTimestamps: false,
    verbatimSymlinks: true,
  });
}

export async function stageProductionDocsets({
  docsRoot = process.cwd(),
  dataDir = resolve(docsRoot, 'src/data'),
  lockPath = resolve(dataDir, 'archive-lock.yaml'),
  productionRoot = resolve(docsRoot, 'dist-production'),
} = {}) {
  const distRoot = resolve(docsRoot, 'dist');
  const previewRoot = resolve(distRoot, 'preview');
  const cnameSource = resolve(docsRoot, 'public/CNAME');
  await requireRealDirectory(distRoot, 'assembled docs root');
  await requireRealDirectory(previewRoot, 'Main-source preview');
  await requireRegularFile(resolve(previewRoot, 'index.html'), 'Main-source preview entrypoint');
  await requireRegularFile(cnameSource, 'public custom-domain declaration');
  if (await existingInfo(productionRoot)) {
    throw new Error(`production output already exists: ${productionRoot}`);
  }
  if (!isWithin(docsRoot, productionRoot) || productionRoot === docsRoot) {
    throw new Error(`production output must be a child of the docs root: ${productionRoot}`);
  }

  const previewDigest = await treeDigest(previewRoot);
  const docsets = await loadDocsets({ dataDir });
  const released = getDocset(docsets, docsets.released);
  const lock = await loadArchiveLock({ lockPath });
  const lockErrors = validateArchiveLock(lock, docsets);
  if (lockErrors.length > 0) throw new Error(lockErrors.join('\n'));

  const releasedArtifacts = [];
  for (const docset of docsets.docsets.filter(
    (entry) => entry.status === 'archived' && entry.availability === 'released',
  )) {
    const archiveRoot = archiveOutputDirectory(docsRoot, docset);
    const lockEntry = lock.archives[docset.id];
    const sourceTreeDigest = await treeDigest(archiveRoot);
    if (sourceTreeDigest !== lockEntry.tree_sha256) {
      throw new Error(
        `released archive ${docset.id} does not match its immutable tree lock`,
      );
    }
    const indexFiles = await collectArchiveIndexFiles(archiveRoot);
    const bundlePath = publicArchiveBundlePath(docsRoot, docset);
    const bundleInfo = await existingInfo(bundlePath);
    if (bundleInfo && (bundleInfo.isSymbolicLink() || !bundleInfo.isFile())) {
      throw new Error(`public archive bundle must be a regular file: ${bundlePath}`);
    }
    if (bundleInfo && await fileDigest(bundlePath) !== lockEntry.bundle_sha256) {
      throw new Error(
        `released archive bundle ${docset.id} does not match its immutable bundle lock`,
      );
    }
    releasedArtifacts.push({
      archiveRoot,
      bundlePath: bundleInfo ? bundlePath : null,
      docset,
      indexFiles,
      lockEntry,
    });
  }

  const selected = releasedArtifacts.find(({ docset }) => docset.id === released.id);
  if (!selected) {
    throw new Error(`selected released docset ${released.id} has no released archive`);
  }
  if (selected.indexFiles.length === 0) {
    throw new Error(`released archive ${released.id} contains no index.html routes`);
  }
  const routes = redirectRoutes(selected.archiveRoot, selected.indexFiles, released);
  const cname = await readFile(cnameSource);

  const stagingRoot = await mkdtemp(resolve(docsRoot, '.dist-production-stage-'));
  let published = false;
  try {
    for (const artifact of releasedArtifacts) {
      const archiveDestination = resolve(
        stagingRoot,
        artifact.docset.path.slice(1, -1),
      );
      if (!isWithin(resolve(stagingRoot, 'v'), archiveDestination)) {
        throw new Error(`released archive resolves outside production /v: ${artifact.docset.id}`);
      }
      await copyTree(artifact.archiveRoot, archiveDestination);
      if (await treeDigest(archiveDestination) !== artifact.lockEntry.tree_sha256) {
        throw new Error(`copied released archive ${artifact.docset.id} failed digest validation`);
      }
      if (artifact.bundlePath) {
        const bundleDestination = resolve(
          stagingRoot,
          '_archive-bundles',
          `${artifact.docset.id}.tar.gz`,
        );
        await mkdir(dirname(bundleDestination), { recursive: true });
        await cp(artifact.bundlePath, bundleDestination, {
          force: false,
          errorOnExist: true,
        });
        if (await fileDigest(bundleDestination) !== artifact.lockEntry.bundle_sha256) {
          throw new Error(
            `copied released archive bundle ${artifact.docset.id} failed digest validation`,
          );
        }
      }
    }

    await writeFile(resolve(stagingRoot, 'CNAME'), cname, { flag: 'wx' });
    for (const [name, contents] of Object.entries(releasedDiscoveryFiles(released))) {
      await writeFile(resolve(stagingRoot, name), contents, { encoding: 'utf8', flag: 'wx' });
    }
    for (const route of routes) {
      const destination = resolve(stagingRoot, route.destination);
      if (!isWithin(stagingRoot, destination)) {
        throw new Error(`production redirect resolves outside output: ${route.destination}`);
      }
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(
        destination,
        redirectDocument(released, route.target),
        { encoding: 'utf8', flag: 'wx' },
      );
    }

    if (await treeDigest(previewRoot) !== previewDigest) {
      throw new Error('Main-source preview changed during production staging');
    }
    await rename(stagingRoot, productionRoot);
    published = true;
  } finally {
    if (!published) await rm(stagingRoot, { recursive: true, force: true });
  }

  return {
    archives: releasedArtifacts.length,
    bundles: releasedArtifacts.filter(({ bundlePath }) => bundlePath).length,
    preview_redirects: routes.filter(({ mount }) => mount === 'preview').length,
    released: released.id,
    root_redirects: routes.filter(({ mount }) => mount === 'root').length,
  };
}

async function main() {
  const result = await stageProductionDocsets();
  console.log(
    `Staged ${result.archives} released archive(s), ${result.bundles} locked bundle(s), and ` +
      `${result.root_redirects} root plus ${result.preview_redirects} preview redirect(s) in ` +
      'dist-production; dist/preview is unchanged.',
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
