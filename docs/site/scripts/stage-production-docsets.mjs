import {
  cp,
  lstat,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ARCHIVE_BUNDLE_SCHEMA,
  inspectArchiveBundle,
  treeDigest,
} from './archive-bundle.mjs';
import { CURRENT_PRODUCTION_DOCSET_PATH } from '../src/lib/docset-path.mjs';

const releaseTagPattern =
  /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const reservedReleaseEntries = new Set([
  '_archive-bundles',
  CURRENT_PRODUCTION_DOCSET_PATH.slice(1, -1),
  'preview',
  'v',
]);
const discoveryFiles = new Set([
  'llms.txt',
  'llms-full.txt',
  'llms-small.txt',
  'robots.txt',
]);
const discoveryRoutes = [
  'llms.txt',
  'llms-full.txt',
  'llms-small.txt',
  'sitemap-index.xml',
];

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

function legacyPreviewRedirect(releasedTag, target) {
  const escapedTarget = escapeHtml(target);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="robots" content="noindex,follow">
    <meta name="registry-legacy-preview-redirect" content="${releasedTag}">
    <meta http-equiv="refresh" content="0;url=${escapedTarget}">
    <link rel="canonical" href="https://docs.registrystack.org${escapedTarget}">
    <title>Registry Stack documentation</title>
    <script>location.replace(${JSON.stringify(target)});</script>
  </head>
  <body><a href="${escapedTarget}">Continue to the latest released documentation</a></body>
</html>
`;
}

export function validatePromotionInputs({ releasedTag, docsSha256 }) {
  const errors = [];
  if (!releaseTagPattern.test(releasedTag ?? '')) {
    errors.push('released tag must be canonical v<major>.<minor>.<patch> text');
  }
  if (!sha256Pattern.test(docsSha256 ?? '')) {
    errors.push('docs SHA-256 must be 64 lowercase hexadecimal characters');
  }
  if (errors.length > 0) throw new Error(errors.join('\n'));
  return {
    releasedTag,
    version: releasedTag.slice(1),
    docsSha256,
  };
}

async function collectFiles(root, current = root) {
  const files = [];
  for (const entry of await readdir(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`documentation tree cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) files.push(...await collectFiles(root, path));
    else if (info.isFile()) files.push(path);
    else throw new Error(`documentation tree contains an unsupported entry: ${path}`);
  }
  return files;
}

async function rewriteDevelopmentDiscovery(devRoot) {
  for (const path of await collectFiles(devRoot)) {
    const name = path.slice(path.lastIndexOf(sep) + 1);
    if (!name.endsWith('.md') && !discoveryFiles.has(name)) continue;
    const contents = await readFile(path, 'utf8');
    let rewritten = contents;
    for (const route of discoveryRoutes) {
      rewritten = rewritten.replaceAll(
        `https://docs.registrystack.org/${route}`,
        `https://docs.registrystack.org${CURRENT_PRODUCTION_DOCSET_PATH}${route}`,
      );
    }
    if (rewritten !== contents) await writeFile(path, rewritten, 'utf8');
  }
}

async function rejectReleaseTreeCollisions(siteRoot) {
  for (const entry of await readdir(siteRoot, { withFileTypes: true })) {
    if (reservedReleaseEntries.has(entry.name)) {
      throw new Error(
        `released archive collides with reserved production path /${entry.name}/`,
      );
    }
  }
}

async function copyReleaseToRoot(siteRoot, distRoot) {
  const copied = [];
  for (const entry of await readdir(siteRoot, { withFileTypes: true })) {
    const source = resolve(siteRoot, entry.name);
    const destination = resolve(distRoot, entry.name);
    if (!isWithin(distRoot, destination)) {
      throw new Error(`released archive entry resolves outside production dist: ${entry.name}`);
    }
    if (await existingInfo(destination)) {
      throw new Error(`released root destination already exists: ${destination}`);
    }
    await cp(source, destination, {
      recursive: entry.isDirectory(),
      dereference: false,
      force: false,
      errorOnExist: true,
      preserveTimestamps: false,
    });
    copied.push(entry.name);
  }
  return copied;
}

async function stageLegacyPreviewRedirects(siteRoot, distRoot, releasedTag) {
  let count = 0;
  for (const source of await collectFiles(siteRoot)) {
    const rel = relative(siteRoot, source).replaceAll(sep, '/');
    if (rel !== 'index.html' && !rel.endsWith('/index.html')) continue;
    const route = rel === 'index.html'
      ? '/'
      : `/${rel.slice(0, -'index.html'.length)}`;
    const destination = resolve(distRoot, 'preview', rel);
    if (!isWithin(resolve(distRoot, 'preview'), destination)) {
      throw new Error(`legacy preview redirect resolves outside /preview/: ${rel}`);
    }
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, legacyPreviewRedirect(releasedTag, route), {
      encoding: 'utf8',
      flag: 'wx',
    });
    count += 1;
  }
  return count;
}

export async function stageProductionDocsets({
  docsRoot = process.cwd(),
  releasedTag,
  docsSha256,
  bundlePath,
} = {}) {
  const inputs = validatePromotionInputs({ releasedTag, docsSha256 });
  if (!bundlePath) throw new Error('released docs bundle path is required');

  const distRoot = resolve(docsRoot, 'dist');
  const devRoot = resolve(distRoot, CURRENT_PRODUCTION_DOCSET_PATH.slice(1, -1));
  await requireRealDirectory(distRoot, 'production dist root');
  await requireRealDirectory(devRoot, 'protected-main development docs');
  await requireRegularFile(
    resolve(devRoot, 'index.html'),
    'protected-main development docs entrypoint',
  );
  await rewriteDevelopmentDiscovery(devRoot);

  const docset = {
    id: inputs.releasedTag,
    path: `/v/${inputs.version}/`,
    status: 'archived',
  };
  const inspected = await inspectArchiveBundle({
    bundlePath: resolve(bundlePath),
    docset,
    expectedBundleSha256: inputs.docsSha256,
    expectedTreeSha256: null,
  });
  try {
    if (inspected.metadata.schema_version !== ARCHIVE_BUNDLE_SCHEMA) {
      throw new Error(
        `released archive ${inputs.releasedTag} must contain separately bound root and version trees`,
      );
    }
    const rootTree = inspected.root_path;
    const versionTree = inspected.version_path;
    await rejectReleaseTreeCollisions(rootTree);
    for (const required of [
      'index.html',
      'index.md',
      'llms.txt',
      'sitemap-index.xml',
      'pagefind/pagefind.js',
    ]) {
      await requireRegularFile(
        resolve(rootTree, required),
        `released archive ${required}`,
      );
    }
    await requireRegularFile(
      resolve(versionTree, 'index.html'),
      'released version archive index.html',
    );

    const versionRoot = resolve(distRoot, `v/${inputs.version}`);
    const versionParent = resolve(distRoot, 'v');
    if (!isWithin(versionParent, versionRoot)) {
      throw new Error(`released version route resolves outside production dist: ${versionRoot}`);
    }
    await rm(versionRoot, { recursive: true, force: true });
    await mkdir(dirname(versionRoot), { recursive: true });
    await requireRealDirectory(versionParent, 'archive version root');
    await cp(versionTree, versionRoot, {
      recursive: true,
      dereference: false,
      force: false,
      errorOnExist: true,
      preserveTimestamps: false,
    });
    if (await treeDigest(versionRoot) !== inspected.version_tree_sha256) {
      throw new Error(`versioned release copy ${inputs.releasedTag} changed during staging`);
    }

    const rootEntries = await copyReleaseToRoot(rootTree, distRoot);
    for (const source of await collectFiles(rootTree)) {
      const rel = relative(rootTree, source);
      const destination = resolve(distRoot, rel);
      const [sourceContents, destinationContents] = await Promise.all([
        readFile(source),
        readFile(destination),
      ]);
      if (!sourceContents.equals(destinationContents)) {
        throw new Error(`released root file changed during staging: ${rel}`);
      }
    }
    const legacyPreviewRedirects = await stageLegacyPreviewRedirects(
      rootTree,
      distRoot,
      inputs.releasedTag,
    );
    return {
      legacyPreviewRedirects,
      released: inputs.releasedTag,
      rootTreeSha256: inspected.root_tree_sha256,
      rootEntries: rootEntries.length,
      versionTreeSha256: inspected.version_tree_sha256,
      versionPath: `/v/${inputs.version}/`,
    };
  } finally {
    await rm(inspected.temporary, { recursive: true, force: true });
  }
}

export function parsePromotionArgs(args) {
  const parsed = {};
  while (args.length > 0) {
    const option = args.shift();
    if (option === '--released-tag' && args[0]) parsed.releasedTag = args.shift();
    else if (option === '--docs-sha256' && args[0]) parsed.docsSha256 = args.shift();
    else if (option === '--bundle' && args[0]) parsed.bundlePath = resolve(args.shift());
    else {
      throw new Error(
        'usage: stage-production-docsets.mjs --released-tag <tag> ' +
          '--docs-sha256 <sha256> --bundle <path>',
      );
    }
  }
  validatePromotionInputs(parsed);
  if (!parsed.bundlePath) {
    throw new Error(
      'usage: stage-production-docsets.mjs --released-tag <tag> ' +
        '--docs-sha256 <sha256> --bundle <path>',
    );
  }
  return parsed;
}

async function main(args) {
  const result = await stageProductionDocsets(parsePromotionArgs([...args]));
  console.log(
    `Promoted unchanged ${result.released} docs to / and ${result.versionPath}; ` +
      `protected main remains at ${CURRENT_PRODUCTION_DOCSET_PATH}.`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
