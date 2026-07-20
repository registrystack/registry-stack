import { createHash } from 'node:crypto';
import { cp, lstat, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadDocsets } from './docsets.mjs';

export const ARCHIVE_CACHE_SCHEMA = 'registry-docs.archive-cache.v1';
export const LINK_INDEX_SCHEMA = 'registry-docs.link-index.v1';
export const ARCHIVE_ENVIRONMENT_NAMES = [
  'PUBLIC_UMAMI_DOMAINS',
  'PUBLIC_UMAMI_SCRIPT_SRC',
  'PUBLIC_UMAMI_WEBSITE_ID',
];

const shaPattern = /^[0-9a-f]{64}$/;
const ignoredDocsPaths = [
  '.archive-build-cache',
  '.astro',
  '.repo-docs-cache',
  'dist',
  'dist-check',
  'node_modules',
  'openapi',
  'public/products',
  'src/content/docs/products',
  'src/data/generated',
];

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function archiveEnvironmentDigest(env = process.env) {
  return digest(
    canonicalJson(
      Object.fromEntries(
        ARCHIVE_ENVIRONMENT_NAMES.map((name) => [name, env[name] ?? '']),
      ),
    ),
  );
}

export async function fileDigest(path) {
  return digest(await readFile(path));
}

function isWithin(parent, child) {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !rel.startsWith(sep));
}

async function existingKind(path) {
  try {
    return await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function requireDirectoryWithoutSymlink(path, label) {
  const info = await existingKind(path);
  if (info === null) return false;
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`${label} must be a real directory, not a symlink: ${path}`);
  }
  return true;
}

export function archiveRelativePath(docset) {
  if (docset?.status !== 'archived') {
    throw new Error(`Docset "${docset?.id ?? '<unknown>'}" is not archived`);
  }
  if (
    typeof docset.path !== 'string' ||
    !/^\/v\/[a-z0-9][a-z0-9.-]*\/$/.test(docset.path)
  ) {
    throw new Error(
      `Archived docset "${docset.id}" path must be a safe path below /v/: ${docset.path}`,
    );
  }
  const rel = docset.path.slice(1, -1);
  if (rel.split('/').some((part) => part === '.' || part === '..')) {
    throw new Error(`Archived docset "${docset.id}" path contains traversal`);
  }
  return rel;
}

export function archiveOutputDirectory(docsRoot, docset) {
  const distRoot = resolve(docsRoot, 'dist');
  const output = resolve(distRoot, archiveRelativePath(docset));
  if (!isWithin(resolve(distRoot, 'v'), output)) {
    throw new Error(`Archived docset "${docset.id}" resolves outside dist/v`);
  }
  return output;
}

async function rejectUnsafeDirectory(path, label) {
  const info = await existingKind(path);
  if (info && (info.isSymbolicLink() || !info.isDirectory())) {
    throw new Error(`${label} must be a real directory, not a symlink: ${path}`);
  }
}

export async function validateArchiveOutputLocation(docsRoot, docset) {
  const distRoot = resolve(docsRoot, 'dist');
  const versionRoot = resolve(distRoot, 'v');
  const output = archiveOutputDirectory(docsRoot, docset);
  await rejectUnsafeDirectory(distRoot, 'archive dist root');
  await rejectUnsafeDirectory(versionRoot, 'archive version root');
  await rejectUnsafeDirectory(output, 'archive output');
  return output;
}

export async function validateLinkIndexLocation(docsRoot) {
  const distRoot = resolve(docsRoot, 'dist');
  const indexRoot = resolve(distRoot, '.archive-link-indexes');
  await rejectUnsafeDirectory(distRoot, 'archive dist root');
  await rejectUnsafeDirectory(indexRoot, 'archive link-index root');
  return indexRoot;
}

async function collectTreeFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`content-addressed archive trees cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) files.push(...(await collectTreeFiles(root, path)));
    else if (info.isFile()) files.push(path);
    else throw new Error(`archive tree contains an unsupported filesystem entry: ${path}`);
  }
  return files;
}

export async function treeDigest(root) {
  if (!(await requireDirectoryWithoutSymlink(root, 'archive tree'))) {
    throw new Error(`archive tree does not exist: ${root}`);
  }
  const hash = createHash('sha256');
  for (const path of await collectTreeFiles(root)) {
    const info = await lstat(path);
    const rel = relative(root, path).replaceAll(sep, '/');
    hash.update(`${rel}\0${info.mode & 0o111 ? 'x' : '-'}\0`);
    hash.update(await readFile(path));
    hash.update('\0');
  }
  return hash.digest('hex');
}

function ignoredDocsPath(rel) {
  const normalized = rel.replaceAll(sep, '/');
  return ignoredDocsPaths.some(
    (ignored) => normalized === ignored || normalized.startsWith(`${ignored}/`),
  );
}

async function inputFiles(root, current = root, { docsRoot = null } = {}) {
  const info = await existingKind(current);
  if (info === null) return [];
  if (info.isSymbolicLink()) {
    throw new Error(`archive inputs cannot contain symlinks: ${current}`);
  }
  if (info.isFile()) return [current];
  if (!info.isDirectory()) throw new Error(`unsupported archive input: ${current}`);
  const files = [];
  for (const entry of (await readdir(current, { withFileTypes: true })).sort((a, b) =>
    a.name.localeCompare(b.name),
  )) {
    const path = resolve(current, entry.name);
    if (docsRoot && ignoredDocsPath(relative(docsRoot, path))) continue;
    files.push(...(await inputFiles(root, path, { docsRoot })));
  }
  return files;
}

export async function computeArchiveInputDigest({
  docsRoot = process.cwd(),
  repoRoot = resolve(docsRoot, '../..'),
  inputRoots = null,
} = {}) {
  const roots = inputRoots ?? [
    { label: 'docs-site', path: docsRoot, docsRoot },
    {
      label: 'registryctl-authoring-catalog',
      path: resolve(repoRoot, 'crates/registryctl/tests/fixtures/project-authoring-journeys.yaml'),
    },
    {
      label: 'registryctl-authoring-fixtures',
      path: resolve(repoRoot, 'crates/registryctl/tests/fixtures/project-authoring'),
    },
    {
      label: 'registryctl-project-starters',
      path: resolve(repoRoot, 'crates/registryctl/assets/project-starters'),
    },
  ];
  const hash = createHash('sha256');
  for (const item of roots) {
    const root = resolve(item.path);
    const files = await inputFiles(root, root, { docsRoot: item.docsRoot ?? null });
    if (files.length === 0 && !(await existingKind(root))) {
      throw new Error(`required archive input is missing: ${root}`);
    }
    for (const path of files) {
      const info = await lstat(path);
      const rel = info.isFile() && path === root ? relative(dirname(root), path) : relative(root, path);
      hash.update(`${item.label}/${rel.replaceAll(sep, '/')}\0`);
      hash.update(await readFile(path));
      hash.update('\0');
    }
  }
  return hash.digest('hex');
}

function sourceRefs(docset) {
  return Object.entries(docset.products ?? {})
    .map(([name, product]) => ({
      name,
      version: product?.version,
      ref: product?.ref,
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

export function archiveIdentity({
  docset,
  manifest,
  inputDigest,
  environmentDigest = archiveEnvironmentDigest(),
  nodeVersion = process.versions.node,
}) {
  archiveRelativePath(docset);
  if (!shaPattern.test(inputDigest)) {
    throw new Error('archive input digest must be 64 lowercase hexadecimal characters');
  }
  if (!shaPattern.test(environmentDigest)) {
    throw new Error('archive environment digest must be 64 lowercase hexadecimal characters');
  }
  const identity = {
    schema_version: ARCHIVE_CACHE_SCHEMA,
    docset_id: docset.id,
    archive_path: docset.path,
    source_refs: sourceRefs(docset),
    docset,
    docsets_manifest: manifest,
    input_digest: inputDigest,
    environment_digest: environmentDigest,
    node_version: nodeVersion,
  };
  return { ...identity, cache_key: digest(canonicalJson(identity)) };
}

export function archiveCollectionKey(identities) {
  return digest(
    canonicalJson({
      schema_version: ARCHIVE_CACHE_SCHEMA,
      cache_keys: identities.map((identity) => identity.cache_key).sort(),
    }),
  );
}

function cacheEntry(cacheRoot, identity) {
  if (!shaPattern.test(identity.cache_key)) throw new Error('invalid archive cache key');
  const root = resolve(cacheRoot);
  const entry = resolve(root, identity.cache_key);
  if (!isWithin(root, entry)) throw new Error('archive cache entry escaped its cache root');
  return entry;
}

function linkIndexPath(docsRoot, docset) {
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(docset.id)) {
    throw new Error(`unsafe docset id for link index: ${docset.id}`);
  }
  return resolve(docsRoot, 'dist/.archive-link-indexes', `${docset.id}.json`);
}

async function readCacheMetadata(entry, identity) {
  const metadataPath = resolve(entry, 'metadata.json');
  const indexPath = resolve(entry, 'link-index.json');
  for (const [path, label] of [
    [metadataPath, 'cache metadata'],
    [indexPath, 'cached link index'],
  ]) {
    const info = await existingKind(path);
    if (info === null || info.isSymbolicLink() || !info.isFile()) {
      throw new Error(`${label} must be a regular file`);
    }
  }
  const metadata = JSON.parse(await readFile(metadataPath, 'utf8'));
  if (metadata.schema_version !== ARCHIVE_CACHE_SCHEMA) {
    throw new Error('cache metadata has an unsupported schema version');
  }
  if (canonicalJson(metadata.identity) !== canonicalJson(identity)) {
    throw new Error('cache metadata identity does not match the expected archive key');
  }
  if (!shaPattern.test(metadata.output_digest) || !shaPattern.test(metadata.link_index_digest)) {
    throw new Error('cache metadata contains an invalid output digest');
  }
  const index = JSON.parse(await readFile(indexPath, 'utf8'));
  if (
    index.schema_version !== LINK_INDEX_SCHEMA ||
    index.cache_key !== identity.cache_key ||
    index.docset_id !== identity.docset_id ||
    index.archive_path !== identity.archive_path
  ) {
    throw new Error('cached link index identity does not match the archive cache entry');
  }
  return { metadata, metadataPath, indexPath };
}

export async function restoreArchive({ docsRoot, cacheRoot, docset, identity }) {
  const resolvedCacheRoot = resolve(cacheRoot);
  const cacheRootInfo = await existingKind(resolvedCacheRoot);
  if (cacheRootInfo === null) return { restored: false, reason: 'cache directory is absent' };
  if (cacheRootInfo.isSymbolicLink() || !cacheRootInfo.isDirectory()) {
    throw new Error(`archive cache root must be a real directory: ${resolvedCacheRoot}`);
  }
  const entry = cacheEntry(resolvedCacheRoot, identity);
  const entryInfo = await existingKind(entry);
  if (entryInfo === null) return { restored: false, reason: 'cache entry is absent' };
  if (entryInfo.isSymbolicLink() || !entryInfo.isDirectory()) {
    return { restored: false, reason: 'cache entry is not a real directory' };
  }
  try {
    const { metadata, indexPath } = await readCacheMetadata(entry, identity);
    const site = resolve(entry, 'site');
    if ((await treeDigest(site)) !== metadata.output_digest) {
      throw new Error('cached archive output digest does not match metadata');
    }
    if ((await fileDigest(indexPath)) !== metadata.link_index_digest) {
      throw new Error('cached link index digest does not match metadata');
    }
    const output = await validateArchiveOutputLocation(docsRoot, docset);
    await rm(output, { recursive: true, force: true });
    await mkdir(dirname(output), { recursive: true });
    await cp(site, output, { recursive: true, force: false, errorOnExist: true });
    const destinationIndex = linkIndexPath(docsRoot, docset);
    await mkdir(await validateLinkIndexLocation(docsRoot), { recursive: true });
    await cp(indexPath, destinationIndex, { force: true });
    return { restored: true, output, cache_key: identity.cache_key };
  } catch (error) {
    return { restored: false, reason: error.message };
  }
}

export async function storeArchive({ docsRoot, cacheRoot, docset, identity, linkIndex }) {
  const resolvedCacheRoot = resolve(cacheRoot);
  const cacheRootInfo = await existingKind(resolvedCacheRoot);
  if (cacheRootInfo?.isSymbolicLink() || (cacheRootInfo && !cacheRootInfo.isDirectory())) {
    throw new Error(`archive cache root must be a real directory: ${resolvedCacheRoot}`);
  }
  await mkdir(resolvedCacheRoot, { recursive: true });
  const output = await validateArchiveOutputLocation(docsRoot, docset);
  const outputDigest = await treeDigest(output);
  if (
    linkIndex?.schema_version !== LINK_INDEX_SCHEMA ||
    linkIndex.cache_key !== identity.cache_key ||
    linkIndex.docset_id !== docset.id ||
    linkIndex.archive_path !== docset.path
  ) {
    throw new Error('link index does not match the archive being cached');
  }
  const indexBody = `${JSON.stringify(linkIndex, null, 2)}\n`;
  const metadata = {
    schema_version: ARCHIVE_CACHE_SCHEMA,
    identity,
    output_digest: outputDigest,
    link_index_digest: digest(indexBody),
  };
  const entry = cacheEntry(resolvedCacheRoot, identity);
  const temporary = resolve(
    resolvedCacheRoot,
    `.tmp-${process.pid}-${identity.cache_key}-${Date.now()}`,
  );
  if (!isWithin(resolvedCacheRoot, temporary)) throw new Error('temporary cache path escaped root');
  await rm(temporary, { recursive: true, force: true });
  await mkdir(temporary, { recursive: true });
  try {
    await cp(output, resolve(temporary, 'site'), {
      recursive: true,
      force: false,
      errorOnExist: true,
    });
    await writeFile(resolve(temporary, 'link-index.json'), indexBody);
    await writeFile(resolve(temporary, 'metadata.json'), `${JSON.stringify(metadata, null, 2)}\n`);
    await rm(entry, { recursive: true, force: true });
    await rename(temporary, entry);
  } catch (error) {
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }
  return { cache_key: identity.cache_key, output_digest: outputDigest };
}

export async function pruneArchiveCache(cacheRoot, identities) {
  const root = resolve(cacheRoot);
  const info = await existingKind(root);
  if (info === null) return;
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`archive cache root must be a real directory: ${root}`);
  }
  const expected = new Set(identities.map((identity) => identity.cache_key));
  for (const entry of await readdir(root)) {
    if (!expected.has(entry)) await rm(resolve(root, entry), { recursive: true, force: true });
  }
}

async function collectionKeyCommand() {
  const docsRoot = process.cwd();
  const dataDir = resolve(docsRoot, 'src/data');
  const manifest = await loadDocsets({ dataDir });
  const inputDigest = await computeArchiveInputDigest({ docsRoot });
  const identities = manifest.docsets
    .filter((docset) => docset.status === 'archived')
    .map((docset) => archiveIdentity({ docset, manifest, inputDigest }));
  process.stdout.write(`key=${archiveCollectionKey(identities)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  if (process.argv.length !== 3 || process.argv[2] !== 'collection-key') {
    console.error('usage: node scripts/archive-cache.mjs collection-key');
    process.exitCode = 1;
  } else {
    await collectionKeyCommand();
  }
}
