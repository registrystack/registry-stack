import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, posix, relative, resolve, sep } from 'node:path';

import * as tar from 'tar';

export const ARCHIVE_BUNDLE_SCHEMA = 'registry-docs.archive-bundle.v1';
export const ARCHIVE_LOCK_SCHEMA = 'registry-docs.archive-lock.v1';

const sha256Pattern = /^[0-9a-f]{64}$/;
const archivePathPattern = /^\/v\/[a-z0-9][a-z0-9.-]*\/$/;
const archiveIdPattern = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/;
const maximumArchiveBundleBytes = 256 * 1024 * 1024;
const maximumExtractedBytes = 1024 * 1024 * 1024;
const maximumArchiveEntries = 100_000;

export function canonicalValue(value) {
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

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function readRegularFile(path, label, {
  maximumBytes = Number.POSITIVE_INFINITY,
} = {}) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    if (error?.code === 'ELOOP') {
      throw new Error(`${label} must be a regular file, not a symlink: ${path}`);
    }
    throw error;
  }
  try {
    const before = await handle.stat();
    if (!before.isFile()) {
      throw new Error(`${label} must be a regular file: ${path}`);
    }
    if (before.size > maximumBytes) {
      throw new Error(`${label} must be no larger than ${maximumBytes} bytes`);
    }
    const contents = await handle.readFile();
    const after = await handle.stat();
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      throw new Error(`${label} changed while it was being read: ${path}`);
    }
    return { contents, info: after };
  } finally {
    await handle.close();
  }
}

export async function fileDigest(path) {
  const { contents } = await readRegularFile(path, 'digest input');
  return sha256(contents);
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

async function requireRealDirectory(path, label) {
  const info = await existingKind(path);
  if (!info || info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`${label} must be a real directory: ${path}`);
  }
}

async function rejectUnsafeDirectory(path, label) {
  const info = await existingKind(path);
  if (info && (info.isSymbolicLink() || !info.isDirectory())) {
    throw new Error(`${label} must be a real directory, not a symlink: ${path}`);
  }
}

export function archiveRelativePath(docset) {
  if (docset?.status !== 'archived') {
    throw new Error(`Docset "${docset?.id ?? '<unknown>'}" is not archived`);
  }
  if (!archiveIdPattern.test(docset.id)) {
    throw new Error(`Archived docset id is unsafe: ${docset.id}`);
  }
  if (typeof docset.path !== 'string' || !archivePathPattern.test(docset.path)) {
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

export async function validateArchiveOutputLocation(docsRoot, docset) {
  const distRoot = resolve(docsRoot, 'dist');
  const versionRoot = resolve(distRoot, 'v');
  const output = archiveOutputDirectory(docsRoot, docset);
  await rejectUnsafeDirectory(distRoot, 'archive dist root');
  await rejectUnsafeDirectory(versionRoot, 'archive version root');
  await rejectUnsafeDirectory(output, 'archive output');
  return output;
}

export function archiveBundleName(docset) {
  archiveRelativePath(docset);
  return `registry-docs-${docset.id}.tar.gz`;
}

export function publicArchiveBundlePath(docsRoot, docset) {
  archiveRelativePath(docset);
  return resolve(docsRoot, 'dist/_archive-bundles', `${docset.id}.tar.gz`);
}

export function localArchiveBundlePath(docsRoot, docset) {
  archiveRelativePath(docset);
  return resolve(docsRoot, '.archive-bundles', `${docset.id}.tar.gz`);
}

async function collectTree(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const directories = [];
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`immutable archive trees cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) {
      directories.push(path);
      const nested = await collectTree(root, path);
      directories.push(...nested.directories);
      files.push(...nested.files);
    } else if (info.isFile()) {
      files.push(path);
    } else {
      throw new Error(`archive tree contains an unsupported filesystem entry: ${path}`);
    }
  }
  return { directories, files };
}

export async function treeDigest(root) {
  await requireRealDirectory(root, 'archive tree');
  const { files } = await collectTree(root);
  const hash = createHash('sha256');
  for (const path of files) {
    const { contents, info } = await readRegularFile(path, 'archive tree entry');
    const rel = relative(root, path).replaceAll(sep, '/');
    hash.update(`${rel}\0${info.mode & 0o111 ? 'x' : '-'}\0`);
    hash.update(contents);
    hash.update('\0');
  }
  return hash.digest('hex');
}

export function archiveSourceRefs(docset) {
  return Object.entries(docset.products ?? {})
    .map(([name, product]) => ({
      name,
      version: product?.version,
      ref: product?.ref,
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

export function archiveMetadata(docset, outputDigest) {
  if (!sha256Pattern.test(outputDigest)) {
    throw new Error('archive output digest must be 64 lowercase hexadecimal characters');
  }
  archiveRelativePath(docset);
  return {
    schema_version: ARCHIVE_BUNDLE_SCHEMA,
    docset_id: docset.id,
    archive_path: docset.path,
    source: docset.source,
    published_at: docset.published_at,
    source_refs: archiveSourceRefs(docset),
    tree_sha256: outputDigest,
  };
}

async function stagedTarEntries(stagingRoot) {
  const { directories, files } = await collectTree(stagingRoot);
  return [...directories, ...files]
    .map((path) => relative(stagingRoot, path).replaceAll(sep, '/'))
    .sort();
}

export async function createArchiveBundle({
  docsRoot = process.cwd(),
  docset,
  bundlePath = localArchiveBundlePath(docsRoot, docset),
} = {}) {
  const output = await validateArchiveOutputLocation(docsRoot, docset);
  await requireRealDirectory(output, `archive output for ${docset.id}`);
  const staging = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-bundle-'));
  let outputDigest;
  let metadata;
  try {
    await cp(output, resolve(staging, 'site'), {
      recursive: true,
      dereference: false,
      force: false,
      errorOnExist: true,
      preserveTimestamps: false,
      verbatimSymlinks: true,
    });
    outputDigest = await treeDigest(resolve(staging, 'site'));
    metadata = archiveMetadata(docset, outputDigest);
    await writeFile(
      resolve(staging, 'metadata.json'),
      `${JSON.stringify(metadata, null, 2)}\n`,
      { mode: 0o644 },
    );
    const entries = await stagedTarEntries(staging);
    await mkdir(dirname(bundlePath), { recursive: true });
    await rm(bundlePath, { force: true });
    await Promise.resolve(tar.create(
      {
        cwd: staging,
        file: bundlePath,
        filter(_path, info) {
          const permissions = info.isDirectory()
            ? 0o755
            : info.mode & 0o111
              ? 0o755
              : 0o644;
          info.mode = (info.mode & ~0o7777) | permissions;
          return true;
        },
        gzip: { level: 9, mtime: 0 },
        mtime: new Date(0),
        noDirRecurse: true,
        noPax: true,
        portable: true,
        strict: true,
      },
      entries,
    ));
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
  return {
    bundle_path: bundlePath,
    bundle_sha256: await fileDigest(bundlePath),
    tree_sha256: outputDigest,
    metadata,
  };
}

function validateTarEntry(path, entry) {
  if (path.includes('\\') || path.startsWith('/') || path.includes('\0')) {
    throw new Error(`archive bundle contains an unsafe path: ${path}`);
  }
  const normalized = posix.normalize(path);
  if (
    normalized !== path ||
    normalized === '..' ||
    normalized.startsWith('../') ||
    !(
      normalized === 'metadata.json' ||
      normalized === 'site' ||
      normalized.startsWith('site/')
    )
  ) {
    throw new Error(`archive bundle contains an unsafe path: ${path}`);
  }
  if (!['Directory', 'File'].includes(entry.type)) {
    throw new Error(`archive bundle contains unsupported ${entry.type} entry: ${path}`);
  }
  return true;
}

function assertMetadataMatchesDocset(metadata, docset) {
  const expected = {
    schema_version: ARCHIVE_BUNDLE_SCHEMA,
    docset_id: docset.id,
    archive_path: docset.path,
    source: docset.source,
    published_at: docset.published_at,
    source_refs: archiveSourceRefs(docset),
    tree_sha256: metadata.tree_sha256,
  };
  if (canonicalJson(metadata) !== canonicalJson(expected)) {
    throw new Error(`archive bundle metadata does not match docset ${docset.id}`);
  }
  if (!sha256Pattern.test(metadata.tree_sha256)) {
    throw new Error(`archive bundle ${docset.id} has an invalid tree digest`);
  }
}

export async function inspectArchiveBundle({
  bundlePath,
  docset,
  expectedBundleSha256,
  expectedTreeSha256,
} = {}) {
  if (!sha256Pattern.test(expectedBundleSha256)) {
    throw new Error(`archive bundle ${docset.id} has no valid locked bundle digest`);
  }
  if (!sha256Pattern.test(expectedTreeSha256)) {
    throw new Error(`archive bundle ${docset.id} has no valid locked tree digest`);
  }
  const { contents: bundleContents } = await readRegularFile(
    bundlePath,
    `archive bundle ${docset.id}`,
    { maximumBytes: maximumArchiveBundleBytes },
  );
  const actualBundleDigest = sha256(bundleContents);
  if (actualBundleDigest !== expectedBundleSha256) {
    throw new Error(
      `archive bundle ${docset.id} digest ${actualBundleDigest} does not match lock ${expectedBundleSha256}`,
    );
  }

  const temporary = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-extract-'));
  const extraction = resolve(temporary, 'extracted');
  const bundleSnapshot = resolve(temporary, 'bundle.tar.gz');
  try {
    await mkdir(extraction);
    await writeFile(bundleSnapshot, bundleContents, { mode: 0o600 });
    let entryCount = 0;
    let extractedBytes = 0;
    await Promise.resolve(tar.extract({
      cwd: extraction,
      file: bundleSnapshot,
      filter(path, entry) {
        entryCount += 1;
        extractedBytes += Number(entry.size ?? 0);
        if (entryCount > maximumArchiveEntries) {
          throw new Error(
            `archive bundle ${docset.id} exceeds ${maximumArchiveEntries} entries`,
          );
        }
        if (extractedBytes > maximumExtractedBytes) {
          throw new Error(
            `archive bundle ${docset.id} exceeds ${maximumExtractedBytes} extracted bytes`,
          );
        }
        return validateTarEntry(path, entry);
      },
      preservePaths: false,
      strict: true,
    }));
    const rootEntries = (await readdir(extraction)).sort();
    if (canonicalJson(rootEntries) !== canonicalJson(['metadata.json', 'site'])) {
      throw new Error(`archive bundle ${docset.id} must contain only metadata.json and site/`);
    }
    const { contents: metadataContents } = await readRegularFile(
      resolve(extraction, 'metadata.json'),
      `archive bundle ${docset.id} metadata`,
    );
    await requireRealDirectory(resolve(extraction, 'site'), `archive bundle ${docset.id} site`);
    const metadata = JSON.parse(metadataContents.toString('utf8'));
    assertMetadataMatchesDocset(metadata, docset);
    const actualTreeDigest = await treeDigest(resolve(extraction, 'site'));
    if (
      actualTreeDigest !== metadata.tree_sha256 ||
      actualTreeDigest !== expectedTreeSha256
    ) {
      throw new Error(
        `archive bundle ${docset.id} tree digest ${actualTreeDigest} does not match its lock`,
      );
    }
    return {
      bundle_sha256: actualBundleDigest,
      bundle_snapshot: bundleSnapshot,
      extraction,
      metadata,
      temporary,
      tree_sha256: actualTreeDigest,
    };
  } catch (error) {
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }
}

export async function restoreArchiveBundle({
  docsRoot = process.cwd(),
  bundlePath,
  docset,
  expectedBundleSha256,
  expectedTreeSha256,
  publishBundle = true,
} = {}) {
  const inspected = await inspectArchiveBundle({
    bundlePath,
    docset,
    expectedBundleSha256,
    expectedTreeSha256,
  });
  try {
    const output = await validateArchiveOutputLocation(docsRoot, docset);
    await rm(output, { recursive: true, force: true });
    await mkdir(dirname(output), { recursive: true });
    await cp(resolve(inspected.extraction, 'site'), output, {
      recursive: true,
      force: false,
      errorOnExist: true,
      preserveTimestamps: false,
    });
    const publicBundle = publicArchiveBundlePath(docsRoot, docset);
    if (publishBundle) {
      await mkdir(dirname(publicBundle), { recursive: true });
      await cp(inspected.bundle_snapshot, publicBundle, { force: true });
    }
    return {
      ...inspected,
      output,
      public_bundle: publishBundle ? publicBundle : null,
    };
  } finally {
    await rm(inspected.temporary, { recursive: true, force: true });
  }
}
