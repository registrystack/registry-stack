import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import YAML from 'yaml';

import {
  ARCHIVE_LOCK_SCHEMA,
  canonicalJson,
  createArchiveBundle,
  localArchiveBundlePath,
} from './archive-bundle.mjs';
import { getDocset, loadDocsets } from './docsets.mjs';

const run = promisify(execFile);
const sha256Pattern = /^[0-9a-f]{64}$/;

function isLockBackedDocset(docset) {
  return (
    docset.status === 'archived' ||
    (docset.status === 'draft' && docset.availability === 'failed')
  );
}

export async function loadArchiveLock({
  lockPath = resolve(process.cwd(), 'src/data/archive-lock.yaml'),
} = {}) {
  return YAML.parse(await readFile(lockPath, 'utf8'));
}

export function validateArchiveLock(lock, docsets) {
  const errors = [];
  if (!lock || typeof lock !== 'object' || Array.isArray(lock)) {
    return ['archive-lock.yaml must contain a top-level object'];
  }
  if (lock.schema_version !== ARCHIVE_LOCK_SCHEMA) {
    errors.push(`archive-lock.yaml schema_version must be ${ARCHIVE_LOCK_SCHEMA}`);
  }
  if (!lock.archives || typeof lock.archives !== 'object' || Array.isArray(lock.archives)) {
    errors.push('archive-lock.yaml archives must be a map');
    return errors;
  }
  const expectedIds = docsets.docsets
    .filter(isLockBackedDocset)
    .map((docset) => docset.id)
    .sort();
  const actualIds = Object.keys(lock.archives).sort();
  for (const missing of expectedIds.filter((id) => !actualIds.includes(id))) {
    errors.push(`archive-lock.yaml is missing lock-backed docset ${missing}`);
  }
  for (const unexpected of actualIds.filter((id) => !expectedIds.includes(id))) {
    errors.push(`archive-lock.yaml contains non-lock-backed docset ${unexpected}`);
  }
  for (const id of actualIds) {
    const entry = lock.archives[id];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      errors.push(`archive-lock.yaml ${id} entry must be a map`);
      continue;
    }
    const dualTree = Object.hasOwn(entry, 'root_tree_sha256') ||
      Object.hasOwn(entry, 'version_tree_sha256');
    const allowed = dualTree
      ? ['bundle_sha256', 'root_tree_sha256', 'version_tree_sha256']
      : ['bundle_sha256', 'tree_sha256'];
    const unknown = Object.keys(entry).filter((key) => !allowed.includes(key));
    if (unknown.length > 0) {
      errors.push(`archive-lock.yaml ${id} has unknown field ${unknown[0]}`);
    }
    for (const field of allowed) {
      if (!sha256Pattern.test(entry[field] ?? '')) {
        errors.push(`archive-lock.yaml ${id}.${field} must be 64 lowercase hex characters`);
      }
    }
  }
  return errors;
}

export function assertArchiveLockImmutable(baseLock, currentLock) {
  const errors = [];
  for (const [id, entry] of Object.entries(baseLock?.archives ?? {})) {
    if (!currentLock?.archives || !(id in currentLock.archives)) {
      errors.push(`immutable archive lock entry ${id} was removed`);
      continue;
    }
    if (canonicalJson(entry) !== canonicalJson(currentLock.archives[id])) {
      errors.push(`immutable archive lock entry ${id} was changed`);
    }
  }
  return errors;
}

export function addArchiveLockEntry(lock, docsetId, result) {
  if (lock?.schema_version !== ARCHIVE_LOCK_SCHEMA || !lock.archives) {
    throw new Error('archive-lock.yaml must be valid before adding an archive');
  }
  if (Object.hasOwn(lock.archives, docsetId)) {
    throw new Error(`immutable archive lock entry ${docsetId} already exists`);
  }
  lock.archives[docsetId] = result.root_tree_sha256
    ? {
        bundle_sha256: result.bundle_sha256,
        root_tree_sha256: result.root_tree_sha256,
        version_tree_sha256: result.version_tree_sha256,
      }
    : {
        bundle_sha256: result.bundle_sha256,
        tree_sha256: result.tree_sha256,
      };
  return lock;
}

async function archiveLockAtGitRef(baseRef, repoRoot) {
  try {
    const { stdout } = await run(
      'git',
      ['show', `${baseRef}:docs/site/src/data/archive-lock.yaml`],
      { cwd: repoRoot, maxBuffer: 4 * 1024 * 1024 },
    );
    return YAML.parse(stdout);
  } catch (error) {
    if (
      error?.code === 128 &&
      /does not exist|exists on disk, but not in/.test(error.stderr ?? '')
    ) {
      return null;
    }
    throw error;
  }
}

export async function checkArchiveLock({
  docsRoot = process.cwd(),
  baseRef = null,
} = {}) {
  const docsets = await loadDocsets({ dataDir: resolve(docsRoot, 'src/data') });
  const lock = await loadArchiveLock({
    lockPath: resolve(docsRoot, 'src/data/archive-lock.yaml'),
  });
  const errors = validateArchiveLock(lock, docsets);
  if (baseRef) {
    const baseLock = await archiveLockAtGitRef(baseRef, resolve(docsRoot, '../..'));
    if (baseLock) errors.push(...assertArchiveLockImmutable(baseLock, lock));
  }
  if (errors.length > 0) throw new Error(errors.join('\n'));
  return { docsets, lock };
}

export async function snapshotArchive({
  docsRoot = process.cwd(),
  docsetId,
  bundlePath = null,
  verifyLock = false,
  writeLock = false,
} = {}) {
  if (verifyLock && writeLock) {
    throw new Error('--verify-lock and --write-lock cannot be used together');
  }
  const docsets = await loadDocsets({ dataDir: resolve(docsRoot, 'src/data') });
  const docset = getDocset(docsets, docsetId);
  const result = await createArchiveBundle({
    docsRoot,
    docset,
    bundlePath: bundlePath ?? localArchiveBundlePath(docsRoot, docset),
  });
  if (verifyLock) {
    const lock = await loadArchiveLock({
      lockPath: resolve(docsRoot, 'src/data/archive-lock.yaml'),
    });
    const expected = lock.archives?.[docset.id];
    const matches = expected?.bundle_sha256 === result.bundle_sha256 &&
      (result.root_tree_sha256
        ? expected?.root_tree_sha256 === result.root_tree_sha256 &&
          expected?.version_tree_sha256 === result.version_tree_sha256
        : expected?.tree_sha256 === result.tree_sha256);
    if (!matches) {
      throw new Error(
        `archive bundle ${docset.id} does not match its immutable lock entry`,
      );
    }
  }
  if (writeLock) {
    const lockPath = resolve(docsRoot, 'src/data/archive-lock.yaml');
    const lock = await loadArchiveLock({ lockPath });
    addArchiveLockEntry(lock, docset.id, result);
    await writeFile(lockPath, YAML.stringify(lock), 'utf8');
  }
  return { docset, result };
}

function parseArgs(args) {
  const command = args.shift();
  if (command === 'check') {
    let baseRef = null;
    while (args.length > 0) {
      const option = args.shift();
      if (option === '--base-ref' && args[0]) {
        baseRef = args.shift();
      } else {
        throw new Error('usage: archive-lock.mjs check [--base-ref <git-ref>]');
      }
    }
    return { command, baseRef };
  }
  if (command === 'snapshot' && args.length >= 1) {
    const docsetId = args.shift();
    let bundlePath = null;
    let verifyLock = false;
    let writeLock = false;
    while (args.length > 0) {
      const option = args.shift();
      if (option === '--output' && args[0]) {
        bundlePath = resolve(args.shift());
      } else if (option === '--verify-lock') {
        verifyLock = true;
      } else if (option === '--write-lock') {
        writeLock = true;
      } else {
        throw new Error(
          'usage: archive-lock.mjs snapshot <docset-id> [--output <bundle-path>] [--verify-lock|--write-lock]',
        );
      }
    }
    return { command, docsetId, bundlePath, verifyLock, writeLock };
  }
  throw new Error(
    'usage: archive-lock.mjs check [--base-ref <git-ref>] | snapshot <docset-id> [--output <bundle-path>] [--verify-lock|--write-lock]',
  );
}

async function main(args) {
  const parsed = parseArgs([...args]);
  if (parsed.command === 'check') {
    const { lock } = await checkArchiveLock({ baseRef: parsed.baseRef });
    console.log(`Archive lock check passed for ${Object.keys(lock.archives).length} archive(s).`);
    return;
  }
  const { docset, result } = await snapshotArchive(parsed);
  const entry = {
    bundle_sha256: result.bundle_sha256,
    ...(result.root_tree_sha256
      ? {
          root_tree_sha256: result.root_tree_sha256,
          version_tree_sha256: result.version_tree_sha256,
        }
      : { tree_sha256: result.tree_sha256 }),
  };
  process.stdout.write(
    `${docset.id}:\n${YAML.stringify(entry).replace(/^/gm, '  ').trimEnd()}\n`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    await main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
