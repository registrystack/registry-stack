import { execFile } from 'node:child_process';
import { readdir, readFile, writeFile } from 'node:fs/promises';
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
const versionPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const releaseIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const releaseRepository = 'registrystack/registry-stack';
const releaseRemote = `https://github.com/${releaseRepository}.git`;

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

export function assertArchiveLockImmutable(
  baseLock,
  currentLock,
  { mutableArchiveId = null } = {},
) {
  const errors = [];
  for (const [id, entry] of Object.entries(baseLock?.archives ?? {})) {
    if (!currentLock?.archives || !(id in currentLock.archives)) {
      errors.push(`immutable archive lock entry ${id} was removed`);
      continue;
    }
    if (
      canonicalJson(entry) !== canonicalJson(currentLock.archives[id]) &&
      id !== mutableArchiveId
    ) {
      errors.push(`immutable archive lock entry ${id} was changed`);
    }
  }
  return errors;
}

function changedBaseArchiveEntries(baseLock, currentLock) {
  const changed = [];
  const removed = [];
  for (const [id, entry] of Object.entries(baseLock?.archives ?? {})) {
    if (!currentLock?.archives || !(id in currentLock.archives)) {
      removed.push(id);
    } else if (canonicalJson(entry) !== canonicalJson(currentLock.archives[id])) {
      changed.push(id);
    }
  }
  return { changed, removed };
}

function workspacePackageVersion(source) {
  let section = null;
  for (const line of source.split(/\r?\n/)) {
    const heading = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(line);
    if (heading) {
      section = heading[1];
      continue;
    }
    if (section !== 'workspace.package') continue;
    const version = /^\s*version\s*=\s*"([^"]+)"\s*(?:#.*)?$/.exec(line);
    if (version) {
      if (!versionPattern.test(version[1])) {
        throw new Error('workspace package version must be canonical semantic version text');
      }
      return version[1];
    }
  }
  throw new Error('Cargo.toml must declare workspace.package.version');
}

async function preparedCandidateArchiveId(repoRoot, docsets) {
  const version = workspacePackageVersion(
    await readFile(resolve(repoRoot, 'Cargo.toml'), 'utf8'),
  );
  const manifestDirectory = resolve(repoRoot, 'release/manifests');
  const manifests = [];
  for (const name of (await readdir(manifestDirectory)).sort()) {
    if (!/^registry-stack-.+[.]yaml$/.test(name)) continue;
    const manifest = YAML.parse(await readFile(resolve(manifestDirectory, name), 'utf8'));
    if (manifest?.stack?.version === version) manifests.push({ name, manifest });
  }
  if (manifests.length !== 1) return null;
  const { name, manifest } = manifests[0];
  const releaseId = manifest.stack.release;
  const id = `v${version}`;
  if (
    typeof releaseId !== 'string' ||
    !releaseIdPattern.test(releaseId) ||
    name !== `registry-stack-${releaseId}.yaml` ||
    manifest.stack.source_repo !== releaseRepository ||
    manifest.stack.source_tag !== id ||
    manifest.artifacts?.['registry-docs'] !== version
  ) {
    return null;
  }
  const candidates = docsets.docsets.filter((docset) => docset.id === id);
  if (candidates.length !== 1) return null;
  const candidate = candidates[0];
  const stack = candidate.products?.['registry-stack'];
  if (
    candidate.status !== 'archived' ||
    candidate.availability !== 'candidate' ||
    stack?.version !== id ||
    stack?.ref !== (manifest.stack.source_ref ?? id)
  ) {
    return null;
  }
  return id;
}

async function releaseTagState(tag, runCommand) {
  const reference = `refs/tags/${tag}`;
  try {
    const { stdout, stderr } = await runCommand(
      'git',
      ['ls-remote', '--exit-code', '--refs', '--tags', releaseRemote, reference],
      {
        env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
        maxBuffer: 1024 * 1024,
        timeout: 15_000,
      },
    );
    const lines = stdout.trim().split('\n').filter(Boolean);
    const expected = new RegExp(`^[0-9a-f]{40}(?:[0-9a-f]{24})?\\t${reference.replaceAll('.', '[.]')}$`);
    if (stderr.trim() || lines.length !== 1 || !expected.test(lines[0])) {
      throw new Error('git ls-remote returned ambiguous output');
    }
    return 'present';
  } catch (error) {
    if (
      error?.code === 2 &&
      !(error.stdout ?? '').trim() &&
      !(error.stderr ?? '').trim()
    ) {
      return 'absent';
    }
    throw new Error(`cannot prove release tag ${tag} is absent on ${releaseRepository}`, {
      cause: error,
    });
  }
}

export async function assertArchiveLockImmutableForRepository(
  baseLock,
  currentLock,
  { repoRoot, docsets, runCommand = run },
) {
  const { changed, removed } = changedBaseArchiveEntries(baseLock, currentLock);
  let mutableArchiveId = null;
  if (removed.length === 0 && changed.length === 1) {
    const candidateId = await preparedCandidateArchiveId(repoRoot, docsets);
    if (candidateId === changed[0]) {
      const state = await releaseTagState(candidateId, runCommand);
      if (state === 'absent') mutableArchiveId = candidateId;
    }
  }
  return assertArchiveLockImmutable(baseLock, currentLock, { mutableArchiveId });
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
    const repoRoot = resolve(docsRoot, '../..');
    const baseLock = await archiveLockAtGitRef(baseRef, repoRoot);
    if (baseLock) {
      errors.push(...await assertArchiveLockImmutableForRepository(baseLock, lock, {
        repoRoot,
        docsets,
      }));
    }
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
