import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import * as tar from 'tar';

import {
  canonicalJson,
  fileDigest,
  treeDigest,
} from './archive-bundle.mjs';
import { getDocset, loadDocsets } from './docsets.mjs';

export const PREVIEW_RECEIPT_SCHEMA = 'registry-docs.unreleased-preview-receipt.v1';
export const PREVIEW_INVENTORY_SCHEMA = 'registry-docs.unreleased-preview-inventory.v1';
export const PREVIEW_DOCSET = 'latest';
export const PREVIEW_AVAILABILITY = 'unreleased';
export const PREVIEW_RELEASE_COORDINATE = null;
export const PREVIEW_RELEASE_COORDINATE_STATUS = 'unassigned';
export const PREVIEW_BASE = '/preview/';

const shaPattern = /^[0-9a-f]{40}$/;
const execFileAsync = promisify(execFile);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function collectTree(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const directories = [];
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(current, entry.name);
    const info = await lstat(path);
    if (info.isSymbolicLink()) {
      throw new Error(`unreleased preview cannot contain symlinks: ${path}`);
    }
    if (info.isDirectory()) {
      directories.push(path);
      const nested = await collectTree(root, path);
      directories.push(...nested.directories);
      files.push(...nested.files);
    } else if (info.isFile()) {
      files.push(path);
    } else {
      throw new Error(`unreleased preview contains an unsupported filesystem entry: ${path}`);
    }
  }
  return { directories, files };
}

async function previewInventory(previewRoot) {
  const { files } = await collectTree(previewRoot);
  const entries = [];
  for (const path of files) {
    const info = await lstat(path);
    entries.push({
      path: relative(previewRoot, path).replaceAll(sep, '/'),
      bytes: info.size,
      mode: info.mode & 0o111 ? 'executable' : 'regular',
      sha256: await fileDigest(path),
    });
  }
  return {
    schema_version: PREVIEW_INVENTORY_SCHEMA,
    base: PREVIEW_BASE,
    entries,
  };
}

async function tarEntries(stagingRoot) {
  const { directories, files } = await collectTree(stagingRoot);
  return [...directories, ...files]
    .map((path) => relative(stagingRoot, path).replaceAll(sep, '/'))
    .sort();
}

async function createDeterministicTar(previewRoot, tarPath) {
  const staging = await mkdtemp(resolve(tmpdir(), 'registry-docs-preview-'));
  try {
    await cp(previewRoot, resolve(staging, 'site'), {
      recursive: true,
      dereference: false,
      force: false,
      errorOnExist: true,
      preserveTimestamps: false,
      verbatimSymlinks: true,
    });
    const entries = await tarEntries(staging);
    await mkdir(dirname(tarPath), { recursive: true });
    await rm(tarPath, { force: true });
    await Promise.resolve(tar.create(
      {
        cwd: staging,
        file: tarPath,
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
}

function requireSha(value, label) {
  if (!shaPattern.test(value ?? '')) {
    throw new Error(`${label} must be a full 40-character lowercase Git SHA`);
  }
  return value;
}

function pullRequestBinding({ eventName, headSha, baseSha }) {
  const hasHead = Boolean(headSha);
  const hasBase = Boolean(baseSha);
  if (eventName === 'pull_request' || hasHead || hasBase) {
    if (!hasHead || !hasBase) {
      throw new Error('pull request preview evidence requires both head and base SHAs');
    }
    return {
      head_sha: requireSha(headSha, 'pull request head'),
      base_sha: requireSha(baseSha, 'pull request base'),
    };
  }
  return null;
}

export async function packageUnreleasedPreview({
  docsRoot = process.cwd(),
  previewRoot = resolve(docsRoot, 'dist/preview'),
  outputRoot = resolve(docsRoot, 'preview-evidence'),
  buildCommit,
  buildTree,
  eventName = '',
  pullRequestHead = '',
  pullRequestBase = '',
  nodeVersion = process.version,
} = {}) {
  const previewInfo = await lstat(previewRoot);
  if (previewInfo.isSymbolicLink() || !previewInfo.isDirectory()) {
    throw new Error(`unreleased preview must be a real directory: ${previewRoot}`);
  }
  const entrypoint = await lstat(resolve(previewRoot, 'index.html'));
  if (entrypoint.isSymbolicLink() || !entrypoint.isFile()) {
    throw new Error('unreleased preview must contain a regular index.html');
  }

  const docsets = await loadDocsets({ dataDir: resolve(docsRoot, 'src/data') });
  const current = getDocset(docsets, PREVIEW_DOCSET);
  if (
    docsets.current !== PREVIEW_DOCSET ||
    current.status !== 'current' ||
    current.availability !== PREVIEW_AVAILABILITY
  ) {
    throw new Error(
      `preview evidence requires docset ${PREVIEW_DOCSET} with availability ${PREVIEW_AVAILABILITY}`,
    );
  }

  const commit = requireSha(buildCommit, 'build commit');
  const tree = requireSha(buildTree, 'build tree');
  const pullRequest = pullRequestBinding({
    eventName,
    headSha: pullRequestHead,
    baseSha: pullRequestBase,
  });
  const packageLockPath = resolve(docsRoot, 'package-lock.json');
  const inventory = await previewInventory(previewRoot);
  const inventoryBytes = `${canonicalJson(inventory)}\n`;
  const inventoryDigest = sha256(inventoryBytes);
  const previewTreeDigest = await treeDigest(previewRoot);
  const stem = 'registry-docs-unreleased-preview';
  const tarPath = resolve(outputRoot, `${stem}.tar.gz`);
  const inventoryPath = resolve(outputRoot, `${stem}.inventory.json`);
  const receiptPath = resolve(outputRoot, `${stem}.receipt.json`);

  await mkdir(outputRoot, { recursive: true });
  await writeFile(inventoryPath, inventoryBytes, { mode: 0o644 });
  await createDeterministicTar(previewRoot, tarPath);
  if (await treeDigest(previewRoot) !== previewTreeDigest) {
    throw new Error('unreleased preview changed while it was being packaged');
  }
  const tarDigest = await fileDigest(tarPath);
  const receipt = {
    schema_version: PREVIEW_RECEIPT_SCHEMA,
    evidence_class: 'unreleased_preview',
    build: {
      commit_sha: commit,
      tree_sha: tree,
    },
    pull_request: pullRequest,
    docset: {
      id: PREVIEW_DOCSET,
      availability: PREVIEW_AVAILABILITY,
      release_coordinate: PREVIEW_RELEASE_COORDINATE,
      release_coordinate_status: PREVIEW_RELEASE_COORDINATE_STATUS,
      base: PREVIEW_BASE,
    },
    build_environment: {
      node_version: nodeVersion,
      package_lock_sha256: await fileDigest(packageLockPath),
    },
    artifacts: {
      preview_tree_sha256: previewTreeDigest,
      preview_tar: {
        name: `${stem}.tar.gz`,
        sha256: tarDigest,
      },
      inventory: {
        name: `${stem}.inventory.json`,
        sha256: inventoryDigest,
      },
    },
  };
  await writeFile(
    receiptPath,
    `${JSON.stringify(receipt, null, 2)}\n`,
    { mode: 0o644 },
  );
  return {
    inventory,
    inventory_path: inventoryPath,
    receipt,
    receipt_path: receiptPath,
    tar_path: tarPath,
  };
}

async function gitValue(repoRoot, ...args) {
  const { stdout } = await execFileAsync('git', args, {
    cwd: repoRoot,
    encoding: 'utf8',
    env: { ...process.env, GIT_NO_LAZY_FETCH: '1' },
  });
  return stdout.trim();
}

async function main() {
  const docsRoot = process.cwd();
  const repoRoot = resolve(docsRoot, '../..');
  const buildCommit = process.env.DOCS_BUILD_COMMIT || await gitValue(repoRoot, 'rev-parse', 'HEAD');
  const buildTree = await gitValue(repoRoot, 'rev-parse', `${buildCommit}^{tree}`);
  const result = await packageUnreleasedPreview({
    docsRoot,
    buildCommit,
    buildTree,
    eventName: process.env.GITHUB_EVENT_NAME || '',
    pullRequestHead: process.env.DOCS_PR_HEAD_SHA || '',
    pullRequestBase: process.env.DOCS_PR_BASE_SHA || '',
  });
  console.log(
    `Packaged deterministic unreleased documentation preview: ${result.receipt_path}`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
