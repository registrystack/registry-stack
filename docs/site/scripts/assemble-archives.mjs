import { createWriteStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

import {
  createArchiveBundle,
  localArchiveBundlePath,
  restoreArchiveBundle,
} from './archive-bundle.mjs';
import { loadArchiveLock, validateArchiveLock } from './archive-lock.mjs';
import { buildDocsetArchive } from './build-archives.mjs';
import { loadDocsets } from './docsets.mjs';
import { publishedArchiveDocsets } from '../src/lib/docset-retention.mjs';

const defaultArchiveBaseUrl = 'https://docs.registrystack.org/_archive-bundles';
const defaultReleaseBaseUrl =
  'https://github.com/registrystack/registry-stack/releases/download';
const maximumBundleBytes = 256 * 1024 * 1024;

function trimTrailingSlash(value) {
  return value.replace(/\/+$/, '');
}

export function archiveBundleUrls(docset, {
  archiveBaseUrl = process.env.DOCS_ARCHIVE_BASE_URL || defaultArchiveBaseUrl,
  releaseBaseUrl = process.env.DOCS_RELEASE_BASE_URL || defaultReleaseBaseUrl,
} = {}) {
  return [
    `${trimTrailingSlash(releaseBaseUrl)}/${docset.id}/registry-docs-${docset.id}.tar.gz`,
    `${trimTrailingSlash(archiveBaseUrl)}/${docset.id}.tar.gz`,
  ];
}

async function downloadBundle(url, output, {
  fetchImpl = fetch,
  maximumBytes = maximumBundleBytes,
} = {}) {
  const response = await fetchImpl(url, {
    headers: { 'user-agent': 'registry-docs-archive-assembler/1' },
    redirect: 'follow',
  });
  if (response.status === 404) return false;
  if (!response.ok) {
    throw new Error(`archive bundle download ${url} returned HTTP ${response.status}`);
  }
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new Error(`archive bundle download ${url} exceeds ${maximumBytes} bytes`);
  }
  if (!response.body) {
    throw new Error(`archive bundle download ${url} returned no body`);
  }
  await mkdir(dirname(output), { recursive: true });
  let received = 0;
  const limit = new Transform({
    transform(chunk, _encoding, callback) {
      received += chunk.length;
      if (received > maximumBytes) {
        callback(new Error(`archive bundle download ${url} exceeds ${maximumBytes} bytes`));
      } else {
        callback(null, chunk);
      }
    },
  });
  await pipeline(Readable.fromWeb(response.body), limit, createWriteStream(output, { mode: 0o600 }));
  return true;
}

async function restoreDownloadedBundle({
  docsRoot,
  docset,
  lockEntry,
  urls,
  fetchImpl,
}) {
  const temporary = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-download-'));
  try {
    const bundlePath = resolve(temporary, `${docset.id}.tar.gz`);
    for (const [index, url] of urls.entries()) {
      if (!await downloadBundle(url, bundlePath, { fetchImpl })) continue;
      await restoreArchiveBundle({
        docsRoot,
        bundlePath,
        docset,
        expectedBundleSha256: lockEntry.bundle_sha256,
        expectedRootTreeSha256: lockEntry.root_tree_sha256,
        expectedTreeSha256: lockEntry.tree_sha256,
        expectedVersionTreeSha256: lockEntry.version_tree_sha256,
        // Release assets are canonical and do not need to be duplicated in
        // Pages. The fallback URL is republished so pre-contract releases stay
        // self-hosting.
        publishBundle: index > 0,
      });
      return url;
    }
    return null;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

// This gitignored cache is only ever written by an earlier `--bootstrap` run
// (see bootstrapArchive below). Matches only the outer bundle digest check in
// inspectArchiveBundle, not a metadata or tree-digest mismatch discovered after
// that check passes, which would instead indicate a genuinely broken bundle.
const localBundleDigestMismatchPattern =
  /^archive bundle .+ digest [0-9a-f]{64} does not match lock [0-9a-f]{64}$/;

async function restoreLocalBundle({ docsRoot, docset, lockEntry }) {
  const bundlePath = localArchiveBundlePath(docsRoot, docset);
  try {
    const info = await lstat(bundlePath);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error(`local archive bundle must be a regular file: ${bundlePath}`);
    }
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
  try {
    await restoreArchiveBundle({
      docsRoot,
      bundlePath,
      docset,
      expectedBundleSha256: lockEntry.bundle_sha256,
      expectedRootTreeSha256: lockEntry.root_tree_sha256,
      expectedTreeSha256: lockEntry.tree_sha256,
      expectedVersionTreeSha256: lockEntry.version_tree_sha256,
    });
  } catch (error) {
    if (!localBundleDigestMismatchPattern.test(error.message)) throw error;
    // A digest mismatch here means that bootstrap run's working tree no longer
    // matches the published release, not that the published archive was
    // tampered with. Ignore the stale entry and restore from the published
    // bundle instead.
    console.warn(
      `ignoring stale local archive bundle cache: ${error.message} (${bundlePath}); ` +
        'restoring from the published bundle instead. Delete this file to clear the warning.',
    );
    return false;
  }
  return true;
}

async function bootstrapArchive({
  docsRoot,
  docset,
  lockEntry,
  buildArchive,
}) {
  await buildArchive(docset, {
    docsRoot,
    // Bootstrap is the pre-publication verification path. Candidate archives
    // may therefore use the checked-out source until their exact tag exists;
    // buildDocsetArchive still resolves and prefers the tag once published.
    allowUnpublishedCandidate: true,
    // Candidate-era archives authenticate the canonical root separately from
    // the versioned tree. Build that root exactly as the release workflow does.
    indexable: !lockEntry.tree_sha256,
  });
  const bundlePath = localArchiveBundlePath(docsRoot, docset);
  const result = await createArchiveBundle({
    docsRoot,
    docset,
    bundlePath,
    // A historical lock entry authenticates the original single-tree bundle.
    // Do not let a canonical-root staging tree change its bundle shape.
    singleTree: Boolean(lockEntry.tree_sha256),
  });
  const matches = result.bundle_sha256 === lockEntry.bundle_sha256 &&
    (result.root_tree_sha256
      ? result.root_tree_sha256 === lockEntry.root_tree_sha256 &&
        result.version_tree_sha256 === lockEntry.version_tree_sha256
      : result.tree_sha256 === lockEntry.tree_sha256);
  if (!matches) {
    const expected = result.root_tree_sha256
      ? `bundle_sha256=${lockEntry.bundle_sha256} ` +
        `root_tree_sha256=${lockEntry.root_tree_sha256} ` +
        `version_tree_sha256=${lockEntry.version_tree_sha256}`
      : `bundle_sha256=${lockEntry.bundle_sha256} tree_sha256=${lockEntry.tree_sha256}`;
    const actual = result.root_tree_sha256
      ? `bundle_sha256=${result.bundle_sha256} ` +
        `root_tree_sha256=${result.root_tree_sha256} ` +
        `version_tree_sha256=${result.version_tree_sha256}`
      : `bundle_sha256=${result.bundle_sha256} tree_sha256=${result.tree_sha256}`;
    throw new Error(
      `bootstrapped archive ${docset.id} does not match its immutable lock entry\n` +
        `expected: ${expected}\nactual: ${actual}`,
    );
  }
  await restoreArchiveBundle({
    docsRoot,
    bundlePath,
    docset,
    expectedBundleSha256: lockEntry.bundle_sha256,
    expectedRootTreeSha256: lockEntry.root_tree_sha256,
    expectedTreeSha256: lockEntry.tree_sha256,
    expectedVersionTreeSha256: lockEntry.version_tree_sha256,
  });
}

async function restoreCurrentGeneratedData(docsRoot, currentDocsetId) {
  const { spawn } = await import('node:child_process');
  await new Promise((resolveRun, rejectRun) => {
    const child = spawn('npm', ['run', 'generate'], {
      cwd: docsRoot,
      env: { ...process.env, DOCS_DOCSET: currentDocsetId, DOCS_BASE: '/' },
      shell: process.platform === 'win32',
      stdio: 'inherit',
    });
    child.on('exit', (code) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`npm run generate exited ${code}`));
    });
    child.on('error', rejectRun);
  });
}

export async function assembleArchives({
  docsRoot = process.cwd(),
  bootstrap = false,
  excludeDocsetId = null,
  fetchImpl = fetch,
  buildArchive = buildDocsetArchive,
  restoreGeneratedData = restoreCurrentGeneratedData,
  urlResolver = archiveBundleUrls,
} = {}) {
  const docsets = await loadDocsets({ dataDir: resolve(docsRoot, 'src/data') });
  const lock = await loadArchiveLock({
    lockPath: resolve(docsRoot, 'src/data/archive-lock.yaml'),
  });
  const errors = validateArchiveLock(lock, docsets);
  if (errors.length > 0) throw new Error(errors.join('\n'));
  if (excludeDocsetId) {
    const excluded = docsets.docsets.find((docset) => docset.id === excludeDocsetId);
    if (!excluded || excluded.status !== 'archived') {
      throw new Error(
        `excluded docset must name a declared archived docset: ${excludeDocsetId}`,
      );
    }
  }

  let bootstrapped = 0;
  let restored = 0;
  const sources = {};
  const published = publishedArchiveDocsets(docsets, excludeDocsetId);
  const publishedIds = new Set(published.map((entry) => entry.id));
  const omitted = docsets.docsets
    .filter((entry) => entry.status === 'archived' && !publishedIds.has(entry.id))
    .map((entry) => entry.id);
  const archived = published.filter((entry) => entry.id !== excludeDocsetId);
  for (const docset of archived) {
    const lockEntry = lock.archives[docset.id];
    if (await restoreLocalBundle({ docsRoot, docset, lockEntry })) {
      restored += 1;
      sources[docset.id] = 'local';
      continue;
    }
    const source = await restoreDownloadedBundle({
      docsRoot,
      docset,
      lockEntry,
      urls: urlResolver(docset),
      fetchImpl,
    });
    if (source) {
      restored += 1;
      sources[docset.id] = source;
      continue;
    }
    if (!bootstrap) {
      throw new Error(
        `no immutable bundle is published for ${docset.id}; rerun with --bootstrap only in archive publication verification`,
      );
    }
    await bootstrapArchive({ docsRoot, docset, lockEntry, buildArchive });
    bootstrapped += 1;
    sources[docset.id] = 'bootstrap';
  }
  if (bootstrapped > 0) {
    await restoreGeneratedData(docsRoot, docsets.current);
  }
  return {
    bootstrapped,
    restored,
    skipped: excludeDocsetId ? [excludeDocsetId] : [],
    omitted,
    sources,
  };
}

export function parseArgs(args) {
  let bootstrap = false;
  let excludeDocsetId = null;
  while (args.length > 0) {
    const option = args.shift();
    if (option === '--bootstrap') bootstrap = true;
    else if (option === '--exclude-docset' && args[0]) {
      excludeDocsetId = args.shift();
    } else {
      throw new Error(
        'usage: assemble-archives.mjs [--bootstrap] [--exclude-docset <id>]',
      );
    }
  }
  return { bootstrap, excludeDocsetId };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const result = await assembleArchives(parseArgs(process.argv.slice(2)));
    console.log(
      `Assembled ${result.restored + result.bootstrapped} immutable archive(s): ` +
        `${result.restored} restored, ${result.bootstrapped} bootstrapped, ` +
        `${result.skipped.length} supplied separately, ` +
        `${result.omitted.length} outside the publication window.`,
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
