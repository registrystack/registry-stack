import { execFile, spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, mkdir, mkdtemp, open, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  constants as zlibConstants,
  crc32,
  deflateRawSync,
  gunzipSync,
} from 'node:zlib';
import { applyArchiveSeo } from './apply-archive-seo.mjs';
import { checkBuiltAnalytics } from './check-built-analytics.mjs';
import {
  archiveOutputDirectory,
  releaseRootOutputDirectory,
  validateArchiveOutputLocation,
} from './archive-bundle.mjs';
import { isCandidateSourceProduct, loadDocsets } from './docsets.mjs';

const execFileAsync = promisify(execFile);
const archiveExecutionEnvironmentKeys = Object.freeze([
  'COMSPEC',
  'ComSpec',
  'Path',
  'PATH',
  'PATHEXT',
  'SYSTEMROOT',
  'SystemRoot',
  'TEMP',
  'TMP',
  'TMPDIR',
  // Transport-only settings let controlled builders reach pinned Git objects
  // through their required proxy or trust store without admitting unrelated
  // hosted-runner metadata into archive generation.
  'ALL_PROXY',
  'CURL_CA_BUNDLE',
  'GIT_SSL_CAINFO',
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'NODE_EXTRA_CA_CERTS',
  'NO_PROXY',
  'SSL_CERT_DIR',
  'SSL_CERT_FILE',
  'all_proxy',
  'https_proxy',
  'http_proxy',
  'no_proxy',
]);
// Artifacts a current-source generator writes from the checked-out tree, which
// an archive must instead take from its docset's pinned source ref. A directory
// entry stages every regular file below it. That keeps command
// additions covered without maintaining a second manifest of generated pages.
export const currentSourceGeneratedArtifacts = Object.freeze([
  'docs/site/src/content/docs/reference/cli',
  'docs/site/src/data/generated/cli-reference.json',
]);

function compareEntryNames(left, right) {
  if (left.name < right.name) return -1;
  if (left.name > right.name) return 1;
  return 0;
}

async function regularFilesBelow(path) {
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  if (info.isSymbolicLink()) {
    throw new Error(`generated archive input must not be a symlink: ${path}`);
  }
  if (info.isFile()) return [path];
  if (!info.isDirectory()) {
    throw new Error(`generated archive input must be a regular file or directory: ${path}`);
  }

  const files = [];
  for (const entry of (await readdir(path, { withFileTypes: true })).sort(compareEntryNames)) {
    files.push(...await regularFilesBelow(resolve(path, entry.name)));
  }
  return files;
}

function archiveBuildEnvironment(inheritedEnvironment, docset, {
  base,
  homeDirectory,
  indexable,
}) {
  const environment = {};
  for (const key of archiveExecutionEnvironmentKeys) {
    if (inheritedEnvironment[key] !== undefined) {
      environment[key] = inheritedEnvironment[key];
    }
  }
  return {
    ...environment,
    ASTRO_TELEMETRY_DISABLED: '1',
    CI: 'true',
    DOCS_BASE: base,
    DOCS_DOCSET: docset.id,
    DOCS_RELEASED_ARCHIVE: indexable ? 'true' : '',
    GIT_ATTR_NOSYSTEM: '1',
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_CONFIG_KEY_0: 'core.autocrlf',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_VALUE_0: 'false',
    HOME: homeDirectory,
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    NO_COLOR: '1',
    PUBLIC_UMAMI_DOMAINS: '',
    PUBLIC_UMAMI_SCRIPT_SRC: '',
    PUBLIC_UMAMI_WEBSITE_ID: '',
    // Pagefind assembles its content-hashed index through Rayon. Parallel
    // scheduling can change the index chunk bytes even when every page is
    // identical, so immutable release archives must build it on one worker.
    RAYON_NUM_THREADS: '1',
    SOURCE_DATE_EPOCH: '0',
    TZ: 'UTC',
    USERPROFILE: homeDirectory,
    XDG_CACHE_HOME: resolve(homeDirectory, '.cache'),
    XDG_CONFIG_HOME: resolve(homeDirectory, '.config'),
  };
}

async function run(command, args, env) {
  await new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      env,
      shell: process.platform === 'win32',
      stdio: 'inherit',
    });
    child.on('exit', (code) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`${command} ${args.join(' ')} exited ${code}`));
    });
    child.on('error', rejectRun);
  });
}

export async function readOptionalRegularFile(path) {
  let file;
  try {
    file = await open(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    const info = await file.stat();
    if (!info.isFile()) {
      throw new Error(`generated archive input must be a regular file: ${path}`);
    }
    return await file.readFile();
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  } finally {
    await file?.close();
  }
}

async function replaceFile(path, contents) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.archive.tmp`;
  try {
    await writeFile(temporary, contents, { flag: 'wx' });
    await rename(temporary, path);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

const deterministicGzipHeader = Buffer.from([
  0x1f, 0x8b, 0x08, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x02, 0xff,
]);

function deterministicGzip(contents) {
  // zlib records the host OS in its gzip header, so gzipSync emits different
  // bytes on macOS and Linux. Build the framing explicitly with no optional
  // fields, zero mtime, maximum-compression XFL, and the unknown-OS marker.
  const compressed = deflateRawSync(contents, {
    level: 9,
    memLevel: 8,
    strategy: zlibConstants.Z_DEFAULT_STRATEGY,
    windowBits: 15,
  });
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(contents), 0);
  trailer.writeUInt32LE(contents.length >>> 0, 4);
  return Buffer.concat([deterministicGzipHeader, compressed, trailer]);
}

export async function normalizePagefindGzipMetadata(outputRoot) {
  const pagefindRoot = resolve(outputRoot, 'pagefind');
  let pagefindInfo;
  try {
    pagefindInfo = await lstat(pagefindRoot);
  } catch (error) {
    if (error?.code === 'ENOENT') return { files: 0, normalized: 0 };
    throw error;
  }
  if (pagefindInfo.isSymbolicLink() || !pagefindInfo.isDirectory()) {
    throw new Error(`generated Pagefind output must be a real directory: ${pagefindRoot}`);
  }
  const entries = await readdir(pagefindRoot, { withFileTypes: true });

  let files = 0;
  let normalized = 0;
  for (const entry of entries
    .filter(({ name }) => /^wasm\.[^.]+\.pagefind$/.test(name))
    .sort(compareEntryNames)) {
    const path = resolve(pagefindRoot, entry.name);
    if (!entry.isFile()) {
      throw new Error(`generated Pagefind WebAssembly must be a regular file: ${path}`);
    }
    const contents = await readOptionalRegularFile(path);
    if (
      contents === null ||
      contents.length < 10 ||
      contents[0] !== 0x1f ||
      contents[1] !== 0x8b ||
      contents[2] !== 0x08
    ) {
      throw new Error(`generated Pagefind WebAssembly must use gzip framing: ${path}`);
    }
    files += 1;
    let uncompressed;
    try {
      uncompressed = gunzipSync(contents);
    } catch (error) {
      throw new Error(`generated Pagefind WebAssembly must be valid gzip: ${path}`, {
        cause: error,
      });
    }
    const updated = deterministicGzip(uncompressed);
    if (!contents.equals(updated)) {
      await replaceFile(path, updated);
      normalized += 1;
    }
  }
  return { files, normalized };
}

// `stagePinnedGeneratedArtifacts` reads pinned archive inputs from history that
// a shallow or partial checkout may still need to fetch on demand, so a single
// dropped connection here fails the whole docs gate. Retry a bounded number of
// times with backoff, but only for a failure that looks transient: a real
// content problem (missing ref, bad path) must still fail on the first try.
const gitRetryAttempts = 3;
const gitRetryBaseDelayMs = 200;

const transientGitErrorCodes = new Set([
  'EAGAIN',
  'ECONNREFUSED',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EPIPE',
  'ETIMEDOUT',
]);

const transientGitStderrPattern = new RegExp(
  [
    'could not resolve host',
    'could not read from remote repository',
    "couldn't connect to server",
    'connection (?:reset|refused|timed out)',
    'the remote end hung up unexpectedly',
    'early eof',
    'rpc failed',
    'unable to access',
    "unable to create '.*index\\.lock'",
    'operation timed out',
    'temporary failure in name resolution',
    'transfer closed with .* bytes remaining',
  ].join('|'),
  'i',
);

function isTransientGitFailure(error, stderr) {
  if (typeof error?.code === 'string' && transientGitErrorCodes.has(error.code)) return true;
  return transientGitStderrPattern.test(stderr);
}

function waitBeforeGitRetry(delayMs) {
  return new Promise((resolveWait) => setTimeout(resolveWait, delayMs));
}

export async function git(command, args, cwd, {
  execFileImpl = execFileAsync,
  wait = waitBeforeGitRetry,
  attempts = gitRetryAttempts,
} = {}) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await execFileImpl(command, args, {
        cwd,
        encoding: 'buffer',
        maxBuffer: 16 * 1024 * 1024,
      });
    } catch (error) {
      const stderr = Buffer.isBuffer(error?.stderr)
        ? error.stderr.toString('utf8').trim()
        : String(error?.stderr ?? '').trim();
      const failure = new Error(`${command} ${args.join(' ')} failed: ${stderr || error.message}`);
      if (attempt === attempts || !isTransientGitFailure(error, stderr)) {
        throw failure;
      }
      await wait(gitRetryBaseDelayMs * 2 ** (attempt - 1));
    }
  }
}

async function resolveLocalCommit(ref, cwd) {
  try {
    const { stdout } = await execFileAsync(
      'git',
      ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`],
      { cwd, encoding: 'utf8', maxBuffer: 1024 * 1024 },
    );
    const commit = stdout.trim();
    if (!/^[0-9a-f]{40}$/.test(commit)) {
      throw new Error(`git resolved ${ref} to an invalid commit: ${commit}`);
    }
    return commit;
  } catch (error) {
    if (error?.code === 1) return null;
    const stderr = String(error?.stderr ?? '').trim();
    throw new Error(`git could not resolve ${ref}: ${stderr || error.message}`);
  }
}

export async function stagePinnedGeneratedArtifacts(docset, {
  docsRoot = process.cwd(),
  executeGit = git,
  resolveCommit = resolveLocalCommit,
  allowUnpublishedCandidate = false,
  artifacts = currentSourceGeneratedArtifacts,
} = {}) {
  const sourceProduct = docset.products?.['registry-stack'];
  const declaredSourceRef = sourceProduct?.ref;
  const repoRoot = resolve(docsRoot, '../..');
  let sourceRef = declaredSourceRef;
  if (isCandidateSourceProduct(docset, sourceProduct)) {
    // An archive that has already been tagged must remain bound to that tag.
    // Before publication the exact candidate tag does not exist yet, so the
    // release-candidate entrypoint intentionally stages the checked-out source.
    const taggedCommit = await resolveCommit(declaredSourceRef, repoRoot);
    if (taggedCommit === null && !allowUnpublishedCandidate) {
      throw new Error(
        `Archived candidate docset "${docset.id}" must resolve its exact source tag`,
      );
    }
    sourceRef = taggedCommit ?? 'HEAD';
  } else if (typeof sourceRef !== 'string' || !/^[0-9a-f]{40}$/.test(sourceRef)) {
    throw new Error(
      `Archived docset "${docset.id}" must pin products.registry-stack.ref to a full commit or its exact candidate tag`,
    );
  }
  // `git ls-tree` with no pathspec lists the whole tree, so an empty artifact
  // list must short-circuit rather than fall through. The ref check above still
  // runs: an archived docset has to pin its source ref whether or not there is
  // anything to stage from it.
  if (artifacts.length === 0) {
    return async () => {};
  }
  const currentPaths = new Set();
  for (const repoRelative of artifacts) {
    const local = resolve(repoRoot, repoRelative);
    if (relative(docsRoot, local).startsWith('..')) {
      throw new Error(`generated archive input resolves outside docs root: ${repoRelative}`);
    }
    for (const file of await regularFilesBelow(local)) {
      currentPaths.add(relative(repoRoot, file).split(sep).join('/'));
    }
  }
  const { stdout: listed } = await executeGit(
    'git',
    ['ls-tree', '-rz', '-r', '--name-only', sourceRef, '--', ...artifacts],
    repoRoot,
  );
  const pinnedPaths = new Set(
    listed
      .toString('utf8')
      .split('\0')
      .filter(Boolean),
  );
  const pinnedContents = new Map();
  for (const path of pinnedPaths) {
    const { stdout } = await executeGit('git', ['show', `${sourceRef}:${path}`], repoRoot);
    pinnedContents.set(path, stdout);
  }

  const affectedPaths = [...new Set([...pinnedPaths, ...currentPaths])].sort();
  const snapshots = new Map();
  for (const repoRelative of affectedPaths) {
    const local = resolve(repoRoot, repoRelative);
    snapshots.set(local, await readOptionalRegularFile(local));
  }

  const restore = async () => {
    for (const [local, contents] of snapshots) {
      if (contents === null) await rm(local, { force: true });
      else await replaceFile(local, contents);
    }
  };
  try {
    for (const repoRelative of affectedPaths) {
      const local = resolve(repoRoot, repoRelative);
      const contents = pinnedContents.get(repoRelative);
      if (contents === undefined) await rm(local, { force: true });
      else await replaceFile(local, contents);
    }
  } catch (error) {
    await restore();
    throw error;
  }
  return restore;
}

export async function buildDocsetArchive(docset, {
  docsRoot = process.cwd(),
  environment = process.env,
  runCommand = run,
  applySeo = applyArchiveSeo,
  verifyAnalytics = checkBuiltAnalytics,
  normalizePagefind = normalizePagefindGzipMetadata,
  stageGeneratedArtifacts = stagePinnedGeneratedArtifacts,
  allowUnpublishedCandidate = false,
  indexable = false,
} = {}) {
  if (docset.status !== 'archived') {
    throw new Error(`Docset "${docset.id}" is not archived`);
  }

  const versionOutDir = await validateArchiveOutputLocation(docsRoot, docset);
  const rootOutDir = releaseRootOutputDirectory(docsRoot, docset);
  await rm(rootOutDir, { recursive: true, force: true });
  await rm(versionOutDir, { recursive: true, force: true });
  const archiveHome = await mkdtemp(resolve(tmpdir(), 'registry-docs-archive-home-'));
  // Archives are immutable release files. Pass only the operating-system
  // variables needed to execute local tools, then bind every build input that
  // may affect their bytes. Hosted-runner metadata and mutable deployment
  // configuration must not enter the archive build.
  const rootEnv = archiveBuildEnvironment(environment, docset, {
    base: '/',
    homeDirectory: archiveHome,
    indexable,
  });
  const versionEnv = archiveBuildEnvironment(environment, docset, {
    base: docset.path,
    homeDirectory: archiveHome,
    indexable: false,
  });
  // Current-source generators read the checked-out tree and label their output
  // as unreleased. Release archives instead stage those generated artifacts
  // from the docset's pinned source ref and refresh only inputs whose
  // generators honor DOCS_DOCSET. Released archives are built at the canonical
  // root so Pages can promote their bytes without rewriting links or canonical
  // metadata.
  let restoreGeneratedArtifacts = async () => {};
  try {
    restoreGeneratedArtifacts = await stageGeneratedArtifacts(docset, {
      docsRoot,
      allowUnpublishedCandidate,
    });
    await runCommand('npm', ['run', 'generate:archive'], rootEnv);
    await runCommand('npx', ['astro', 'check'], rootEnv);
    await runCommand(
      'npx',
      ['astro', 'build', '--outDir', rootOutDir],
      rootEnv,
    );
    if (indexable) {
      // Pagefind's directory walk follows filesystem enumeration order, which
      // changes document numbering and content-hashed index chunks across
      // builders. Preserve Starlight's search UI and page markers, then replace
      // only its generated index with the canonical URL-sorted builder.
      await rm(resolve(rootOutDir, 'pagefind'), { recursive: true, force: true });
      await runCommand(
        'node',
        ['scripts/build-production-search.mjs', '--dist-root', rootOutDir],
        rootEnv,
      );
    }
    await runCommand(
      'npx',
      ['astro', 'build', '--outDir', archiveOutputDirectory(docsRoot, docset)],
      versionEnv,
    );
    await normalizePagefind(rootOutDir);
    await normalizePagefind(versionOutDir);
    await applySeo(rootOutDir, { indexable });
    await applySeo(versionOutDir, { indexable: false });
    await verifyAnalytics(rootOutDir, { enabled: indexable });
    await verifyAnalytics(versionOutDir, { enabled: false });
  } finally {
    try {
      await restoreGeneratedArtifacts();
    } finally {
      await rm(archiveHome, { recursive: true, force: true });
    }
  }
  console.log(
    `Built released docset ${docset.id} at ${rootOutDir} and ${versionOutDir}.`,
  );
}

export async function buildArchivedDocsets({
  dataDir = resolve(process.cwd(), 'src/data'),
  docsets = null,
} = {}) {
  const manifest = docsets ?? await loadDocsets({ dataDir });
  const archived = manifest.docsets.filter((docset) => docset.status === 'archived');
  if (archived.length === 0) {
    console.log('No archived docsets to build.');
    return;
  }

  for (const docset of archived) {
    await buildDocsetArchive(docset, {
      indexable: docset.id === manifest.released,
    });
  }

  // Return generated files to the current docset so local worktrees stay sane.
  await run('npm', ['run', 'generate'], { ...process.env, DOCS_DOCSET: manifest.current, DOCS_BASE: '/' });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await buildArchivedDocsets();
}
