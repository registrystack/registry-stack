import { execFile, spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { applyArchiveSeo } from './apply-archive-seo.mjs';
import {
  archiveOutputDirectory,
  releaseRootOutputDirectory,
  validateArchiveOutputLocation,
} from './archive-bundle.mjs';
import { isCandidateSourceProduct, loadDocsets } from './docsets.mjs';

const execFileAsync = promisify(execFile);
export const currentSourceGeneratedArtifacts = Object.freeze([
  'docs/site/src/data/generated/project-authoring-journeys.json',
  'docs/site/src/data/generated/project-starters.json',
  'docs/site/src/data/generated/configuration-reference.json',
  'docs/site/src/data/generated/configuration-reference-coverage.json',
  'docs/site/public/generated/configuration-reference.v1.json',
  'docs/site/public/generated/configuration-reference-coverage.v1.json',
  'docs/site/src/data/generated/diagnostics/authoring.json',
  'docs/site/src/data/generated/diagnostics/fixture.json',
  'docs/site/src/data/generated/diagnostics/operator.json',
  'docs/site/public/generated/diagnostics/authoring.v1.json',
  'docs/site/public/generated/diagnostics/fixture.v1.json',
  'docs/site/public/generated/diagnostics/operator.v1.json',
]);

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
    .sort((left, right) => left.name.localeCompare(right.name))) {
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
    if (contents.subarray(4, 8).some((byte) => byte !== 0)) {
      const updated = Buffer.from(contents);
      updated.fill(0, 4, 8);
      await replaceFile(path, updated);
      normalized += 1;
    }
  }
  return { files, normalized };
}

async function git(command, args, cwd) {
  try {
    return await execFileAsync(command, args, {
      cwd,
      encoding: 'buffer',
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    const stderr = Buffer.isBuffer(error?.stderr)
      ? error.stderr.toString('utf8').trim()
      : String(error?.stderr ?? '').trim();
    throw new Error(`${command} ${args.join(' ')} failed: ${stderr || error.message}`);
  }
}

export async function stagePinnedGeneratedArtifacts(docset, {
  docsRoot = process.cwd(),
  executeGit = git,
} = {}) {
  const sourceProduct = docset.products?.['registry-stack'];
  const declaredSourceRef = sourceProduct?.ref;
  let sourceRef = declaredSourceRef;
  if (isCandidateSourceProduct(docset, sourceProduct)) {
    sourceRef = 'HEAD';
  } else if (typeof sourceRef !== 'string' || !/^[0-9a-f]{40}$/.test(sourceRef)) {
    throw new Error(
      `Archived docset "${docset.id}" must pin products.registry-stack.ref to a full commit or its exact candidate tag`,
    );
  }
  const repoRoot = resolve(docsRoot, '../..');
  const { stdout: listed } = await executeGit(
    'git',
    ['ls-tree', '-rz', '--name-only', sourceRef, '--', ...currentSourceGeneratedArtifacts],
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

  const snapshots = new Map();
  for (const repoRelative of currentSourceGeneratedArtifacts) {
    const local = resolve(repoRoot, repoRelative);
    if (relative(docsRoot, local).startsWith('..')) {
      throw new Error(`generated archive input resolves outside docs root: ${repoRelative}`);
    }
    snapshots.set(local, await readOptionalRegularFile(local));
  }

  const restore = async () => {
    for (const [local, contents] of snapshots) {
      if (contents === null) await rm(local, { force: true });
      else await replaceFile(local, contents);
    }
  };
  try {
    for (const repoRelative of currentSourceGeneratedArtifacts) {
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
  runCommand = run,
  applySeo = applyArchiveSeo,
  normalizePagefind = normalizePagefindGzipMetadata,
  stageGeneratedArtifacts = stagePinnedGeneratedArtifacts,
  indexable = false,
} = {}) {
  if (docset.status !== 'archived') {
    throw new Error(`Docset "${docset.id}" is not archived`);
  }

  const rootEnv = {
    ...process.env,
    DOCS_DOCSET: docset.id,
    DOCS_BASE: '/',
    DOCS_RELEASED_ARCHIVE: indexable ? 'true' : '',
    TZ: 'UTC',
    // Archives are immutable release files, so their bytes cannot depend on
    // mutable deployment analytics configuration.
    PUBLIC_UMAMI_WEBSITE_ID: '',
    PUBLIC_UMAMI_SCRIPT_SRC: '',
    PUBLIC_UMAMI_DOMAINS: '',
  };
  const versionEnv = {
    ...rootEnv,
    DOCS_BASE: docset.path,
    DOCS_RELEASED_ARCHIVE: '',
  };
  const versionOutDir = await validateArchiveOutputLocation(docsRoot, docset);
  const rootOutDir = releaseRootOutputDirectory(docsRoot, docset);
  await rm(rootOutDir, { recursive: true, force: true });
  await rm(versionOutDir, { recursive: true, force: true });
  // Current-source generators consume the checked-out registryctl contracts
  // and label their output as unreleased. Release archives instead stage those
  // generated artifacts from the docset's pinned source ref and refresh only
  // inputs whose generators honor DOCS_DOCSET. Released archives are built at
  // the canonical root so Pages can promote their bytes without rewriting
  // links or canonical metadata.
  const restoreGeneratedArtifacts = await stageGeneratedArtifacts(docset, { docsRoot });
  try {
    await runCommand('npm', ['run', 'generate:archive'], rootEnv);
    await runCommand('npx', ['astro', 'check'], rootEnv);
    await runCommand(
      'npx',
      ['astro', 'build', '--outDir', rootOutDir],
      rootEnv,
    );
    await runCommand(
      'npx',
      ['astro', 'build', '--outDir', archiveOutputDirectory(docsRoot, docset)],
      versionEnv,
    );
    await normalizePagefind(rootOutDir);
    await normalizePagefind(versionOutDir);
    await applySeo(rootOutDir, { indexable });
    await applySeo(versionOutDir, { indexable: false });
  } finally {
    await restoreGeneratedArtifacts();
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
