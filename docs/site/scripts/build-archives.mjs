import { execFile, spawn } from 'node:child_process';
import { lstat, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { applyArchiveSeo } from './apply-archive-seo.mjs';
import {
  archiveOutputDirectory,
  validateArchiveOutputLocation,
} from './archive-bundle.mjs';
import { loadDocsets } from './docsets.mjs';

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
  'docs/site/src/data/generated/standard-journeys.json',
  'docs/site/public/generated/standard-journeys.json',
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

async function readOptionalRegularFile(path) {
  try {
    const info = await lstat(path);
    if (!info.isFile()) {
      throw new Error(`generated archive input must be a regular file: ${path}`);
    }
    return await readFile(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
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
  const sourceRef = docset.products?.['registry-stack']?.ref;
  if (typeof sourceRef !== 'string' || !/^[0-9a-f]{40}$/.test(sourceRef)) {
    throw new Error(
      `Archived docset "${docset.id}" must pin products.registry-stack.ref to a full commit`,
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
  stageGeneratedArtifacts = stagePinnedGeneratedArtifacts,
} = {}) {
  if (docset.status !== 'archived') {
    throw new Error(`Docset "${docset.id}" is not archived`);
  }

  const env = {
    ...process.env,
    DOCS_DOCSET: docset.id,
    DOCS_BASE: docset.path,
    TZ: 'UTC',
    // Archives are immutable release files, so their bytes cannot depend on
    // mutable deployment analytics configuration.
    PUBLIC_UMAMI_WEBSITE_ID: '',
    PUBLIC_UMAMI_SCRIPT_SRC: '',
    PUBLIC_UMAMI_DOMAINS: '',
  };
  const outDir = await validateArchiveOutputLocation(docsRoot, docset);
  await rm(outDir, { recursive: true, force: true });
  // Current-source generators consume the checked-out registryctl contracts
  // and label their output as unreleased. Release archives instead stage those
  // generated artifacts from the docset's pinned source ref and refresh only
  // inputs whose generators honor DOCS_DOCSET.
  const restoreGeneratedArtifacts = await stageGeneratedArtifacts(docset, { docsRoot });
  try {
    await runCommand('npm', ['run', 'generate:archive'], env);
    await runCommand('npx', ['astro', 'check'], env);
    await runCommand(
      'npx',
      ['astro', 'build', '--outDir', archiveOutputDirectory(docsRoot, docset)],
      env,
    );
    await applySeo(outDir);
  } finally {
    await restoreGeneratedArtifacts();
  }
  console.log(`Built archived docset ${docset.id} at ${outDir}.`);
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
    await buildDocsetArchive(docset);
  }

  // Return generated files to the current docset so local worktrees stay sane.
  await run('npm', ['run', 'generate'], { ...process.env, DOCS_DOCSET: manifest.current, DOCS_BASE: '/' });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await buildArchivedDocsets();
}
