import { spawn } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { applyArchiveSeo } from './apply-archive-seo.mjs';
import {
  archiveIdentity,
  computeArchiveInputDigest,
  pruneArchiveCache,
  restoreArchive,
  storeArchive,
  validateArchiveOutputLocation,
  validateLinkIndexLocation,
} from './archive-cache.mjs';
import { createArchiveLinkIndex, writeArchiveLinkIndex } from './check-built-links.mjs';
import { loadDocsets } from './docsets.mjs';

async function run(command, args, env, cwd = process.cwd()) {
  await new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd,
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

export async function buildDocsetArchive(
  docset,
  {
    docsRoot = process.cwd(),
    commandRunner = run,
    archiveSeo = applyArchiveSeo,
  } = {},
) {
  if (docset.status !== 'archived') {
    throw new Error(`Docset "${docset.id}" is not archived`);
  }

  const env = { ...process.env, DOCS_DOCSET: docset.id, DOCS_BASE: docset.path };
  const outDir = await validateArchiveOutputLocation(docsRoot, docset);
  await rm(outDir, { recursive: true, force: true });
  await commandRunner('npm', ['run', 'generate'], env, docsRoot);
  await commandRunner('npx', ['astro', 'check'], env, docsRoot);
  await commandRunner('npx', ['astro', 'build', '--outDir', outDir], env, docsRoot);
  await archiveSeo(outDir);
  console.log(`Built archived docset ${docset.id} at ${outDir}.`);
}

export async function buildArchivedDocsets({
  docsRoot = process.cwd(),
  dataDir = resolve(docsRoot, 'src/data'),
  cacheRoot = resolve(docsRoot, '.archive-build-cache'),
  docsets = null,
  mode = 'full',
  inputDigest = null,
  commandRunner = run,
  archiveBuilder = buildDocsetArchive,
} = {}) {
  if (!['incremental', 'full'].includes(mode)) {
    throw new Error(`archive build mode must be incremental or full, got ${mode}`);
  }
  const manifest = docsets ?? (await loadDocsets({ dataDir }));
  const archived = manifest.docsets.filter((docset) => docset.status === 'archived');
  const archiveInputDigest =
    inputDigest ?? (await computeArchiveInputDigest({ docsRoot }));
  const identities = archived.map((docset) =>
    archiveIdentity({ docset, manifest, inputDigest: archiveInputDigest }),
  );
  const stats = { mode, built: [], restored: [] };

  // Indexes are build-local. Cache entries carry their own copy and restore it
  // only after their metadata and output tree have been validated.
  await rm(await validateLinkIndexLocation(docsRoot), {
    recursive: true,
    force: true,
  });
  if (mode === 'incremental') await pruneArchiveCache(cacheRoot, identities);

  for (let index = 0; index < archived.length; index += 1) {
    const docset = archived[index];
    const identity = identities[index];
    if (mode === 'incremental') {
      const cached = await restoreArchive({ docsRoot, cacheRoot, docset, identity });
      if (cached.restored) {
        stats.restored.push(docset.id);
        console.log(`Restored archived docset ${docset.id} from ${identity.cache_key}.`);
        continue;
      }
      console.log(`Archive cache miss for ${docset.id}: ${cached.reason}.`);
    }

    await archiveBuilder(docset, { docsRoot, commandRunner });
    const linkIndex = await createArchiveLinkIndex({
      docsRoot,
      docset,
      cacheKey: identity.cache_key,
    });
    await writeArchiveLinkIndex({ docsRoot, docset, index: linkIndex });
    if (mode === 'incremental') {
      await storeArchive({ docsRoot, cacheRoot, docset, identity, linkIndex });
    }
    stats.built.push(docset.id);
  }

  if (archived.length === 0) console.log('No archived docsets to build.');

  // Return every generated current-doc surface to HEAD. Archive cache entries
  // never supply the current docset.
  await commandRunner(
    'npm',
    ['run', 'generate'],
    { ...process.env, DOCS_DOCSET: manifest.current, DOCS_BASE: '/' },
    docsRoot,
  );
  return stats;
}

export function parseArgs(args, env = process.env) {
  let mode = null;
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--mode' && args[index + 1]) {
      mode = args[index + 1];
      index += 1;
      continue;
    }
    throw new Error('usage: node scripts/build-archives.mjs [--mode incremental|full]');
  }
  const selectedMode = mode ?? env.ARCHIVE_MODE ?? 'full';
  if (!['incremental', 'full'].includes(selectedMode)) {
    throw new Error(`ARCHIVE_MODE must be incremental or full, got ${selectedMode}`);
  }
  return { mode: selectedMode };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    await buildArchivedDocsets(parseArgs(process.argv.slice(2)));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
