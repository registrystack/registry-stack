import { spawn } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyArchiveSeo } from './apply-archive-seo.mjs';
import { loadDocsets } from './docsets.mjs';

function outDirForDocset(docset) {
  return `dist${docset.path.replace(/\/$/, '')}`;
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

export async function buildDocsetArchive(docset) {
  if (docset.status !== 'archived') {
    throw new Error(`Docset "${docset.id}" is not archived`);
  }

  const env = { ...process.env, DOCS_DOCSET: docset.id, DOCS_BASE: docset.path };
  const outDir = outDirForDocset(docset);
  await rm(outDir, { recursive: true, force: true });
  await run('npm', ['run', 'generate'], env);
  await run('npx', ['astro', 'check'], env);
  await run('npx', ['astro', 'build', '--outDir', outDir], env);
  await applyArchiveSeo(outDir);
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
