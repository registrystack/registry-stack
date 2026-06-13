import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { getDocset, loadDocsets, selectedDocsetId } from './docsets.mjs';

const dataDir = resolve(process.cwd(), 'src/data');
const docsets = await loadDocsets({ dataDir });
const docset = getDocset(docsets, selectedDocsetId(docsets));

if (docset.id === docsets.current) {
  console.error('Refusing to build the current docset as an archive. Set DOCS_DOCSET to an archived docset id.');
  process.exit(1);
}

const base = docset.path;
const outDir = `dist${base.replace(/\/$/, '')}`;
const env = { ...process.env, DOCS_DOCSET: docset.id, DOCS_BASE: base };

async function run(command, args) {
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

await run('npm', ['run', 'generate']);
await run('npm', ['run', 'redoc']);
await run('npx', ['astro', 'check']);
await run('npx', ['astro', 'build', '--outDir', outDir]);

console.log(`Built archived docset ${docset.id} at ${outDir}.`);
