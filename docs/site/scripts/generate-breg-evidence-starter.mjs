// Package reviewed teaching inputs. Service setup remains in bregctl/evidencectl.
import { mkdir, lstat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as tar from 'tar';

export const starterFiles = [
  'organization-selection.yaml',
  'named-starter/README.md',
  'named-starter/questions/record-named.yaml',
  'named-starter/derivations/record-named.rhai',
  'named-starter/fixtures/record-named.yaml',
  'default-starter/README.md',
  'default-starter/questions/record-active.yaml',
  'default-starter/derivations/record-active.rhai',
  'default-starter/fixtures/record-active.yaml',
  'default-starter/targets/local/settings.yaml',
  'registry/registry.yaml',
  'registry/clients.yaml',
  'registry/tests/journeys.yaml',
  'starter/README.md',
  'starter/questions/record-active.yaml',
  'starter/questions/record-status-pair.yaml',
  'starter/derivations/record-active.rhai',
  'starter/derivations/record-status-pair.rhai',
  'starter/fixtures/record-active.yaml',
  'starter/fixtures/record-status-pair.yaml',
  'starter/targets/local/settings.yaml',
].sort();

export async function packageStarter(source, output) {
  // Explicit inventory excludes credentials, local state, outputs and the
  // maintainer test driver even if they exist beside the teaching inputs.
  for (const file of starterFiles) {
    const info = await lstat(resolve(source, file));
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Starter input is not a plain file: ${file}`);
  }
  await mkdir(dirname(output), { recursive: true });
  await tar.create({
    cwd: source,
    file: output,
    gzip: { level: 9, mtime: 0 },
    mtime: new Date(0),
    portable: true,
    noDirRecurse: true,
    noPax: true,
    strict: true,
    filter(_path, info) { info.mode = (info.mode & ~0o7777) | 0o644; return true; },
  }, starterFiles);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  await packageStarter(resolve(site, '../../products/breg/evidence'), resolve(site, 'public/examples/breg-evidence-starter.tar.gz'));
}
