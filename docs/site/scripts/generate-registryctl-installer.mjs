import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const siteRoot = resolve(scriptDir, '..');
const repoRoot = resolve(siteRoot, '../..');
const canonicalInstaller = resolve(repoRoot, 'crates/registryctl/install.sh');
const publicInstaller = resolve(siteRoot, 'public/install.sh');

export async function generateRegistryctlInstaller({
  source = canonicalInstaller,
  destination = publicInstaller,
} = {}) {
  const contents = await readFile(source);
  if (!contents.toString('utf8', 0, 20).startsWith('#!/usr/bin/env bash')) {
    throw new Error(`registryctl installer has an unexpected interpreter: ${source}`);
  }

  await mkdir(dirname(destination), { recursive: true });
  const temporary = `${destination}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, contents, { flag: 'wx', mode: 0o755 });
    await rename(temporary, destination);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }

  return contents;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateRegistryctlInstaller();
  console.log('Generated public Registryctl installer -> public/install.sh');
}
