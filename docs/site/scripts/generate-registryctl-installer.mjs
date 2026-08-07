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
  docset = process.env.DOCS_DOCSET,
} = {}) {
  let contents = await readFile(source, 'utf8');
  if (!contents.startsWith('#!/usr/bin/env bash')) {
    throw new Error(`registryctl installer has an unexpected interpreter: ${source}`);
  }
  if (/^v\d+\.\d+\.\d+$/.test(docset ?? '')) {
    const versionPattern = /^default_version="v\d+\.\d+\.\d+"$/gm;
    const matches = contents.match(versionPattern) ?? [];
    if (matches.length !== 1) {
      throw new Error(`registryctl installer must declare one default_version: ${source}`);
    }
    contents = contents.replace(versionPattern, `default_version="${docset}"`);
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
