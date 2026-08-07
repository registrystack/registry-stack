import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { generateRegistryctlInstaller } from './generate-registryctl-installer.mjs';

const siteRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(siteRoot, '../..');

test('publishes the canonical Registryctl installer byte for byte for current docs', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registryctl-public-installer-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = resolve(repoRoot, 'crates/registryctl/install.sh');
  const destination = resolve(root, 'public/install.sh');

  await generateRegistryctlInstaller({ source, destination });

  assert.equal(await readFile(destination, 'utf8'), await readFile(source, 'utf8'));
  assert.notEqual((await stat(destination)).mode & 0o111, 0);
});

test('binds a release-docset installer to that exact version', async (t) => {
  const root = await mkdtemp(resolve(tmpdir(), 'registryctl-release-installer-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = resolve(root, 'install.sh');
  const destination = resolve(root, 'public/install.sh');
  await writeFile(source, '#!/usr/bin/env bash\ndefault_version="v0.16.3"\necho "$default_version"\n');

  await generateRegistryctlInstaller({ source, destination, docset: 'v0.17.0' });

  assert.equal(
    await readFile(destination, 'utf8'),
    '#!/usr/bin/env bash\ndefault_version="v0.17.0"\necho "$default_version"\n',
  );
  assert.notEqual((await stat(destination)).mode & 0o111, 0);
});

test('current and archived docs generation publish the stable installer URL', async () => {
  const packageJson = JSON.parse(await readFile(resolve(siteRoot, 'package.json'), 'utf8'));
  const generator = 'node scripts/generate-registryctl-installer.mjs';

  assert.match(packageJson.scripts.generate, new RegExp(generator.replaceAll('.', '\\.')));
  assert.match(packageJson.scripts['generate:archive'], new RegExp(generator.replaceAll('.', '\\.')));
});
