// Focused tests for how the docs checks locate the Vale binary.
// Run with `npm test` (node --test).

import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { resolveVale } from './vale-binary.mjs';

async function fakePackage(version) {
  const packageDir = await mkdtemp(join(tmpdir(), 'vale-package-'));
  await writeFile(join(packageDir, 'package.json'), JSON.stringify({ name: '@vvago/vale', version }));
  return packageDir;
}

async function fakeVale(printedVersion) {
  const dir = await mkdtemp(join(tmpdir(), 'vale-bin-'));
  const bin = join(dir, 'vale');
  await writeFile(bin, `#!/bin/sh\necho "vale version ${printedVersion}"\n`);
  await chmod(bin, 0o755);
  return bin;
}

test('uses VALE_BIN when it reports the version the package pins', async () => {
  const packageDir = await fakePackage('3.24.0');
  const bin = await fakeVale('3.24.0');

  assert.equal(await resolveVale({ packageDir, env: { VALE_BIN: bin } }), bin);
});

test('compares VALE_BIN against the package version without its prerelease suffix', async () => {
  const packageDir = await fakePackage('3.24.0-1');
  const bin = await fakeVale('3.24.0');

  assert.equal(await resolveVale({ packageDir, env: { VALE_BIN: bin } }), bin);
});

test('refuses a VALE_BIN that reports a different version, naming both', async () => {
  const packageDir = await fakePackage('3.24.0');
  const bin = await fakeVale('3.17.1');

  await assert.rejects(
    resolveVale({ packageDir, env: { VALE_BIN: bin } }),
    (error) => {
      assert.match(error.message, /3\.17\.1/);
      assert.match(error.message, /3\.24\.0/);
      assert.match(error.message, /VALE_BIN/);
      return true;
    },
  );
});

test('refuses a VALE_BIN that cannot run', async () => {
  const packageDir = await fakePackage('3.24.0');
  const missing = join(packageDir, 'no-such-vale');

  await assert.rejects(
    resolveVale({ packageDir, env: { VALE_BIN: missing } }),
    /VALE_BIN/,
  );
});

test('without VALE_BIN, uses the package binary when it is already installed', async () => {
  const packageDir = await fakePackage('3.24.0');
  const nativeBin = join(packageDir, 'native', process.platform === 'win32' ? 'vale.exe' : 'vale');
  await mkdir(join(packageDir, 'native'));
  await writeFile(nativeBin, '');

  assert.equal(await resolveVale({ packageDir, env: {} }), nativeBin);
});
