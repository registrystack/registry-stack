import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { cargoRuntimeEnvironment } from './run-node-tests.mjs';

test('macOS restores the Cargo runtime carrier on the child loader path', () => {
  assert.deepEqual(
    cargoRuntimeEnvironment(
      {
        REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: '/cargo/fips',
        DYLD_LIBRARY_PATH: '/caller/runtime',
      },
      'darwin',
    ),
    {
      REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: '/cargo/fips',
      DYLD_LIBRARY_PATH: '/cargo/fips:/caller/runtime',
    },
  );
});

test('other platforms leave the child environment unchanged', () => {
  const environment = { REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: '/cargo/fips' };
  assert.deepEqual(cargoRuntimeEnvironment(environment, 'linux'), environment);
});

test('the launcher restores the path after a protected macOS executable strips it', { skip: process.platform !== 'darwin' }, () => {
  const directory = mkdtempSync(join(tmpdir(), 'registry-node-tests-'));
  try {
    const expected = '/cargo/fips';
    const child = join(directory, 'loader-path.test.mjs');
    writeFileSync(
      child,
      "import assert from 'node:assert/strict'; import { test } from 'node:test'; test('loader path', () => assert.equal(process.env.DYLD_LIBRARY_PATH, process.env.EXPECTED_RUNTIME));\n",
    );
    const completed = spawnSync(
      '/usr/bin/env',
      [process.execPath, fileURLToPath(new URL('./run-node-tests.mjs', import.meta.url)), child],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          EXPECTED_RUNTIME: expected,
          REGISTRY_CARGO_RUNTIME_LIBRARY_PATH: expected,
          DYLD_LIBRARY_PATH: expected,
        },
      },
    );
    assert.equal(completed.status, 0, completed.stderr || completed.stdout);
  } finally {
    rmSync(directory, { recursive: true });
  }
});
