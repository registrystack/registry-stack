import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const docsPackage = JSON.parse(readFileSync(resolve(here, '../package.json'), 'utf8'));

test('direct dependency updates remain installable with tar and yaml overrides', () => {
  const fixture = mkdtempSync(join(tmpdir(), 'registry-docs-overrides-'));
  try {
    for (const [name, version] of [['tar', '7.5.22'], ['yaml', '2.9.1']]) {
      const packageDir = join(fixture, name);
      mkdirSync(packageDir);
      writeFileSync(join(packageDir, 'package.json'), JSON.stringify({ name, version }));
    }
    writeFileSync(join(fixture, 'package.json'), JSON.stringify({
      name: 'registry-docs-overrides-test',
      version: '1.0.0',
      private: true,
      devDependencies: {
        tar: 'file:./tar',
        yaml: 'file:./yaml',
      },
      overrides: {
        tar: docsPackage.overrides.tar,
        yaml: docsPackage.overrides.yaml,
      },
    }));

    const result = spawnSync('npm', [
      'install', '--package-lock-only', '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
    ], { cwd: fixture, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
