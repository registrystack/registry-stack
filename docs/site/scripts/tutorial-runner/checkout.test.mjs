import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readlink, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { copyCheckout } from './checkout.mjs';

test('a checkout copy holds the files a clone would, as they stand in the working tree', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'tutorial-checkout-test.')));
  try {
    const repo = join(root, 'repo');
    const git = (...args) => execFileSync('git', ['-C', repo, ...args], { stdio: 'pipe' });
    await mkdir(join(repo, 'products/example'), { recursive: true });
    execFileSync('git', ['init', '-q', repo]);
    await writeFile(join(repo, '.gitignore'), 'target/\n');
    await writeFile(join(repo, 'products/example/registry.yaml'), 'committed\n');
    await writeFile(join(repo, 'gone.txt'), 'deleted later\n');
    await symlink('products/example/registry.yaml', join(repo, 'link.yaml'));
    git('add', '.');
    git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-m', 'init');
    await writeFile(join(repo, 'products/example/registry.yaml'), 'edited in the working tree\n');
    await writeFile(join(repo, 'new.txt'), 'untracked\n');
    await mkdir(join(repo, 'target'));
    await writeFile(join(repo, 'target/build.bin'), 'ignored\n');
    await rm(join(repo, 'gone.txt'));

    const dest = join(root, 'reader');
    await copyCheckout(repo, dest);
    assert.equal(await readFile(join(dest, 'products/example/registry.yaml'), 'utf8'), 'edited in the working tree\n');
    assert.equal(await readFile(join(dest, 'new.txt'), 'utf8'), 'untracked\n');
    assert.equal(await readlink(join(dest, 'link.yaml')), 'products/example/registry.yaml');
    assert.equal(existsSync(join(dest, 'target')), false);
    assert.equal(existsSync(join(dest, 'gone.txt')), false);
    assert.equal(existsSync(join(dest, '.git')), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
