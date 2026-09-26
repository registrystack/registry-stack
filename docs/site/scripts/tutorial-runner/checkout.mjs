// Copy a checkout for a journey that starts from one.
//
// Some pages start "from a Registry Stack checkout" and copy an example out of
// it. The copy holds what a reader who cloned the repository would have, with
// this working tree's edits: every tracked file that still exists, and every
// untracked file git does not ignore. Build output and the .git directory are
// left behind, so the copy is small and the journey cannot touch this
// checkout.

import { execFileSync } from 'node:child_process';
import { cp, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';

function listFiles(repoRoot, ...args) {
  const output = execFileSync('git', ['-C', repoRoot, 'ls-files', '-z', ...args], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return output.split('\0').filter(Boolean);
}

export async function copyCheckout(repoRoot, dest) {
  const deleted = new Set(listFiles(repoRoot, '--deleted'));
  const files = listFiles(repoRoot, '--cached', '--others', '--exclude-standard').filter((path) => !deleted.has(path));
  for (const path of new Set(files)) {
    await mkdir(dirname(join(dest, path)), { recursive: true });
    await cp(join(repoRoot, path), join(dest, path), { verbatimSymlinks: true, recursive: true });
  }
}
