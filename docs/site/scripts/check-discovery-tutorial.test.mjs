import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { test } from 'node:test';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

test('Discovery tutorial dry-run binds the documented reader journey', async () => {
  const { stdout } = await execFileAsync(
    'bash',
    ['scripts/check-discovery-tutorial.sh', '--dry-run'],
    { cwd: new URL('..', import.meta.url), encoding: 'utf8' },
  );

  assert.match(
    stdout,
    /Discovery tutorial dry-run: 5 shell fences and required role\/output literals present/u,
  );
});
