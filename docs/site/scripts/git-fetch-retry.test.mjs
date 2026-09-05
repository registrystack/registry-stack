// Focused unit tests for the shared shallow-clone fetch retry.
// Run with `npm test` (node --test).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { fetchRefWithRetry } from './git-fetch-retry.mjs';

// A real promisified execFile rejection's `.message` already embeds the
// child's stderr (Node formats it as `Command failed: <cmd>\n<stderr>`), in
// addition to carrying it separately on `.stderr`. These fakes mirror that
// shape so the tests exercise both the transient classifier (which reads
// `.stderr`) and the operator-facing surfacing (which reads `.message`).
function fakeGitFetchError(command, stderr) {
  const error = new Error(`Command failed: ${command}\n${stderr}`);
  error.stderr = Buffer.from(stderr);
  return error;
}

test('retries a transient fetch failure with backoff before succeeding', async () => {
  let calls = 0;
  const waits = [];
  const result = await fetchRefWithRetry('deadbeef', '/repo', {
    execFileImpl: async () => {
      calls += 1;
      if (calls < 3) {
        throw fakeGitFetchError(
          'git fetch --quiet --depth 1 origin deadbeef',
          "fatal: unable to access 'https://example.invalid/repo.git/': Could not resolve host: example.invalid\n",
        );
      }
      return { stdout: Buffer.from(''), stderr: Buffer.from('') };
    },
    wait: async (delayMs) => { waits.push(delayMs); },
  });

  assert.equal(result.stdout.toString('utf8'), '');
  assert.equal(calls, 3);
  assert.deepEqual(waits, [200, 400]);
});

test('does not retry a non-transient fetch failure', async () => {
  let calls = 0;
  await assert.rejects(
    fetchRefWithRetry('missing-ref', '/repo', {
      execFileImpl: async () => {
        calls += 1;
        throw fakeGitFetchError(
          'git fetch --quiet --depth 1 origin missing-ref',
          "fatal: couldn't find remote ref missing-ref\n",
        );
      },
      wait: async () => {
        throw new Error('must not wait before retrying a permanent failure');
      },
    }),
    /couldn't find remote ref/,
  );
  assert.equal(calls, 1);
});

test('stops retrying a persistent transient fetch failure after its bounded attempts, stderr intact', async () => {
  let calls = 0;
  const waits = [];
  await assert.rejects(
    fetchRefWithRetry('deadbeef', '/repo', {
      execFileImpl: async () => {
        calls += 1;
        throw fakeGitFetchError(
          'git fetch --quiet --depth 1 origin deadbeef',
          'fatal: the remote end hung up unexpectedly\n',
        );
      },
      wait: async (delayMs) => { waits.push(delayMs); },
    }),
    /fatal: the remote end hung up unexpectedly/,
  );
  assert.equal(calls, 3);
  assert.deepEqual(waits, [200, 400]);
});
