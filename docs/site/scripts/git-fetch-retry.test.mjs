// Unit tests for the network-git retry helper (scripts/git-fetch-retry.mjs).
// Run with `npm test` (node --test). Everything here is offline: the
// "operation" passed to retryGitFetch is a fake that fails or succeeds on
// command, and `sleep` is stubbed so the backoff never actually waits.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { retryGitFetch } from './git-fetch-retry.mjs';

function gitError(stderr) {
  const error = new Error('Command failed: git fetch --quiet --depth 1 origin deadbeef');
  error.stderr = stderr;
  return error;
}

test('retries a transient failure and returns on success within the retry budget', async () => {
  let calls = 0;
  const sleeps = [];
  const result = await retryGitFetch(
    'demo-repo: fetch deadbeef',
    async () => {
      calls += 1;
      if (calls < 3) throw gitError('fatal: the remote end hung up unexpectedly');
      return 'ok';
    },
    { sleep: async (ms) => sleeps.push(ms) },
  );

  assert.equal(result, 'ok');
  assert.equal(calls, 3);
  // Slept between attempt 1->2 and 2->3, but not after the final success.
  assert.equal(sleeps.length, 2);
});

test('succeeds on the first attempt without sleeping', async () => {
  let calls = 0;
  let slept = false;
  const result = await retryGitFetch(
    'demo-repo: fetch deadbeef',
    async () => {
      calls += 1;
      return 'ok';
    },
    { sleep: async () => (slept = true) },
  );

  assert.equal(result, 'ok');
  assert.equal(calls, 1);
  assert.equal(slept, false);
});

test('surfaces the real git stderr after exhausting the retry budget', async () => {
  let calls = 0;
  await assert.rejects(
    () =>
      retryGitFetch(
        'demo-repo: fetch deadbeef',
        async () => {
          calls += 1;
          throw gitError('fatal: unable to access https://example.test/demo.git/: Could not resolve host');
        },
        { sleep: async () => {} },
      ),
    /demo-repo: fetch deadbeef: failed after 3 attempts: fatal: unable to access .+ Could not resolve host/,
  );
  assert.equal(calls, 3);
});

test('bounds a runaway stderr stream so a huge message cannot flood the log', async () => {
  const hugeStderr = 'x'.repeat(10_000);
  await assert.rejects(
    () =>
      retryGitFetch(
        'demo-repo: fetch deadbeef',
        async () => {
          throw gitError(hugeStderr);
        },
        { sleep: async () => {}, attempts: 1, stderrLimit: 200 },
      ),
    (error) => {
      assert.match(error.message, /truncated/);
      assert.ok(error.message.length < hugeStderr.length);
      return true;
    },
  );
});

test('does not retry when attempts is 1', async () => {
  let calls = 0;
  await assert.rejects(
    () =>
      retryGitFetch(
        'demo-repo: fetch deadbeef',
        async () => {
          calls += 1;
          throw gitError('fatal: nope');
        },
        { sleep: async () => {}, attempts: 1 },
      ),
  );
  assert.equal(calls, 1);
});

test('falls back to the error message when git reports no stderr', async () => {
  await assert.rejects(
    () =>
      retryGitFetch(
        'demo-repo: fetch deadbeef',
        async () => {
          throw new Error('spawn git ENOENT');
        },
        { sleep: async () => {}, attempts: 1 },
      ),
    /failed after 1 attempts: spawn git ENOENT/,
  );
});
