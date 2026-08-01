// Unit tests for the OpenAPI fetch-at-ref pipeline (scripts/fetch-openapi.mjs).
// Run with `npm test` (node --test). specFromClone's git executor and retry
// backoff are injectable test seams, so this runs offline and instantly; the
// retry-and-stderr-bounding policy itself is covered exhaustively in
// git-fetch-retry.test.mjs.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { specFromClone } from './fetch-openapi.mjs';

test('specFromClone retries a transient fetch failure and reads the spec after success', async () => {
  const dest = await mkdtemp(join(tmpdir(), 'fetch-openapi-test-'));
  try {
    let fetchCalls = 0;
    const invoked = [];
    const fakeRun = async (command, args) => {
      invoked.push(args[0]);
      if (args[0] === 'fetch') {
        fetchCalls += 1;
        if (fetchCalls < 2) {
          const error = new Error('Command failed: git fetch --quiet --depth 1 origin deadbeef');
          error.stderr = 'fatal: the remote end hung up unexpectedly';
          throw error;
        }
      }
      if (args[0] === 'checkout') {
        // specFromClone reads the spec from the worktree only after checkout
        // succeeds; since the git executor is faked, seed that file here,
        // where a real checkout would have populated it.
        await mkdir(join(dest, 'openapi'), { recursive: true });
        await writeFile(join(dest, 'openapi/demo.openapi.json'), '{"openapi":"3.0.0"}\n');
      }
      return { stdout: '', stderr: '' };
    };

    const raw = await specFromClone(
      'demo-repo',
      'https://example.test/demo.git',
      'deadbeef',
      'openapi/demo.openapi.json',
      { run: fakeRun, retryOptions: { sleep: async () => {} }, dest },
    );

    assert.equal(fetchCalls, 2);
    // init and remote-add each ran once; only fetch (the network step) retried.
    assert.deepEqual(invoked, ['init', 'remote', 'fetch', 'fetch', 'checkout']);
    assert.equal(raw, '{"openapi":"3.0.0"}\n');
  } finally {
    await rm(dest, { recursive: true, force: true });
  }
});
