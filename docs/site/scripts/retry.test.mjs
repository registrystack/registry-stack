// Focused unit tests for the bounded-retry helper.
// Run with `npm test` (node --test).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { withRetry } from './retry.mjs';

function transientError(message) {
  const error = new Error(message);
  error.transient = true;
  return error;
}

function permanentError(message) {
  return new Error(message);
}

const isTransient = (error) => Boolean(error.transient);

test('retries a transient failure with backoff before succeeding', async () => {
  let calls = 0;
  const waits = [];
  const result = await withRetry(
    async () => {
      calls += 1;
      if (calls < 3) throw transientError('flaky');
      return 'ok';
    },
    { isTransient, wait: async (delayMs) => { waits.push(delayMs); } },
  );

  assert.equal(result, 'ok');
  assert.equal(calls, 3);
  assert.deepEqual(waits, [200, 400]);
});

test('does not retry a non-transient failure', async () => {
  let calls = 0;
  await assert.rejects(
    withRetry(
      async () => {
        calls += 1;
        throw permanentError('bad input');
      },
      {
        isTransient,
        wait: async () => {
          throw new Error('must not wait before retrying a permanent failure');
        },
      },
    ),
    /bad input/,
  );
  assert.equal(calls, 1);
});

test('stops retrying a persistent transient failure after its bounded attempts', async () => {
  let calls = 0;
  const waits = [];
  await assert.rejects(
    withRetry(
      async () => {
        calls += 1;
        throw transientError('still flaky');
      },
      { isTransient, wait: async (delayMs) => { waits.push(delayMs); } },
    ),
    /still flaky/,
  );
  assert.equal(calls, 3);
  assert.deepEqual(waits, [200, 400]);
});
