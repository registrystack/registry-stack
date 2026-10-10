'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

test('oversized object keys are refused before the native client sees the token', () => {
  const indexPath = require.resolve('../index');
  const clientPath = require.resolve('../client');
  const previousIndex = require.cache[indexPath];
  const previousClient = require.cache[clientPath];
  let holdCalls = 0;

  class NativeSchedulingClient {
    createHold() {
      holdCalls += 1;
      return Promise.resolve();
    }
  }

  require.cache[indexPath] = {
    id: indexPath,
    filename: indexPath,
    loaded: true,
    exports: { SchedulingClient: NativeSchedulingClient },
  };
  delete require.cache[clientPath];

  try {
    const { SchedulingClient, SchedulingClientError } = require('../client');
    const client = new SchedulingClient({ baseUrl: 'https://scheduling.example/' });
    const oversizedKey = 'k'.repeat(1024 * 1024 + 1);

    assert.throws(
      () => client.createHold('token-canary', 'key-1', { [oversizedKey]: null }),
      (error) => error instanceof SchedulingClientError && error.kind === 'invalid-request',
    );
    assert.equal(holdCalls, 0);
  } finally {
    if (previousIndex === undefined) delete require.cache[indexPath];
    else require.cache[indexPath] = previousIndex;
    if (previousClient === undefined) delete require.cache[clientPath];
    else require.cache[clientPath] = previousClient;
  }
});

test('a native rejection without a failure envelope is a protocol failure with an unknown outcome', async () => {
  const indexPath = require.resolve('../index');
  const clientPath = require.resolve('../client');
  const previousIndex = require.cache[indexPath];
  const previousClient = require.cache[clientPath];

  class NativeSchedulingClient {
    createHold() {
      return Promise.reject(new Error('Failed to convert the result: token-canary'));
    }
  }

  require.cache[indexPath] = {
    id: indexPath,
    filename: indexPath,
    loaded: true,
    exports: { SchedulingClient: NativeSchedulingClient },
  };
  delete require.cache[clientPath];

  try {
    const { SchedulingClient, SchedulingClientError } = require('../client');
    const client = new SchedulingClient({ baseUrl: 'https://scheduling.example/' });

    await assert.rejects(
      client.createHold('token-canary', 'key-1', { offering: 'o' }),
      (error) => {
        assert.ok(error instanceof SchedulingClientError);
        assert.equal(error.kind, 'protocol');
        assert.equal(error.outcomeUnknown, true);
        assert.equal(error.message, 'Registry Scheduling client failed');
        assert.doesNotMatch(error.message, /token-canary/);
        return true;
      },
    );
  } finally {
    if (previousIndex === undefined) delete require.cache[indexPath];
    else require.cache[indexPath] = previousIndex;
    if (previousClient === undefined) delete require.cache[clientPath];
    else require.cache[clientPath] = previousClient;
  }
});
