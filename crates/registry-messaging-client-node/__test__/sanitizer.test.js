'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

test('oversized object keys are refused before the native client sees the token', () => {
  const indexPath = require.resolve('../index');
  const clientPath = require.resolve('../client');
  const previousIndex = require.cache[indexPath];
  const previousClient = require.cache[clientPath];
  let submitCalls = 0;

  class NativeMessagingClient {
    submit() {
      submitCalls += 1;
      return Promise.resolve();
    }
  }

  require.cache[indexPath] = {
    id: indexPath,
    filename: indexPath,
    loaded: true,
    exports: { MessagingClient: NativeMessagingClient },
  };
  delete require.cache[clientPath];

  try {
    const { MessagingClient, MessagingClientError } = require('../client');
    const client = new MessagingClient({ baseUrl: 'https://messaging.example/' });
    const oversizedKey = 'k'.repeat(1024 * 1024 + 1);

    assert.throws(
      () => client.submit('token-canary', 'key-1', { [oversizedKey]: null }),
      (error) => error instanceof MessagingClientError && error.kind === 'invalid_request',
    );
    assert.equal(submitCalls, 0);
  } finally {
    if (previousIndex === undefined) delete require.cache[indexPath];
    else require.cache[indexPath] = previousIndex;
    if (previousClient === undefined) delete require.cache[clientPath];
    else require.cache[clientPath] = previousClient;
  }
});
