'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const nativePath = require.resolve('../index');
const clientPath = require.resolve('../client');

function loadWithFakeNative(FakeCoordinatorClient) {
  const previousNative = require.cache[nativePath];
  const previousClient = require.cache[clientPath];
  require.cache[nativePath] = { id: nativePath, filename: nativePath, loaded: true, exports: { CoordinatorClient: FakeCoordinatorClient } };
  delete require.cache[clientPath];
  const loaded = require('../client');
  return {
    ...loaded,
    restore() {
      if (previousNative) require.cache[nativePath] = previousNative;
      else delete require.cache[nativePath];
      if (previousClient) require.cache[clientPath] = previousClient;
      else delete require.cache[clientPath];
    },
  };
}

test('configuration accessors and proxies are refused before native construction', () => {
  let constructions = 0;
  class FakeCoordinatorClient { constructor() { constructions += 1; } }
  const loaded = loadWithFakeNative(FakeCoordinatorClient);
  try {
    for (const config of [
      Object.defineProperty({}, 'baseUrl', { enumerable: true, get() { throw new Error('getter ran'); } }),
      new Proxy({ baseUrl: 'https://coordinator.example.invalid/' }, {}),
    ]) {
      assert.throws(() => new loaded.CoordinatorClient(config), (error) => {
        assert.ok(error instanceof loaded.CoordinatorClientError);
        assert.equal(error.kind, 'configuration');
        return true;
      });
    }
    assert.equal(constructions, 0);
  } finally {
    loaded.restore();
  }
});

test('cyclic and oversized start input is refused before the native call', async () => {
  let calls = 0;
  class FakeCoordinatorClient {
    start() { calls += 1; return Promise.resolve({ kind: 'complete', value: null }); }
  }
  const loaded = loadWithFakeNative(FakeCoordinatorClient);
  try {
    const client = new loaded.CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/' });
    const input = {};
    input.self = input;
    assert.throws(
      () => client.start('secret', 'key', { flow: 'example', input }),
      (error) => error instanceof loaded.CoordinatorClientError && error.kind === 'invalid_request',
    );
    assert.throws(
      () => client.start('secret', 'key', { flow: 'example', input: 'x'.repeat(1024 * 1024 + 1) }),
      (error) => error instanceof loaded.CoordinatorClientError && error.kind === 'invalid_request',
    );
    assert.equal(calls, 0);
  } finally {
    loaded.restore();
  }
});

test('sparse and accessor-bearing arrays are refused without executing user code or native calls', () => {
  let calls = 0;
  let getters = 0;
  class FakeCoordinatorClient {
    start() { calls += 1; return Promise.resolve({ kind: 'complete', value: null }); }
  }
  const loaded = loadWithFakeNative(FakeCoordinatorClient);
  try {
    const client = new loaded.CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/' });
    const indexedGetter = [];
    Object.defineProperty(indexedGetter, '0', {
      enumerable: true,
      get() { getters += 1; return 'unsafe'; },
    });
    const customMap = ['safe'];
    Object.defineProperty(customMap, 'map', {
      enumerable: true,
      get() { getters += 1; return Array.prototype.map; },
    });

    for (const input of [new Array(20_001), indexedGetter, customMap]) {
      assert.throws(
        () => client.start('secret', 'key', { flow: 'example', input }),
        (error) => error instanceof loaded.CoordinatorClientError && error.kind === 'invalid_request',
      );
    }
    assert.equal(getters, 0);
    assert.equal(calls, 0);
  } finally {
    loaded.restore();
  }
});
