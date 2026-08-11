'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const http = require('node:http');
const path = require('node:path');
const { after, before, test } = require('node:test');

const { RelayClient, RelayClientError } = require('..');

const TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';
const TRACEPARENT = `00-${TRACE_ID}-00f067aa0ba902b7-01`;
const ETAG = `"${'0123456789abcdef'.repeat(4)}"`;

function assertBoundaryChildExitsNormally(source) {
  const result = spawnSync(process.execPath, ['-e', source], {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8',
    timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null, `child terminated by ${result.signal}: ${result.stderr}`);
  assert.equal(result.status, 0, result.stderr);
}

let server;
let baseUrl;

before(async () => {
  server = http.createServer((request, response) => {
    response.setHeader('traceparent', TRACEPARENT);
    response.setHeader('content-type', 'application/json');
    if (request.headers['if-none-match'] === ETAG) {
      response.statusCode = 304;
      response.setHeader('etag', ETAG);
      response.end();
      return;
    }
    if (request.url.endsWith('/health')) {
      response.end(JSON.stringify({ status: 'ok' }));
      return;
    }
    if (request.url.endsWith('/ready')) {
      response.end(JSON.stringify({ status: 'ready' }));
      return;
    }
    if (request.url.endsWith('/openapi.json')) {
      response.end('{"openapi":"3.1.0"}');
      return;
    }
    response.statusCode = 404;
    response.end('{}');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}/tenant`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test('probe results are plain camelCase object graphs', async () => {
  const result = await new RelayClient({ baseUrl }).health();
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
  assert.equal(result.kind, 'complete');
  assert.deepEqual(result.value, { status: 'ok' });
  assert.equal(result.traceId, TRACE_ID);
});

test('raw document bodies cross as Buffer values', async () => {
  const result = await new RelayClient({ baseUrl }).openapi();
  assert.equal(result.kind, 'complete');
  assert.ok(Buffer.isBuffer(result.body));
  assert.equal(result.body.toString('utf8'), '{"openapi":"3.1.0"}');
  assert.equal(result.mediaType, 'application/json');
});

test('every endpoint accepts its documented plain input graph', async () => {
  const client = new RelayClient({ baseUrl });
  const expectNotModified = async (promise) => {
    const result = await promise;
    assert.deepEqual(result, { kind: 'notModified', etag: ETAG, traceId: TRACE_ID });
  };

  assert.equal((await client.health()).value.status, 'ok');
  assert.equal((await client.ready()).value.status, 'ready');
  await expectNotModified(client.openapi(ETAG));
  await expectNotModified(client.serviceMetadata(ETAG));
  await expectNotModified(client.resources({ pageSize: 10 }, ETAG));
  await expectNotModified(client.continueResources({ cursor: 'resource-cursor' }, ETAG));
  await expectNotModified(client.resource('people', ETAG));
  await expectNotModified(client.listRecords('people', {
    pageSize: 10,
    fields: ['name'],
    accessProfile: 'public',
    format: 'geojson',
    filters: { status: 'active' },
    bbox: [-10, -5, 10, 5],
  }, ETAG));
  await expectNotModified(client.continueListRecords({
    route: { kind: 'records', resource: 'people' },
    cursor: 'records-cursor',
    format: 'geojson-rfc7946',
    accessProfile: 'public',
  }, ETAG));
  await expectNotModified(client.readRecord('people', 'person-1', {
    fields: ['name'],
    accessProfile: 'public',
    format: 'json-ld',
  }, ETAG));
  await expectNotModified(client.lookup('people', 'by-identity', {
    number: 42,
    active: true,
    jurisdiction: 'AA',
  }, { format: 'json' }, ETAG));
  await expectNotModified(client.search('people', 'by-name', {
    pageSize: 10,
    filters: { status: 'active' },
  }, ETAG));
  await expectNotModified(client.continueSearch({
    route: { kind: 'search', resource: 'people', search: 'by-name' },
    cursor: 'search-cursor',
    format: 'json-fg',
  }, ETAG));
  await expectNotModified(client.artifact('schema', ETAG));
  await expectNotModified(client.sdmxData({
    agency: 'AGENCY',
    resource: 'FLOW',
    version: '1.0.0',
    key: 'A.B',
    constraints: { TIME_PERIOD: 'ge:2020+le:2024' },
    offset: 1,
    limit: 10,
    dimensionAtObservation: 'AllDimensions',
    format: 'csv',
  }, ETAG));
  await expectNotModified(client.sdmxStructure({
    kind: 'dataflow',
    agency: 'AGENCY',
    resource: 'FLOW',
    version: '1.0.0',
  }, ETAG));
});

test('request validation failures have a distinct stable kind', async () => {
  const client = new RelayClient({ baseUrl });
  await assert.rejects(
    client.resources({ pageSize: 0 }),
    (error) => error instanceof RelayClientError && error.kind === 'invalid_request',
  );
});

test('synchronous napi argument conversion failures use fixed redacted envelopes', () => {
  const client = new RelayClient({ baseUrl });
  for (const invoke of [
    () => client.resource(42),
    () => client.resources({ pageSize: 1n }),
    () => client.lookup('people', 'by-identity', undefined),
    () => client.lookup('people', 'by-identity', { number: Number.NaN }),
    () => client.lookup('people', 'by-identity', { number: Number.POSITIVE_INFINITY }),
  ]) {
    assert.throws(
      invoke,
      (error) => error instanceof RelayClientError
        && error.kind === 'invalid_request'
        && error.message === 'Relay client arguments are invalid',
    );
  }
});

test('constructor napi conversion failures use fixed configuration envelopes', () => {
  for (const config of [{ baseUrl: 1n }, undefined]) {
    assert.throws(
      () => new RelayClient(config),
      (error) => error instanceof RelayClientError
        && error.kind === 'configuration'
        && error.message === 'Relay client configuration is invalid',
    );
  }
});

test('cyclic inputs are rejected without aborting the Node process', () => {
  const prelude = `
    const assert = require('node:assert/strict');
    const { RelayClient, RelayClientError } = require('.');
    const matches = (kind) => (error) => error instanceof RelayClientError
      && error.kind === kind
      && error.message === (kind === 'configuration'
        ? 'Relay client configuration is invalid'
        : 'Relay client arguments are invalid');
  `;
  assertBoundaryChildExitsNormally(`${prelude}
    const config = { baseUrl: 'http://127.0.0.1:1' };
    config.self = config;
    assert.throws(() => new RelayClient(config), matches('configuration'));
  `);
  assertBoundaryChildExitsNormally(`${prelude}
    const client = new RelayClient({ baseUrl: 'http://127.0.0.1:1' });
    const selectors = {};
    selectors.self = selectors;
    assert.throws(
      () => client.lookup('people', 'by-identity', selectors),
      matches('invalid_request'),
    );
  `);
  assertBoundaryChildExitsNormally(`${prelude}
    const client = new RelayClient({ baseUrl: 'http://127.0.0.1:1' });
    const options = {};
    options.self = options;
    assert.throws(
      () => client.lookup('people', 'by-identity', {}, options),
      matches('invalid_request'),
    );
  `);
});

test('plain JSON cloning rejects active and exotic JavaScript behavior', () => {
  const client = new RelayClient({ baseUrl });
  const matchesInvalidRequest = (error) => error instanceof RelayClientError
    && error.kind === 'invalid_request'
    && error.message === 'Relay client arguments are invalid';

  let getterInvoked = false;
  const accessor = {};
  Object.defineProperty(accessor, 'number', {
    enumerable: true,
    get() {
      getterInvoked = true;
      return 42;
    },
  });
  assert.throws(() => client.lookup('people', 'by-identity', accessor), matchesInvalidRequest);
  assert.equal(getterInvoked, false);

  let proxyTrapInvoked = false;
  const proxy = new Proxy({}, {
    ownKeys() {
      proxyTrapInvoked = true;
      return [];
    },
  });
  assert.throws(() => client.lookup('people', 'by-identity', proxy), matchesInvalidRequest);
  assert.equal(proxyTrapInvoked, false);

  const symbolMember = {};
  symbolMember[Symbol('hidden')] = 'value';
  assert.throws(() => client.lookup('people', 'by-identity', symbolMember), matchesInvalidRequest);
  assert.throws(
    () => client.lookup('people', 'by-identity', Object.create({ number: 42 })),
    matchesInvalidRequest,
  );
});

test('plain JSON cloning enforces one bounded budget across all arguments', () => {
  const client = new RelayClient({ baseUrl });
  const matchesInvalidRequest = (error) => error instanceof RelayClientError
    && error.kind === 'invalid_request'
    && error.message === 'Relay client arguments are invalid';

  const halfBudget = 'x'.repeat(2_100_000);
  assert.throws(
    () => client.lookup('people', 'by-identity', { one: halfBudget }, { fields: [halfBudget] }),
    matchesInvalidRequest,
  );
  assert.throws(
    () => client.readRecord('people', 'one', { fields: new Array(100_000).fill('x') }),
    matchesInvalidRequest,
  );

  const deep = {};
  let cursor = deep;
  for (let index = 0; index < 129; index += 1) {
    cursor.next = {};
    cursor = cursor.next;
  }
  assert.throws(() => client.lookup('people', 'by-identity', deep), matchesInvalidRequest);
});

test('continuations cannot cross list and search methods', async () => {
  const client = new RelayClient({ baseUrl });
  await assert.rejects(
    client.continueListRecords({
      route: { kind: 'search', resource: 'people', search: 'by-name' },
      cursor: 'opaque',
      format: 'json',
    }),
    (error) => error instanceof RelayClientError && error.kind === 'invalid_request',
  );
});

test('configuration failures never repeat static credentials', () => {
  const secret = 'canary-static-token';
  assert.throws(
    () => new RelayClient({
      baseUrl: 'https://relay.invalid',
      authorization: { static: secret, privateKeyJwt: {} },
    }),
    (error) => error instanceof RelayClientError
      && error.kind === 'configuration'
      && !error.message.includes(secret),
  );
});

test('private-key JWT configuration is accepted without token-endpoint I/O', () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const clientKey = privateKey.export({ format: 'jwk' });
  clientKey.alg = 'ES256';
  clientKey.kid = 'node-binding-test-key';
  const client = new RelayClient({
    baseUrl,
    authorization: {
      privateKeyJwt: {
        tokenEndpoint: 'https://issuer.invalid/oauth/token',
        clientId: 'node-binding-test-client',
        clientKey,
        audience: 'https://issuer.invalid/oauth/token',
        assertionLifetimeSeconds: 60,
        refreshMarginSeconds: 10,
        requestTimeoutMilliseconds: 1_000,
        connectTimeoutMilliseconds: 500,
        userAgent: 'registry-relay-client-node-test',
      },
    },
  });
  assert.ok(client);
});
