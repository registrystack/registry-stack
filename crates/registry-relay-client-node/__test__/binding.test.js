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
const lookupBodies = [];
const requestUrls = [];

before(async () => {
  server = http.createServer((request, response) => {
    requestUrls.push(request.url);
    response.setHeader('traceparent', TRACEPARENT);
    response.setHeader('content-type', 'application/json');
    if (request.method === 'POST'
      && request.url.includes('/lookups/')
      && request.headers['if-none-match'] !== ETAG) {
      const chunks = [];
      request.on('data', (chunk) => chunks.push(chunk));
      request.on('end', () => {
        lookupBodies.push(Buffer.concat(chunks).toString('utf8'));
        response.statusCode = 404;
        response.end('{}');
      });
      return;
    }
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
    bbox: [-10, -5, 10, 5],
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

test('record and SDMX inputs use the canonical cross-language literals', async () => {
  const client = new RelayClient({ baseUrl });
  const before = requestUrls.length;
  const invalid = (error) => error instanceof RelayClientError
    && error.kind === 'invalid_request';

  await assert.rejects(
    client.readRecord('people', 'one', { format: 'geo-json-rfc7946' }),
    invalid,
  );
  await assert.rejects(
    client.sdmxStructure({
      kind: 'data-structure',
      agency: 'AGENCY',
      resource: 'FLOW',
      version: '1.0.0',
    }),
    invalid,
  );
  assert.equal(requestUrls.length, before);
});

test('constructor numeric options preserve JavaScript safe integers', () => {
  for (const numericOptions of [
    { maxResponseBytes: 2 ** 32 },
    { maxResponseBytes: Number.MAX_SAFE_INTEGER },
    { requestTimeoutMilliseconds: 2 ** 32 },
    { connectTimeoutMilliseconds: 2 ** 32 },
  ]) {
    assert.ok(new RelayClient({ baseUrl, ...numericOptions }));
  }

  for (const maxResponseBytes of [1.5, -1, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(
      () => new RelayClient({ baseUrl, maxResponseBytes }),
      (error) => error instanceof RelayClientError
        && error.kind === 'configuration'
        && error.message === 'maxResponseBytes must be a non-negative integer',
    );
  }
  assert.throws(
    () => new RelayClient({ baseUrl, maxResponseBytes: 0 }),
    (error) => error instanceof RelayClientError
      && error.kind === 'configuration'
      && error.message === 'the response body bound must be greater than zero',
  );
});

test('request integer options accept their target maxima without precision loss', async () => {
  requestUrls.length = 0;
  const client = new RelayClient({ baseUrl });
  await assert.rejects(client.resources({ pageSize: 100 }));
  await assert.rejects(client.listRecords('people', { pageSize: 0xffff_ffff }));
  await assert.rejects(client.search('people', 'within-bbox', {
    pageSize: 0xffff_ffff,
    bbox: [-10, -5, 10, 5],
  }));
  await assert.rejects(client.sdmxData({
    agency: 'AGENCY',
    resource: 'FLOW',
    version: '1.0.0',
    offset: 0xffff_ffff,
    limit: 0xffff_ffff,
  }));

  assert.equal(requestUrls.length, 4);
  const queries = requestUrls.map((value) => new URL(value, baseUrl).searchParams);
  assert.equal(queries[0].get('pageSize'), '100');
  assert.equal(queries[1].get('pageSize'), '4294967295');
  assert.equal(queries[2].get('pageSize'), '4294967295');
  assert.equal(queries[3].get('offset'), '4294967295');
  assert.equal(queries[3].get('limit'), '4294967295');
});

test('request integer options reject fractional, unsafe, and target-overflow values before I/O', async () => {
  requestUrls.length = 0;
  const client = new RelayClient({ baseUrl });
  for (const invoke of [
    () => client.resources({ pageSize: 1.5 }),
    () => client.listRecords('people', { pageSize: Number.MAX_SAFE_INTEGER + 1 }),
    () => client.search('people', 'within-bbox', {
      pageSize: 2 ** 32,
      bbox: [-10, -5, 10, 5],
    }),
    () => client.sdmxData({
      agency: 'AGENCY', resource: 'FLOW', version: '1.0.0', offset: 2 ** 32,
    }),
    () => client.sdmxData({
      agency: 'AGENCY', resource: 'FLOW', version: '1.0.0', limit: -1,
    }),
  ]) {
    await assert.rejects(
      invoke(),
      (error) => error instanceof RelayClientError
        && error.kind === 'invalid_request'
        && /must be a non-negative integer/.test(error.message),
    );
  }
  await assert.rejects(
    client.resources({ pageSize: 101 }),
    (error) => error instanceof RelayClientError
      && error.kind === 'invalid_request'
      && error.message === 'resource page size must be between 1 and 100',
  );
  assert.deepEqual(requestUrls, []);
});

test('lookup preserves the full JavaScript safe integer domain in its JSON body', async () => {
  lookupBodies.length = 0;
  const client = new RelayClient({ baseUrl });
  await assert.rejects(client.lookup('people', 'by-number', {
    max: Number.MAX_SAFE_INTEGER,
    min: Number.MIN_SAFE_INTEGER,
    wide: 2 ** 32,
  }));
  assert.deepEqual(lookupBodies, [
    '{"selectors":{"max":9007199254740991,"min":-9007199254740991,"wide":4294967296}}',
  ]);
});

test('lookup rejects fractional and unsafe numeric selectors as invalid requests', async () => {
  lookupBodies.length = 0;
  const client = new RelayClient({ baseUrl });
  for (const selector of [
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    Number.MIN_SAFE_INTEGER - 1,
  ]) {
    await assert.rejects(
      client.lookup('people', 'by-number', { number: selector }),
      (error) => error instanceof RelayClientError
        && error.kind === 'invalid_request'
        && error.message === 'a lookup selector value is invalid',
    );
  }
  assert.deepEqual(lookupBodies, []);
});

test('list and search runtime options preserve their distinct query shapes', async () => {
  const client = new RelayClient({ baseUrl });
  for (const promise of [
    client.listRecords('people', { bbox: [-10, -5, 10, 5] }),
    client.search('people', 'within-bbox', { pageSize: 10 }),
    client.search('people', 'within-bbox', {
      bbox: [-10, -5, 10, 5],
      filters: { status: 'active' },
    }),
  ]) {
    await assert.rejects(
      promise,
      (error) => error instanceof RelayClientError && error.kind === 'invalid_request',
    );
  }
  assert.throws(
    () => client.search('people', 'within-bbox', undefined),
    (error) => error instanceof RelayClientError
      && error.kind === 'invalid_request'
      && error.message === 'Relay client arguments are invalid',
  );
});

test('error facts omit nulls while preserving present falsy values', () => {
  const absent = new RelayClientError({
    kind: 'protocol',
    message: 'Relay response violated the protocol',
    code: null,
    status: null,
    traceId: null,
    retryAfterSeconds: null,
    transportKind: null,
    tokenKind: null,
  });
  for (const field of [
    'code', 'status', 'traceId', 'retryAfterSeconds', 'transportKind', 'tokenKind',
  ]) {
    assert.equal(Object.hasOwn(absent, field), false);
  }

  const present = new RelayClientError({
    kind: 'problem',
    message: 'Relay refused the request',
    code: 'resource.not_found',
    status: 0,
    traceId: TRACE_ID,
    retryAfterSeconds: 0,
    transportKind: 'connect',
    tokenKind: 'transport',
  });
  assert.equal(present.code, 'resource.not_found');
  assert.equal(present.status, 0);
  assert.equal(present.traceId, TRACE_ID);
  assert.equal(present.retryAfterSeconds, 0);
  assert.equal(present.transportKind, 'connect');
  assert.equal(present.tokenKind, 'transport');
});

test('synchronous napi argument conversion failures use fixed redacted envelopes', () => {
  const client = new RelayClient({ baseUrl });
  for (const invoke of [
    () => client.resource(42),
    () => client.resources({ pageSize: 1n }),
    () => client.resources({ pageSize: Number.POSITIVE_INFINITY }),
    () => client.lookup('people', 'by-identity', undefined),
    () => client.lookup('people', 'by-identity', { number: Number.NaN }),
    () => client.lookup('people', 'by-identity', { number: Number.POSITIVE_INFINITY }),
    () => client.search('people', 'within-bbox', { bbox: [Number.NaN, -5, 10, 5] }),
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
  for (const config of [
    { baseUrl: 1n },
    { baseUrl, maxResponseBytes: Number.NaN },
    { baseUrl, requestTimeoutMilliseconds: Number.POSITIVE_INFINITY },
    undefined,
  ]) {
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
  const privateKeyJwt = {
    tokenEndpoint: 'https://issuer.invalid/oauth/token',
    clientId: 'node-binding-test-client',
    clientKey,
    audience: 'https://issuer.invalid/oauth/token',
    assertionLifetimeSeconds: 300,
    refreshMarginSeconds: 2 ** 32,
    requestTimeoutMilliseconds: 2 ** 32,
    connectTimeoutMilliseconds: 2 ** 32,
    userAgent: 'registry-relay-client-node-test',
  };
  const construct = (overrides = {}) => new RelayClient({
    baseUrl,
    authorization: { privateKeyJwt: { ...privateKeyJwt, ...overrides } },
  });
  const client = construct();
  assert.ok(client);

  for (const [overrides, message] of [
    [
      { assertionLifetimeSeconds: 300.5 },
      'authorization.privateKeyJwt.assertionLifetimeSeconds must be an integer',
    ],
    [
      { refreshMarginSeconds: Number.MAX_SAFE_INTEGER + 1 },
      'authorization.privateKeyJwt.refreshMarginSeconds must be an integer',
    ],
    [
      { requestTimeoutMilliseconds: -1 },
      'authorization.privateKeyJwt.requestTimeoutMilliseconds must be a non-negative integer',
    ],
  ]) {
    assert.throws(
      () => construct(overrides),
      (error) => error instanceof RelayClientError
        && error.kind === 'configuration'
        && error.message === message,
    );
  }
});
