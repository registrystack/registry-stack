'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { after, before, test } = require('node:test');

const {
  BaseRegistryClient,
  BaseRegistryClientError,
  BRegCreateBinding,
  BRegLifecycleAction,
  BRegLifecycleAuthority,
  BRegMetadata,
  BRegPatchBinding,
} = require('..');

const TRACE_ID = '4bf92f3577b34da6a3ce929d0e0e4736';
const TRACEPARENT = `00-${TRACE_ID}-00f067aa0ba902b7-01`;
const MISSING_RECORD_ID = '00000000-0000-4000-8000-000000000001';
let server;
let baseUrl;

before(async () => {
  server = http.createServer((request, response) => {
    response.setHeader('traceparent', TRACEPARENT);
    response.setHeader('content-type', 'application/json');
    if (request.url.endsWith('/health')) response.end(JSON.stringify({ status: 'alive' }));
    else if (request.url.endsWith('/ready')) response.end(JSON.stringify({ status: 'ready' }));
    else if (request.url.includes('/openapi.json')) response.end('{"openapi":"3.1.0"}');
    else if (request.url.endsWith('/v1/records/people')) {
      response.setHeader(
        'link',
        '<https://id.registrystack.org/profiles/registry-record/v1>; rel="profile", '
          + '</tenant/v1/schemas/person>; rel="describedby"',
      );
      response.end(JSON.stringify({
        items: [],
        pageInfo: { nextCursor: null },
        meta: {
          registryIdentifier: 'test-registry',
          datasetIdentifier: 'people',
          entityTypeIdentifier: 'person',
        },
      }));
    }
    else if (request.url.endsWith('/v1/registry')) response.end(JSON.stringify({
      id: 'test-registry',
      version: '1.0.0',
      revision: `sha256:${'a'.repeat(64)}`,
      metadataVersion: '1',
      entities: [],
      operations: [],
    }));
    else if (request.url.endsWith(`/v1/records/companies/${MISSING_RECORD_ID}`)) {
      response.statusCode = 404;
      response.setHeader('content-type', 'application/problem+json');
      response.setHeader('cache-control', 'no-store');
      response.end(JSON.stringify({
        type: 'urn:breg:problem:resource.not_found',
        title: 'Not Found',
        status: 404,
        detail: 'The requested resource was not found.',
        code: 'resource.not_found',
        traceId: TRACE_ID,
      }));
    }
    else { response.statusCode = 404; response.end('{}'); }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}/tenant`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
});

test('probe results are plain camelCase object graphs', async () => {
  const result = await new BaseRegistryClient({ baseUrl }).health();
  assert.deepEqual(result.value, { status: 'alive' });
  assert.equal(result.kind, 'complete');
  assert.equal(result.traceId, TRACE_ID);
});

test('raw documents cross as Buffer values', async () => {
  const result = await new BaseRegistryClient({ baseUrl }).openapi();
  assert.ok(Buffer.isBuffer(result.body));
  assert.equal(result.body.toString(), '{"openapi":"3.1.0"}');
  assert.equal(result.mediaType, 'application/json');
});

test('invalid request graphs fail before I/O with a stable kind', async () => {
  const client = new BaseRegistryClient({ baseUrl });
  const cyclic = {}; cyclic.self = cyclic;
  assert.throws(() => client.continueList(cyclic), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
  await assert.rejects(client.listRecords('people', { top: 0 }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'invalid_request'
  ));
});

test('nullable record options use request defaults', async () => {
  const result = await new BaseRegistryClient({ baseUrl }).listRecords('people', {
    select: null,
    accessProfile: null,
    format: null,
    top: null,
    filter: null,
    orderby: null,
    count: null,
  });
  assert.deepEqual(result.value.items, []);
});

test('constructors reject unsupported fields and unsafe integers', () => {
  assert.throws(() => new BaseRegistryClient({ baseUrl, retry: true }), (error) => (
    error instanceof BaseRegistryClientError && error.kind === 'configuration'
  ));
  assert.throws(() => new BaseRegistryClient({
    baseUrl,
    maxResponseBytes: Number.MAX_SAFE_INTEGER + 1,
  }), (error) => error instanceof BaseRegistryClientError && error.kind === 'configuration');
});

test('nullable private-key JWT durations use provider defaults', () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const clientKey = privateKey.export({ format: 'jwk' });
  clientKey.alg = 'ES256';
  clientKey.kid = 'breg-node-binding-test-key';
  const config = {
    baseUrl,
    authorization: {
      privateKeyJwt: {
        tokenEndpoint: 'https://issuer.invalid/oauth/token',
        clientId: 'breg-node-binding-test-client',
        clientKey,
        assertionLifetimeSeconds: null,
        refreshMarginSeconds: null,
      },
    },
  };
  assert.ok(new BaseRegistryClient(config));
  assert.throws(() => new BaseRegistryClient({
    ...config,
    authorization: {
      privateKeyJwt: {
        ...config.authorization.privateKeyJwt,
        assertionLifetimeSeconds: 1.5,
      },
    },
  }), (error) => error instanceof BaseRegistryClientError && error.kind === 'configuration');
});

test('a missing record fails with its own not_found kind', async () => {
  const client = new BaseRegistryClient({ baseUrl });
  await assert.rejects(
    client.getRecord('companies', MISSING_RECORD_ID),
    (error) => error instanceof BaseRegistryClientError
      && error.kind === 'not_found'
      && error.status === 404,
  );
});

test('metadata selection failures use the public error envelope', async () => {
  const metadata = await new BaseRegistryClient({ baseUrl }).registryContract();
  assert.equal(metadata.etag, null);
  assert.throws(
    () => metadata.selectCreate('records.missing.create', 'writer'),
    (error) => error instanceof BaseRegistryClientError
      && error.kind === 'metadata_selection'
      && error.code === 'not_found',
  );
  assert.throws(
    () => metadata.selectCreate(null, 'writer'),
    (error) => error instanceof BaseRegistryClientError
      && error.kind === 'invalid_request',
  );
});

test('configuration failures never repeat static credentials', () => {
  const secret = 'canary-static-token-that-must-not-render';
  assert.throws(() => new BaseRegistryClient({
    baseUrl,
    authorization: { static: secret, privateKeyJwt: {} },
  }), (error) => (
    error instanceof BaseRegistryClientError
      && error.kind === 'configuration'
      && !error.message.includes(secret)
  ));
});

test('metadata-selected authority types have no public constructor', () => {
  for (const Authority of [
    BRegCreateBinding,
    BRegPatchBinding,
    BRegLifecycleAuthority,
    BRegLifecycleAction,
    BRegMetadata,
  ]) {
    assert.throws(() => new Authority());
  }
});
