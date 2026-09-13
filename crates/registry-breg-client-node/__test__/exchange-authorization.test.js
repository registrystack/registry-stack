'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { test } = require('node:test');
const { BaseRegistryClient, BaseRegistryClientError } = require('..');

const TRACE = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
const GRANT = '00000000-0000-4000-8000-000000000042';

function key() {
  return { ...crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' }), alg: 'ES256', kid: 'synthetic-test' };
}
function clientConfig(endpoint, resource, scopes) {
  return { tokenEndpoint: endpoint, clientId: 'agent-client', clientKey: key(), resource, scopes };
}
function jwt(claims) {
  return `${Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'authority-key', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.signature`;
}
async function serve(handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}
async function form(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return new URLSearchParams(Buffer.concat(chunks).toString());
}

test('first-party option signs one verified person context and caches its token', async () => {
  const exchanges = [];
  const { server, origin } = await serve(async (request, response) => {
    if (request.url === '/token') {
      exchanges.push(await form(request));
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ access_token: 'person-token', token_type: 'Bearer', expires_in: 300,
        scope: 'records:get', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' }));
    } else {
      assert.equal(request.headers.authorization, 'Bearer person-token');
      response.writeHead(200, { 'content-type': 'application/json', traceparent: TRACE });
      response.end('{}');
    }
  });
  try {
    const client = new BaseRegistryClient({ baseUrl: origin, authorization: { exchange: {
      client: clientConfig(`${origin}/token`, 'urn:records', ['records:get']),
      context: { issuer: 'https://portal.example', subject: 'person-1', audience: 'https://issuer.example', generation: 'verified-1', deadlineSeconds: Math.floor(Date.now() / 1000) + 120 },
      firstParty: { key: key(), attributes: { registry_actor_kind: 'human', identity: { person_reference: 'person-1' } } },
    } } });
    await Promise.all([client.registryMetadata(), client.registryMetadata()]);
    assert.equal(exchanges.length, 1);
    const claims = JSON.parse(Buffer.from(exchanges[0].get('subject_token').split('.')[1], 'base64url'));
    assert.equal(claims.sub, 'person-1');
    assert.equal(claims.scope, 'records:get');
    assert.equal(claims.registry_grant_id, undefined);
    assert.equal(exchanges[0].get('resource'), 'urn:records');
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('remote grant option refreshes through empty assertion POST and refuses revocation', async () => {
  let assertions = 0;
  let reads = 0;
  const deadline = Math.floor(Date.now() / 1000) + 120;
  const { server, origin } = await serve(async (request, response) => {
    if (request.url === '/token') {
      const requestForm = await form(request);
      const bootstrap = requestForm.get('grant_type') === 'client_credentials';
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ access_token: bootstrap ? 'bootstrap' : 'task-token', token_type: 'Bearer', expires_in: bootstrap ? 60 : 1,
        scope: bootstrap ? 'casework:grants:assert' : 'records:get',
        ...(bootstrap ? {} : { issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' }) }));
    } else if (request.url === `/v1/task-grants/${GRANT}/assertion`) {
      assertions++;
      assert.equal(request.method, 'POST');
      assert.equal(request.headers.authorization, 'Bearer bootstrap');
      assert.equal((await form(request)).toString(), '');
      if (assertions > 1) { response.writeHead(403); response.end(); return; }
      const now = Math.floor(Date.now() / 1000);
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ assertion: jwt({ iss: 'https://casework.example', sub: 'agent-1', aud: 'https://issuer.example',
        iat: now, nbf: now, exp: now + 60, jti: 'assertion-1', scope: 'records:get', registry_actor_kind: 'agent',
        registry_grant_id: GRANT, registry_grant_client: 'agent-client', registry_grant_resource: 'urn:records', registry_grant_exp: deadline }),
        expiresAt: now + 60, grantExpiresAt: deadline }));
    } else {
      reads++;
      assert.equal(request.headers.authorization, 'Bearer task-token');
      response.writeHead(200, { 'content-type': 'application/json', traceparent: TRACE });
      response.end('{}');
    }
  });
  try {
    const client = new BaseRegistryClient({ baseUrl: origin, authorization: { exchange: {
      client: clientConfig(`${origin}/token`, 'urn:records', ['records:get']),
      context: { issuer: 'https://casework.example', subject: 'agent-1', audience: 'https://issuer.example', generation: 'grant-1', deadlineSeconds: deadline, grantId: GRANT },
      remote: { endpoint: `${origin}/v1/task-grants/${GRANT}/assertion`, bootstrap: clientConfig(`${origin}/token`, 'urn:casework', ['casework:grants:assert']),
        bootstrapResource: 'urn:casework', bootstrapScope: 'casework:grants:assert' },
    } } });
    await client.registryMetadata();
    await assert.rejects(client.registryMetadata(), error => error instanceof BaseRegistryClientError && error.tokenKind === 'protocol');
    assert.equal(assertions, 2);
    assert.equal(reads, 1);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
