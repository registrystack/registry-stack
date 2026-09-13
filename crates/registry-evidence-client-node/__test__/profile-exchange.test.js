'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { EvidenceClient, EvidenceClientError } = require('..');
const { startStubServer } = require('./helpers/stub-server');

function key() {
  return {
    ...crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' }),
    alg: 'ES256', kid: 'synthetic-profile-key',
  };
}

test('profile and exchange compose without losing pins or authority binding', async () => {
  const contracts = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'products',
    'breg', 'acceptance', 'farmer-landholding-evidence', 'evidence', 'farmer-contracts.json')));
  const published = { ...contracts, schema: 'registry.evidence-definitions/v1', holderBoundBatchMaxSize: 1 };
  const jwks = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'tests', 'fixtures', 'jwks.json')));
  let origin;
  let revision = contracts.definitions[0].configurationRevision;
  const stub = await startStubServer({
    'GET /.well-known/oauth-protected-resource': (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ resource: origin, authorization_servers: [origin],
        jwks_uri: `${origin}/.well-known/evidence/jwks.json`, bearer_methods_supported: ['header'] }));
    },
    'GET /.well-known/oauth-authorization-server': (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ issuer: origin, token_endpoint: `${origin}/token`,
        grant_types_supported: ['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange'],
        token_endpoint_auth_methods_supported: ['private_key_jwt'] }));
    },
    'GET /.well-known/evidence/jwks.json': (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/jwk-set+json' });
      res.end(JSON.stringify(jwks));
    },
    'POST /token': (_req, res, body) => {
      const form = new URLSearchParams(body.toString());
      assert.equal(form.get('grant_type'), 'urn:ietf:params:oauth:grant-type:token-exchange');
      assert.equal(form.get('resource'), 'urn:registry:evidence');
      assert.equal(form.get('scope'), 'evidence:invoke');
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ access_token: 'staff-token', token_type: 'Bearer', expires_in: 300,
        scope: 'evidence:invoke', issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' }));
    },
    'GET /v1/evidence-definitions': (req, res) => {
      assert.equal(req.headers.authorization, 'Bearer staff-token');
      published.definitions[0].configurationRevision = revision;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(published));
    },
    'POST /v1/evidence': (req, res) => {
      assert.equal(req.headers.authorization, 'Bearer staff-token');
      res.writeHead(503, { 'content-type': 'application/problem+json' });
      res.end(JSON.stringify({ type: 'about:blank', title: 'synthetic refusal', status: 503 }));
    },
  });
  origin = stub.baseUrl.slice(0, -1);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-profile-exchange-'));
  try {
    const profilePath = path.join(directory, 'client.json');
    fs.writeFileSync(profilePath, JSON.stringify({
      schema: 'registry.evidence-client-profile/v1', baseUrl: origin, clientId: 'profile-staff',
      privateKey: { source: 'environment', variable: 'UNUSED_PROFILE_EXCHANGE_KEY' },
      trust: { type: 'local-loopback-discovery' }, contracts: { type: 'published' },
      oauth: { resource: 'urn:registry:evidence', scopes: ['evidence:invoke'] },
      expected: { definitions: { 'farmer-status': {
        configurationRevision: revision, evidenceType: contracts.definitions[0].evidenceType,
        purpose: contracts.definitions[0].purpose, assuranceProfile: contracts.assuranceProfile,
        responseFormat: 'signed-jws',
      } } },
    }), { mode: 0o600 });
    const authorization = (resource) => ({ exchange: {
      client: { tokenEndpoint: `${origin}/token`, clientId: 'profile-staff', clientKey: key(),
        resource, scopes: ['evidence:invoke'] },
      context: { issuer: 'https://portal.example', subject: 'person-1', audience: origin,
        generation: 'verified-1', deadlineSeconds: Math.floor(Date.now() / 1000) + 120 },
      firstParty: { key: key(), attributes: { registry_actor_kind: 'human' } },
    } });
    class ApplicationClient extends EvidenceClient {}
    const mismatched = ApplicationClient.fromProfileWithAuthorization(profilePath, authorization('urn:wrong'));
    assert.ok(mismatched instanceof ApplicationClient);
    await assert.rejects(mismatched.request({ requirement: 'farmer-status',
      selectors: { 'farmer-number': 'F-123' } }),
    error => error instanceof EvidenceClientError && error.kind === 'configuration');
    assert.equal(stub.requests.filter(request => request.url === '/token').length, 0);

    const client = EvidenceClient.fromProfileWithAuthorization(profilePath, authorization('urn:registry:evidence'));
    await assert.rejects(client.request({ requirement: 'farmer-status',
      selectors: { 'farmer-number': 'F-123' } }), error => error instanceof EvidenceClientError);
    assert.equal(stub.requests.filter(request => request.url === '/token').length, 1);
    assert.equal(stub.requests.filter(request => request.url === '/v1/evidence').length, 1);

    revision = `sha256:${'2'.repeat(64)}`;
    const drifted = EvidenceClient.fromProfileWithAuthorization(profilePath, authorization('urn:registry:evidence'));
    await assert.rejects(drifted.request({ requirement: 'farmer-status',
      selectors: { 'farmer-number': 'F-123' } }),
    error => error instanceof EvidenceClientError && error.kind === 'configuration');
    assert.equal(stub.requests.filter(request => request.url === '/v1/evidence').length, 1,
      'definition drift must fail before the Evidence POST');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
    await stub.close();
  }
});
