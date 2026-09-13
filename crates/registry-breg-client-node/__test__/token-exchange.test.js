'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { test } = require('node:test');
const { PrivateKeyJwt, BaseRegistryClientError } = require('..');

test('exchange preserves service cache and sends exact independent grant requests', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    const form = new URLSearchParams(body);
    requests.push(form);
    const subject = form.get('subject_token');
    response.writeHead(200, {'content-type':'application/json', 'cache-control':'no-store', pragma:'no-cache'});
    response.end(JSON.stringify({access_token: subject || 'service-token', token_type:'Bearer',
      expires_in:300, scope:'records:get', issued_token_type:'urn:ietf:params:oauth:token-type:access_token'}));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const clientKey = crypto.generateKeyPairSync('ec', {namedCurve:'prime256v1'}).privateKey.export({format:'jwk'});
    Object.assign(clientKey, {alg:'ES256', kid:'synthetic-test'});
    const config = {tokenEndpoint:`http://127.0.0.1:${server.address().port}/token`, clientId:'test-client',
      clientKey, resource:'urn:test:resource', scopes:['records:get']};
    const provider = new PrivateKeyJwt(config);
    assert.equal(await provider.bearerToken(), 'service-token');
    assert.deepEqual(await Promise.all([provider.exchange('first-subject'), provider.exchange('second-subject')]),
      ['first-subject', 'second-subject']);
    assert.equal(await provider.bearerToken(), 'service-token');
    assert.equal(requests.length, 3);
    for (const form of requests.slice(1)) {
      assert.equal(form.get('grant_type'), 'urn:ietf:params:oauth:grant-type:token-exchange');
      assert.equal(form.get('subject_token_type'), 'urn:ietf:params:oauth:token-type:jwt');
      assert.equal(form.get('resource'), 'urn:test:resource');
      assert.equal(form.get('scope'), 'records:get');
      assert.equal(form.has('client_secret'), false);
    }
    assert.notEqual(requests[1].get('client_assertion'), requests[2].get('client_assertion'));
    await assert.rejects(provider.exchange('bad\nsubject'), error => error instanceof BaseRegistryClientError && !error.message.includes('bad'));
    await assert.rejects(new PrivateKeyJwt({...config, resource:null}).exchange('subject'));
    assert.equal(requests.length, 3);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('provider configuration rejects executable properties without invoking them', () => {
  let accessed = false;
  const config = { get clientKey() { accessed = true; throw new Error('secret-canary'); } };
  assert.throws(() => new PrivateKeyJwt(config), error => error instanceof BaseRegistryClientError && !error.message.includes('secret-canary'));
  assert.equal(accessed, false);
});
