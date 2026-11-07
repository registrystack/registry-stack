'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { EvidenceClient, EvidenceClientError } = require('..');
const { startStubServer } = require('./helpers/stub-server');
const {
  generateSigningKey,
  signEvidence,
  requestSpec,
  holderPresentedEvidenceFor,
  evidenceFor,
} = require('./helpers/live-signing');

const DAY_MILLIS = 24 * 60 * 60 * 1000;

/** A stub that answers with a signed `holder-presented` assertion whose
 * credential was issued `credentialAgeMillis` before the observation. */
function holderPresentedRoute(spec, signingKey, credentialAgeMillis) {
  return (req, res, body) => {
    const requestBody = JSON.parse(body.toString('utf8'));
    const evidence = holderPresentedEvidenceFor(spec, requestBody.requestNonce, credentialAgeMillis);
    res.writeHead(200, { 'content-type': 'application/jose+json' });
    res.end(JSON.stringify(signEvidence(evidence, signingKey)));
  };
}

async function withClient(route, run) {
  const signingKey = generateSigningKey();
  const stub = await startStubServer({ 'POST /v1/evidence': route(signingKey) });
  try {
    const client = new EvidenceClient({
      baseUrl: stub.baseUrl,
      trustedJwks: signingKey.jwks,
      revokedKeyIds: [],
      token: { static: 'channel-token' },
    });
    await run(client);
  } finally {
    await stub.close();
  }
}

test('a source assertion states its channel and no presented credential', async () => {
  const spec = requestSpec();
  await withClient(
    (signingKey) => (req, res, body) => {
      const { requestNonce } = JSON.parse(body.toString('utf8'));
      res.writeHead(200, { 'content-type': 'application/jose+json' });
      res.end(JSON.stringify(signEvidence(evidenceFor(spec, requestNonce), signingKey)));
    },
    async (client) => {
      const verified = await client.requestAndVerify(client.prepare(spec));
      assert.equal(verified.evidence.channel, 'source');
      assert.equal('presentedCredential' in verified.evidence, false);
    },
  );
});

test('the default policy refuses a holder-presented assertion', async () => {
  const spec = requestSpec();
  await withClient(
    (signingKey) => holderPresentedRoute(spec, signingKey, DAY_MILLIS),
    async (client) => {
      await assert.rejects(client.requestAndVerify(client.prepare(spec)), (error) => {
        assert.ok(error instanceof EvidenceClientError);
        assert.equal(error.kind, 'verification');
        return true;
      });
    },
  );
});

test('a request accepting holder-presented exposes the presented credential', async () => {
  const spec = { ...requestSpec(), acceptedChannels: ['source', 'holder-presented'] };
  await withClient(
    (signingKey) => holderPresentedRoute(spec, signingKey, DAY_MILLIS),
    async (client) => {
      const prepared = client.prepare(spec);
      const accepted = prepared.policyDocument;
      assert.deepEqual(accepted.acceptedChannels, ['source', 'holder-presented']);
      const verified = await client.requestAndVerify(prepared);
      assert.equal(verified.evidence.channel, 'holder-presented');
      assert.deepEqual(verified.evidence.presentedCredential, {
        trustEntry: 'national-id',
        issuer: 'https://issuer.example',
        type: 'https://credentials.example/identity',
        issuedAt: verified.evidence.presentedCredential.issuedAt,
        subjectLink: 'attribute-match',
      });
    },
  );
});

test('a credential older than maximumCredentialAgeSeconds is refused', async () => {
  const spec = {
    ...requestSpec(),
    acceptedChannels: ['holder-presented'],
    maximumCredentialAgeSeconds: 60 * 60,
  };
  await withClient(
    (signingKey) => holderPresentedRoute(spec, signingKey, DAY_MILLIS),
    async (client) => {
      await assert.rejects(client.requestAndVerify(client.prepare(spec)), (error) => {
        assert.equal(error.kind, 'verification');
        return true;
      });
    },
  );
  await withClient(
    (signingKey) => holderPresentedRoute(spec, signingKey, 30 * 60 * 1000),
    async (client) => {
      const verified = await client.requestAndVerify(client.prepare(spec));
      assert.equal(verified.evidence.channel, 'holder-presented');
    },
  );
});

test('a channel policy outside the contract or the shape is refused before any exchange', () => {
  const client = new EvidenceClient({
    baseUrl: 'http://127.0.0.1:9',
    trustedJwks: generateSigningKey().jwks,
    revokedKeyIds: [],
    token: { static: 'channel-token' },
  });
  for (const members of [
    { acceptedChannels: [] },
    { acceptedChannels: ['source', 'source'] },
    { acceptedChannels: ['wallet'] },
    { acceptedChannels: 'source' },
    { maximumCredentialAgeSeconds: 0 },
    { maximumCredentialAgeSeconds: -1 },
  ]) {
    assert.throws(
      () => client.prepare({ ...requestSpec(), ...members }),
      (error) => error instanceof EvidenceClientError && error.kind === 'configuration',
      JSON.stringify(members),
    );
  }
});
