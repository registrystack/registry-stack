'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const { EvidenceClient, EvidenceClientError } = require('..');

function validConfig(overrides = {}) {
  return {
    baseUrl: 'https://evidence.example.org',
    trustedJwks: {
      keys: [
        {
          kty: 'EC',
          crv: 'P-256',
          kid: '_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo',
          alg: 'ES256',
          x: '3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4',
          y: 'GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU',
        },
      ],
    },
    revokedKeyIds: [],
    token: { static: 'construction-test-token' },
    ...overrides,
  };
}

/** Every construction refusal in this file is the Rust configuration
 * failure, crossing as an `EvidenceClientError` with `kind: "configuration"`
 * and a human-readable `message` (not JSON a caller must parse). */
function assertConfigurationRefusal(build) {
  assert.throws(build, (error) => {
    assert.ok(error instanceof EvidenceClientError);
    assert.equal(error.kind, 'configuration');
    assert.doesNotMatch(error.message, /^\{/, 'message must be prose, not a JSON envelope');
    return true;
  });
}

test('a non-HTTPS, non-loopback base URL is refused', () => {
  assertConfigurationRefusal(
    () => new EvidenceClient(validConfig({ baseUrl: 'http://evidence.example.org' })),
  );
});

test('an empty trusted key set is refused', () => {
  assertConfigurationRefusal(() => new EvidenceClient(validConfig({ trustedJwks: { keys: [] } })));
});

test('the current revoked key list is required', () => {
  const config = validConfig();
  delete config.revokedKeyIds;
  assertConfigurationRefusal(() => new EvidenceClient(config));
});

test('a malformed revoked key identifier is refused', () => {
  assertConfigurationRefusal(() => new EvidenceClient(validConfig({ revokedKeyIds: ['not-a-thumbprint'] })));
});

test('a base URL with an empty path segment is refused', () => {
  assertConfigurationRefusal(
    () => new EvidenceClient(validConfig({ baseUrl: 'https://evidence.example.org/prefix//suffix' })),
  );
});

test('fromProfile returns the public wrapper and preserves consumer subclasses', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-client-node-profile-'));
  try {
    const profilePath = path.join(directory, 'client.json');
    fs.writeFileSync(
      profilePath,
      JSON.stringify({
        schema: 'registry.evidence-client-profile/v1',
        baseUrl: 'https://evidence.example.org',
        clientId: 'node-profile-test',
        privateKey: { source: 'environment', variable: 'UNUSED_PRIVATE_JWK' },
        trust: { type: 'https-discovery' },
        contracts: { type: 'published' },
        verification: {
          maximumAssertionLifetimeSeconds: 300,
          clockSkewSeconds: 30,
        },
      }),
      { mode: 0o600 },
    );
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    const privateJwk = privateKey.export({ format: 'jwk' });
    const thumbprintInput = JSON.stringify({
      crv: privateJwk.crv,
      kty: privateJwk.kty,
      x: privateJwk.x,
    });
    privateJwk.alg = 'EdDSA';
    privateJwk.kid = crypto.createHash('sha256').update(thumbprintInput).digest('base64url');

    const client = EvidenceClient.fromProfile(profilePath, privateJwk);
    assert.ok(client instanceof EvidenceClient);
    assert.throws(
      () => client.request({ requirement: 'adult-status' }),
      (error) => error instanceof EvidenceClientError && error.kind === 'configuration',
    );

    class ApplicationEvidenceClient extends EvidenceClient {}
    const applicationClient = ApplicationEvidenceClient.fromProfile(profilePath, privateJwk);
    assert.ok(applicationClient instanceof ApplicationEvidenceClient);
    assert.ok(applicationClient instanceof EvidenceClient);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
