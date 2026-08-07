'use strict';

const assert = require('node:assert/strict');
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
