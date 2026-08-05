'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { EvidenceClient } = require('../index.js');

function validConfig(overrides = {}) {
  return {
    baseUrl: 'https://evidence.example.org',
    trustedJwks: {
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          kid: 'construction-test-key',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
      ],
    },
    token: { static: 'construction-test-token' },
    ...overrides,
  };
}

/** Every construction refusal in this file is the Rust configuration
 * failure, crossing as a thrown error whose `message` is the stable JSON
 * envelope `kind: "configuration"`. */
function assertConfigurationRefusal(build) {
  assert.throws(build, (error) => {
    const mapped = JSON.parse(error.message);
    assert.equal(mapped.kind, 'configuration');
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

test('a base URL with an empty path segment is refused', () => {
  assertConfigurationRefusal(
    () => new EvidenceClient(validConfig({ baseUrl: 'https://evidence.example.org/prefix//suffix' })),
  );
});
