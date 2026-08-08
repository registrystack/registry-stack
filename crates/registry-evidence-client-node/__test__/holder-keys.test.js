'use strict';

// Holder keys as a JS caller supplies them, and the batch envelope a request
// presenting several of them can be answered with. Neither needs a server:
// `prepare` performs no I/O, and `SdJwtVcBatchResponse.parse` reads bytes a
// caller already holds.

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { EvidenceClient, EvidenceClientError, SdJwtVcBatchResponse } = require('..');
const { requestSpec } = require('./helpers/live-signing');

const DUMMY_JWKS = {
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
};

/** Two genuine, on-curve P-256 public points, so an accepted key here is one
 * the wrapped client's own acceptability check also accepts. */
const HOLDER_KEYS = [
  {
    kty: 'EC',
    crv: 'P-256',
    x: 'axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY',
    y: 'T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU',
    alg: 'ES256',
    kid: 'holder-key-0',
  },
  {
    kty: 'EC',
    crv: 'P-256',
    x: 'fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg',
    y: 'B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E',
    alg: 'ES256',
    kid: 'holder-key-1',
  },
];

// The envelope wire shape, stated here rather than reached for: the wrapped
// crate declares `schema` and `type` privately, exactly as `live-signing.js`
// re-states the signed-response constants it needs.
const SD_JWT_VC_BATCH_SCHEMA_V1 = 'registry.sd-jwt-vc-batch-envelope/v1';
const SD_JWT_VC_BATCH_ENVELOPE_TYPE = 'SdJwtVcBatchEnvelope';

function client() {
  return new EvidenceClient({
    baseUrl: 'https://evidence.example.org',
    trustedJwks: DUMMY_JWKS,
    revokedKeyIds: [],
    token: { static: 'holder-keys-test-token' },
  });
}

function envelope(credentials) {
  return Buffer.from(
    JSON.stringify({
      schema: SD_JWT_VC_BATCH_SCHEMA_V1,
      type: SD_JWT_VC_BATCH_ENVELOPE_TYPE,
      credentials,
    }),
  );
}

test('a request may present holder keys, and they never reach the closed policy', () => {
  const prepared = client().prepare({ ...requestSpec(), holderKeys: HOLDER_KEYS });
  const policy = JSON.stringify(prepared.policyDocument);
  for (const key of HOLDER_KEYS) {
    assert.ok(!policy.includes(key.x), 'a holder key reached the verification policy');
    assert.ok(!policy.includes(key.kid), 'a holder key identifier reached the verification policy');
  }
});

test('presenting no holder key is the request this package has always sent', () => {
  const spec = requestSpec();
  assert.equal(spec.holderKeys, undefined);
  assert.ok(client().prepare(spec));
  assert.ok(client().prepare({ ...spec, holderKeys: [] }));
  assert.ok(client().prepare({ ...spec, holderKeys: null }));
});

test('a holder key carrying a private key half is refused, and the half is never echoed', () => {
  // A caller that pasted a whole key pair rather than its public half. The
  // refusal has to say that specifically: an "unknown member" refusal reads
  // as a typo, and the caller would not learn it had just handed its private
  // key to an outbound request.
  const PRIVATE_CANARY = 'secret-private-scalar-value';
  for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth']) {
    const key = { ...HOLDER_KEYS[0], [member]: PRIVATE_CANARY };
    assert.throws(
      () => client().prepare({ ...requestSpec(), holderKeys: [key] }),
      (error) => {
        assert.ok(error instanceof EvidenceClientError);
        assert.equal(error.kind, 'configuration');
        assert.match(error.message, /private key material/);
        assert.match(error.message, new RegExp(`\`${member}\``));
        assert.ok(!error.message.includes(PRIVATE_CANARY), 'the private half leaked into the message');
        assert.ok(!error.stack.includes(PRIVATE_CANARY), 'the private half leaked into the stack');
        return true;
      },
    );
  }
});

test('a holder key outside the public JWK shape is refused without echoing it', () => {
  const CANARY = 'secret-canary-value';
  for (const key of [
    { ...HOLDER_KEYS[0], use: CANARY },
    { kty: CANARY },
    CANARY,
    null,
  ]) {
    assert.throws(
      () => client().prepare({ ...requestSpec(), holderKeys: [key] }),
      (error) => {
        assert.ok(error instanceof EvidenceClientError);
        assert.equal(error.kind, 'configuration');
        assert.ok(!error.message.includes(CANARY), `leaked in: ${error.message}`);
        return true;
      },
    );
  }
});

test('a batch envelope answers holder key i with credential i', () => {
  const parsed = new SdJwtVcBatchResponse(envelope(['credential-for-key-0', 'credential-for-key-1']));
  assert.ok(parsed instanceof SdJwtVcBatchResponse);
  assert.equal(parsed.count, 2);
  assert.deepEqual(parsed.credentials, ['credential-for-key-0', 'credential-for-key-1']);
  assert.equal(parsed.credentialForHolderKey(0), 'credential-for-key-0');
  assert.equal(parsed.credentialForHolderKey(1), 'credential-for-key-1');
  assert.equal(parsed.credentialForHolderKey(2), null);
});

test('a body that is not this envelope is refused as a protocol failure', () => {
  for (const body of [
    Buffer.from('not json'),
    Buffer.from(JSON.stringify({ schema: 'something-else', type: SD_JWT_VC_BATCH_ENVELOPE_TYPE, credentials: ['a'] })),
    envelope([]),
    envelope(['']),
  ]) {
    assert.throws(
      () => new SdJwtVcBatchResponse(body),
      (error) => {
        assert.ok(error instanceof EvidenceClientError);
        assert.equal(error.kind, 'protocol');
        assert.equal(error.status, 200);
        return true;
      },
    );
  }
});
