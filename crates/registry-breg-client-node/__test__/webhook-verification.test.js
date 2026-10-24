'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const {
  BaseRegistryClientError,
  verifyHookDelivery,
} = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const key = Buffer.from('webhook-delivery-signing-key-0123456789abcdef');
const body = Buffer.from('{"entity":"case","values":{"label":"value"}}');
const signature = 'v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM';

function headers() {
  return {
    'Ce-Specversion': '1.0',
    'CE-ID': '00000000-0000-4000-8000-000000000001',
    'ce-source': 'urn:registrystack:registry:example:instance:primary',
    'ce-type': 'case-created-v1',
    'ce-time': '2026-08-30T00:00:00Z',
    'ce-dataschema': 'urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa',
    'x-registry-event-generation': '1',
    'x-registry-delivery-attempt': '1',
    'x-registry-delivery-time': '2026-08-30T00:00:01Z',
    'idempotency-key': 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'content-type': 'application/json',
    'x-registry-signature': signature,
  };
}

function input(overrides = {}) {
  return {
    method: 'POST',
    path: '/hooks/registry',
    headers: headers(),
    body,
    key,
    ...overrides,
  };
}

test('shared language vectors authenticate exact RFC3339 fractions', () => {
  const vectors = require('../../registry-platform-crypto/tests/fixtures/delivery-signatures.json');
  for (const vector of vectors) {
    const exact = { ...headers(), 'x-registry-delivery-time': vector.deliveryTime, 'x-registry-signature': vector.signature };
    if (vector.valid) {
      assert.equal(verifyHookDelivery(input({ headers: exact })).deliveryTime, vector.deliveryTime);
      assert.throws(() => verifyHookDelivery(input({ headers: { ...exact, 'x-registry-delivery-time': '2026-08-30T00:00:01.0000Z' } })), assertRefusal('signature-mismatch'));
    } else {
      assert.throws(() => verifyHookDelivery(input({ headers: exact })), assertRefusal('invalid-delivery-time'));
    }
  }
});

function assertRefusal(code) {
  return (error) => error instanceof BaseRegistryClientError
    && error.kind === 'hook-verification'
    && error.code === code
    && !error.message.includes(signature)
    && !error.message.includes(key.toString());
}

function assertExactRefusal(code, message) {
  return (error) => assertRefusal(code)(error) && error.message === message;
}

test('accepts the fixed BReg signing vector and returns exact delivery values', () => {
  const verified = verifyHookDelivery(input());

  assert.deepEqual(verified, {
    id: '00000000-0000-4000-8000-000000000001',
    source: 'urn:registrystack:registry:example:instance:primary',
    type: 'case-created-v1',
    time: '2026-08-30T00:00:00Z',
    dataschema: 'urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa',
    generation: '1',
    attempt: '1',
    deliveryTime: '2026-08-30T00:00:01Z',
    idempotencyKey: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    body,
  });
  assert.ok(Buffer.isBuffer(verified.body));
});

test('refuses a tampered signed header', () => {
  assert.throws(() => verifyHookDelivery(input({
    headers: { ...headers(), 'ce-type': 'case-patched-v1' },
  })), assertRefusal('signature-mismatch'));
});

test('refuses a tampered body', () => {
  assert.throws(
    () => verifyHookDelivery(input({ body: Buffer.from('{"tampered":true}') })),
    assertRefusal('signature-mismatch'),
  );
});

test('refuses the wrong key', () => {
  assert.throws(
    () => verifyHookDelivery(input({ key: Buffer.alloc(32, 0x6b) })),
    assertRefusal('signature-mismatch'),
  );
});

test('refuses a truncated signature', () => {
  assert.throws(() => verifyHookDelivery(input({
    headers: { ...headers(), 'x-registry-signature': 'v1=truncated' },
  })), assertRefusal('malformed-signature'));
});

test('reports an invalid delivery time with its fix', () => {
  const vector = require('../../registry-platform-crypto/tests/fixtures/delivery-signatures.json').find(value => !value.valid);
  assert.throws(() => verifyHookDelivery(input({
    headers: { ...headers(), 'x-registry-delivery-time': vector.deliveryTime, 'x-registry-signature': vector.signature },
  })), assertExactRefusal(
    'invalid-delivery-time',
    'the Base Registry Engine hook delivery time is invalid; check the signed delivery time and sender clock',
  ));
});

test('reports a duplicate signed header with its fix', () => {
  assert.throws(() => verifyHookDelivery(input({
    headers: { ...headers(), 'CE-TYPE': 'case-created-v1' },
  })), assertExactRefusal(
    'duplicate-header',
    'a Base Registry Engine hook header is repeated; remove duplicate signed headers',
  ));
});

test('reports an oversized body with its fix', () => {
  assert.throws(
    () => verifyHookDelivery(input({ body: Buffer.alloc(1_048_577, 0x78) })),
    assertExactRefusal(
      'body-too-large',
      'the Base Registry Engine hook body exceeds the Version 1 limit; reduce the body size',
    ),
  );
});

test('reports an invalid key with its fix', () => {
  assert.throws(
    () => verifyHookDelivery(input({ key: Buffer.from('short-key') })),
    assertExactRefusal(
      'invalid-key',
      'the Base Registry Engine hook verification key is too short; configure a key of at least 32 bytes',
    ),
  );
});

test('refuses an unknown signature version', () => {
  assert.throws(() => verifyHookDelivery(input({
    headers: { ...headers(), 'x-registry-signature': signature.replace('v1=', 'v2=') },
  })), assertRefusal('unsupported-version'));
});

test('refuses a missing signed header', () => {
  const deliveryHeaders = headers();
  delete deliveryHeaders['ce-time'];
  assert.throws(
    () => verifyHookDelivery(input({ headers: deliveryHeaders })),
    assertRefusal('missing-header'),
  );
});

test('refuses shared backing stores before native verification', () => {
  for (const [field, value] of [['body', body], ['key', key]]) {
    const shared = Buffer.from(new SharedArrayBuffer(value.length));
    value.copy(shared);
    assert.throws(
      () => verifyHookDelivery(input({ [field]: shared })),
      (error) => error instanceof BaseRegistryClientError && error.kind === 'invalid-request',
    );
  }
});
