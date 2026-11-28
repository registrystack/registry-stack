'use strict';

const assert = require('node:assert/strict');
const { createHmac } = require('node:crypto');
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
    // The fixed vector is dated 2026-08-30, outside any default window.
    callerEnforcedFreshness: true,
    ...overrides,
  };
}

// The fixed headers re-signed for `deliveryTime` with the vector's key.
function signedHeaders(deliveryTime) {
  const values = {
    ...headers(),
    // Rounded to the nearest second so a one-second window is not crossed by the fraction.
    'x-registry-delivery-time': new Date(Math.round(deliveryTime.getTime() / 1000) * 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, 'Z'),
  };
  const parts = [
    values['Ce-Specversion'], values['CE-ID'], values['ce-source'], values['ce-type'],
    values['ce-time'], values['ce-dataschema'], values['x-registry-event-generation'],
    values['x-registry-delivery-attempt'], values['x-registry-delivery-time'],
    'POST', '/hooks/registry', 'application/json', values['idempotency-key'], body,
  ].map((part) => Buffer.from(part));
  const signed = [Buffer.from('breg-webhook-signature-v1')];
  for (const part of parts) {
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(part.length));
    signed.push(length, part);
  }
  values['x-registry-signature'] = `v1=${createHmac('sha256', key)
    .update(Buffer.concat(signed)).digest('base64url')}`;
  return values;
}

function fresh(offsetSeconds, overrides = {}) {
  return input({
    headers: signedHeaders(new Date(Date.now() + offsetSeconds * 1000)),
    callerEnforcedFreshness: undefined,
    ...overrides,
  });
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

test('the default window is 300 seconds in both directions', () => {
  for (const offset of [0, -290, 290]) {
    assert.equal(verifyHookDelivery(fresh(offset)).attempt, '1');
  }
  for (const offset of [-310, 310]) {
    assert.throws(() => verifyHookDelivery(fresh(offset)), assertRefusal('stale-delivery'));
  }
});

test('an application that names no window refuses the old fixed vector', () => {
  const { callerEnforcedFreshness, ...bare } = input();
  assert.equal(callerEnforcedFreshness, true);
  assert.throws(() => verifyHookDelivery(bare), assertRefusal('stale-delivery'));
});

test('maxSkewSeconds replaces the default window', () => {
  assert.equal(verifyHookDelivery(fresh(-600, { maxSkewSeconds: 900 })).attempt, '1');
  assert.throws(
    () => verifyHookDelivery(fresh(-60, { maxSkewSeconds: 10 })),
    assertRefusal('stale-delivery'),
  );
  for (const edge of [1, 3600]) {
    assert.equal(verifyHookDelivery(fresh(0, { maxSkewSeconds: edge })).attempt, '1');
  }
});

test('callerEnforcedFreshness accepts an old delivery', () => {
  assert.equal(verifyHookDelivery(input()).attempt, '1');
});

test('refuses freshness options out of range, mistyped or combined', () => {
  for (const overrides of [
    { maxSkewSeconds: 0 },
    { maxSkewSeconds: 3601 },
    { maxSkewSeconds: -1 },
    { maxSkewSeconds: 1.5 },
    { maxSkewSeconds: Number.NaN },
    { maxSkewSeconds: '10' },
    { callerEnforcedFreshness: 'yes' },
    { maxSkewSeconds: 10, callerEnforcedFreshness: true },
  ]) {
    assert.throws(
      () => verifyHookDelivery(fresh(0, overrides)),
      (error) => error instanceof BaseRegistryClientError && error.kind === 'invalid-request',
      JSON.stringify(overrides),
    );
  }
});
