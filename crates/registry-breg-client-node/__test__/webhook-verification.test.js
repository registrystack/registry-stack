'use strict';

const assert = require('node:assert/strict');
const { createHmac } = require('node:crypto');
const { test } = require('node:test');

const {
  BaseRegistryClientError,
  verifyHookDelivery,
} = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');

const key = Buffer.from('0123456789abcdef0123456789abcdef');
const previousKey = Buffer.from('abcdef0123456789abcdef0123456789');
const body = Buffer.from('{"causation":{"hop":0,"root":"00000000-0000-4000-8000-000000000001"},"data":{},"dataschema":"https://example.test/schema","id":"00000000-0000-4000-8000-000000000001","source":"/products/breg/deployments/example","subject":{"recordReference":"breg/case/42","recordRevision":7},"time":"2026-08-30T00:00:00.123Z","type":"case-created-v1"}');
const signature = 'v1,NELq97rzqnAqQUxh1eiskBB3oOl+4FsqaI1ZV/lAqQY=';
const { id, source, type, time, dataschema } = JSON.parse(body);
const timestamp = '1788048001';

function signedHeaders(stamp = timestamp, signingKey = key, eventId = id, payload = body) {
  const digest = createHmac('sha256', signingKey).update(`${eventId}.${stamp}.`)
    .update(payload).digest('base64');
  return {
    'Content-Type': 'application/json',
    'Webhook-ID': eventId,
    'webhook-timestamp': String(stamp),
    'webhook-signature': `v1,${digest}`,
  };
}

function input(overrides = {}) {
  return { headers: signedHeaders(), body, key, callerEnforcedFreshness: true, ...overrides };
}

function fresh(offset, overrides = {}) {
  return input({
    headers: signedHeaders(Math.floor(Date.now() / 1000) + offset),
    callerEnforcedFreshness: undefined,
    ...overrides,
  });
}

function assertRefusal(code) {
  return (error) => error instanceof BaseRegistryClientError
    && error.kind === 'hook-verification' && error.code === code
    && !error.message.includes(signature) && !error.message.includes(key.toString());
}

test('accepts the fixed standard webhook envelope vector', () => {
  assert.equal(signedHeaders()['webhook-signature'], signature);
  assert.deepEqual(verifyHookDelivery(input()), { id, timestamp, source, type, time, dataschema, body });
});

test('checks the shared signature vectors without a wall clock', () => {
  const vectors = require('../../registry-platform-crypto/tests/fixtures/standard-webhooks.json');
  for (const vector of vectors) {
    const { id, timestamp, signature, body, keyHex, previousKeyHex, expected, keyPolicy } = vector;
    // Freshness is exercised separately with the live clock.
    const code = keyPolicy === 'below-minimum' ? 'invalid-key'
      : ['accepted', 'stale-delivery'].includes(expected) ? 'invalid-envelope' : expected;
    assert.throws(() => verifyHookDelivery(input({
      headers: { 'content-type': 'application/json', 'webhook-id': id,
        'webhook-timestamp': timestamp, 'webhook-signature': signature },
      body: Buffer.from(body), key: Buffer.from(keyHex, 'hex'),
      previousKey: previousKeyHex ? Buffer.from(previousKeyHex, 'hex') : undefined,
    })), assertRefusal(code), vector.name);
  }
});

test('accepts a signature made with the previous key', () => {
  const headers = signedHeaders(timestamp, previousKey);
  assert.throws(() => verifyHookDelivery(input({ headers })), assertRefusal('signature-mismatch'));
  assert.equal(verifyHookDelivery(input({ headers, previousKey })).id, id);
});

test('refuses mismatched identity and invalid headers or bytes', () => {
  for (const [code, overrides] of [
    ['id-mismatch', { headers: signedHeaders(timestamp, key, '00000000-0000-4000-8000-000000000002') }],
    ['duplicate-header', { headers: { ...signedHeaders(), 'webhook-id': id } }],
    ['missing-header', { headers: {} }],
    ['invalid-content-type', { headers: { ...signedHeaders(), 'Content-Type': 'text/plain' } }],
    ['signature-mismatch', { body: Buffer.from('{}') }],
    ['body-too-large', { body: Buffer.alloc(1_048_577) }],
  ]) {
    assert.throws(() => verifyHookDelivery(input(overrides)), assertRefusal(code));
  }
});

test('names invalid key lengths and kinds without revealing their bytes', () => {
  for (const [overrides, message] of [
    [{ key: Buffer.alloc(31, 120) }, 'The current hook key is 31 bytes and must contain 32 to 64 exact bytes.'],
    [{ key: Buffer.from('x'.repeat(64) + '\n') }, 'The current hook key is 65 bytes including a trailing newline and must contain 32 to 64 exact bytes.'],
    [{ key: Buffer.from('whsec_synthetic_key_text_for_test') }, 'The current hook key starts with whsec_ and must be supplied as exact key bytes.'],
    [{ previousKey: key }, 'The previous hook key equals the current key. Pass the key the sender used before rotation, or omit the previous key.'],
  ]) {
    assert.throws(() => verifyHookDelivery(input(overrides)),
      (error) => assertRefusal('invalid-key')(error) && error.message === message);
  }
});

test('refuses shared backing stores before native verification', () => {
  for (const [field, value] of [['body', body], ['key', key], ['previousKey', previousKey]]) {
    const shared = Buffer.from(new SharedArrayBuffer(value.length));
    value.copy(shared);
    assert.throws(
      () => verifyHookDelivery(input({ [field]: shared })),
      (error) => error instanceof BaseRegistryClientError && error.kind === 'invalid-request',
    );
  }
});

test('the default window is 300 seconds in both directions', () => {
  for (const offset of [0, -295, 295]) {
    assert.equal(verifyHookDelivery(fresh(offset)).id, id);
  }
  for (const offset of [-305, 305]) {
    assert.throws(() => verifyHookDelivery(fresh(offset)), assertRefusal('stale-delivery'));
  }
});

test('an application that names no window refuses the old fixed vector', () => {
  const { callerEnforcedFreshness, ...bare } = input();
  assert.equal(callerEnforcedFreshness, true);
  assert.throws(() => verifyHookDelivery(bare), assertRefusal('stale-delivery'));
});

test('maxSkewSeconds replaces the default window', () => {
  assert.equal(verifyHookDelivery(fresh(-600, { maxSkewSeconds: 900 })).id, id);
  assert.throws(
    () => verifyHookDelivery(fresh(-60, { maxSkewSeconds: 10 })),
    assertRefusal('stale-delivery'),
  );
  for (const edge of [1, 3600]) {
    assert.equal(verifyHookDelivery(fresh(0, { maxSkewSeconds: edge })).id, id);
  }
});

test('callerEnforcedFreshness accepts an old delivery', () => {
  assert.equal(verifyHookDelivery(input()).id, id);
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
