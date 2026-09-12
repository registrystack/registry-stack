'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const {
  BaseRegistryClientError,
  verifyWebhookDelivery,
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

function assertRefusal(code) {
  return (error) => error instanceof BaseRegistryClientError
    && error.kind === 'webhook_verification'
    && error.code === code
    && !error.message.includes(signature)
    && !error.message.includes(key.toString());
}

test('accepts the fixed BReg signing vector and returns exact delivery values', () => {
  const verified = verifyWebhookDelivery(input());

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
  assert.throws(() => verifyWebhookDelivery(input({
    headers: { ...headers(), 'ce-type': 'case-patched-v1' },
  })), assertRefusal('signature_mismatch'));
});

test('refuses a tampered body', () => {
  assert.throws(
    () => verifyWebhookDelivery(input({ body: Buffer.from('{"tampered":true}') })),
    assertRefusal('signature_mismatch'),
  );
});

test('refuses the wrong key', () => {
  assert.throws(
    () => verifyWebhookDelivery(input({ key: Buffer.alloc(32, 0x6b) })),
    assertRefusal('signature_mismatch'),
  );
});

test('refuses a truncated signature', () => {
  assert.throws(() => verifyWebhookDelivery(input({
    headers: { ...headers(), 'x-registry-signature': 'v1=truncated' },
  })), assertRefusal('malformed_signature'));
});

test('refuses an unknown signature version', () => {
  assert.throws(() => verifyWebhookDelivery(input({
    headers: { ...headers(), 'x-registry-signature': signature.replace('v1=', 'v2=') },
  })), assertRefusal('unsupported_version'));
});

test('refuses a missing signed header', () => {
  const deliveryHeaders = headers();
  delete deliveryHeaders['ce-time'];
  assert.throws(
    () => verifyWebhookDelivery(input({ headers: deliveryHeaders })),
    assertRefusal('missing_header'),
  );
});

test('refuses shared backing stores before native verification', () => {
  for (const [field, value] of [['body', body], ['key', key]]) {
    const shared = Buffer.from(new SharedArrayBuffer(value.length));
    value.copy(shared);
    assert.throws(
      () => verifyWebhookDelivery(input({ [field]: shared })),
      (error) => error instanceof BaseRegistryClientError && error.kind === 'invalid_request',
    );
  }
});
