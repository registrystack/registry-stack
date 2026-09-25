#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const { breg, casework, discovery, evidence, messaging, relay } = require('@registrystack/client');

assert.strictEqual(typeof breg.BaseRegistryClient, 'function');
assert.strictEqual(typeof breg.verifyWebhookDelivery, 'function');
assert.strictEqual(typeof discovery.DiscoveryClient, 'function');
assert.strictEqual(typeof evidence.EvidenceClient, 'function');
assert.strictEqual(typeof relay.RelayClient, 'function');
assert.strictEqual(typeof casework.CaseworkClient, 'function');
assert.strictEqual(typeof messaging.MessagingClient, 'function');

assert.ok(new breg.BaseRegistryClient({
  baseUrl: 'https://registry.invalid',
  authorization: { static: 'placeholder-token' },
}));
assert.ok(new relay.RelayClient({
  baseUrl: 'https://relay.invalid',
  authorization: { static: 'placeholder-token' },
}));
assert.ok(new casework.CaseworkClient({ baseUrl: 'https://casework.invalid' }));
assert.ok(new messaging.MessagingClient({ baseUrl: 'https://messaging.invalid' }));

console.log('Unified Node Registry client package smoke passed');
