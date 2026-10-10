#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const client = require('@registrystack/client');
const { breg, casework, discovery, evidence } = client;

assert.strictEqual(typeof breg.BaseRegistryClient, 'function');
assert.strictEqual(typeof breg.verifyWebhookDelivery, 'function');
assert.strictEqual(typeof discovery.DiscoveryClient, 'function');
assert.strictEqual(typeof evidence.EvidenceClient, 'function');
assert.strictEqual(typeof casework.CaseworkClient, 'function');

assert.ok(new breg.BaseRegistryClient({
  baseUrl: 'https://registry.invalid',
  authorization: { static: 'placeholder-token' },
}));
assert.ok(new casework.CaseworkClient({ baseUrl: 'https://casework.invalid' }));

// Messaging joins published packages in v0.38.0. Older release smokes retain
// their original namespaces; source CI also exercises it before admission.
if (Object.hasOwn(client, 'messaging')) {
  assert.strictEqual(typeof client.messaging.MessagingClient, 'function');
  assert.ok(new client.messaging.MessagingClient({ baseUrl: 'https://messaging.invalid' }));
}

// Scheduling joins published packages in v0.40.0, under the same rule.
if (Object.hasOwn(client, 'scheduling')) {
  assert.strictEqual(typeof client.scheduling.SchedulingClient, 'function');
  assert.ok(new client.scheduling.SchedulingClient({ baseUrl: 'https://scheduling.invalid' }));
}

// Coordinator is included only in explicit Coordinator-enabled candidates.
if (Object.hasOwn(client, 'coordinator')) {
  assert.strictEqual(typeof client.coordinator.CoordinatorClient, 'function');
  assert.ok(new client.coordinator.CoordinatorClient({ baseUrl: 'https://coordinator.invalid' }));
}

console.log('Unified Node Registry client package smoke passed');
