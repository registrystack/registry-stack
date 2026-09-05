#!/usr/bin/env node
// Offline construction smoke for the unified Node client package, imported the
// way an ESM application imports it. The CommonJS smoke beside this file covers
// `require()`. Both run against a packed tarball installed into a throwaway
// project, never against a checkout.

import assert from 'node:assert';
import { breg, discovery, evidence, relay } from '@registrystack/client';

assert.strictEqual(typeof breg.BaseRegistryClient, 'function');
assert.strictEqual(typeof discovery.DiscoveryClient, 'function');
assert.strictEqual(typeof evidence.EvidenceClient, 'function');
assert.strictEqual(typeof relay.RelayClient, 'function');

// A published verification key from the Evidence client construction tests. An
// Evidence client refuses to exist without a usable trust anchor, so the smoke
// has to carry one to prove construction offline.
const trustedJwks = {
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

assert.ok(new breg.BaseRegistryClient({
  baseUrl: 'https://registry.invalid',
  authorization: { static: 'placeholder-token' },
}));
assert.ok(new discovery.DiscoveryClient({
  baseUrl: 'https://discovery.invalid',
}));
assert.ok(new evidence.EvidenceClient({
  baseUrl: 'https://evidence.invalid',
  trustedJwks,
  revokedKeyIds: [],
  token: { static: 'placeholder-token' },
}));
assert.ok(new relay.RelayClient({
  baseUrl: 'https://relay.invalid',
  authorization: { static: 'placeholder-token' },
}));

console.log('Unified Node Registry client package ESM smoke passed');
