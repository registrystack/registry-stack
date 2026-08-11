#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const { RelayClient } = require('@registrystack/relay-client');

// The reserved host and placeholder bearer make a network regression fail
// closed if a future constructor accidentally performs I/O.
assert.strictEqual(typeof RelayClient, 'function');
const client = new RelayClient({
  baseUrl: 'https://relay.invalid',
  authorization: { static: 'placeholder-token' },
});
assert.ok(client);

console.log('Node Relay client package smoke passed');
