'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const pkg = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const { BaseRegistryClient, BRegMetadata } = pkg;
const inventory = require('../../../products/breg/contracts/client-capabilities.json');

// A capability entry point is a client method, a metadata method, or a
// package-level function.
test('every inventoried Node capability is a callable public entry point', () => {
  for (const capability of inventory.capabilities) {
    for (const method of capability.node) {
      const callable = [BaseRegistryClient.prototype, BRegMetadata.prototype, pkg]
        .some((owner) => typeof owner[method] === 'function');
      assert.equal(
        callable,
        true,
        `${capability.id} requires a callable ${method} on the client, the metadata class or the package`,
      );
    }
  }
});
