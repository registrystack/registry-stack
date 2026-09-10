'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { BaseRegistryClient } = process.env.BREG_CLIENT_PACKAGE
  ? require(process.env.BREG_CLIENT_PACKAGE).breg : require('..');
const inventory = require('../../../products/breg/contracts/client-capabilities.json');

test('every inventoried Node capability is a callable public client method', () => {
  for (const capability of inventory.capabilities) {
    for (const method of capability.node) {
      assert.equal(
        typeof BaseRegistryClient.prototype[method],
        'function',
        `${capability.id} requires BaseRegistryClient.prototype.${method}`,
      );
    }
  }
});
