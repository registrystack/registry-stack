'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const PRODUCTS = ['discovery', 'evidence', 'breg', 'casework', 'messaging', 'scheduling', 'render', 'coordinator'];

// Node synthesises the named exports an ESM consumer imports from this CommonJS
// entry point by statically scanning it for individual `exports.<name> =`
// assignments. A single `module.exports = { ... }` object literal defeats that
// scan and leaves `import { breg } from '@registrystack/client'` unresolvable,
// so the shape of the assignments is part of the public contract.
test('the public package exposes one namespace per product', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
  for (const product of PRODUCTS) {
    assert.match(source, new RegExp(`exports\\.${product} = require\\('./${product}/client'\\)`));
  }
});

test('product namespaces do not expose standalone loader diagnostics', () => {
  for (const product of PRODUCTS) {
    const source = fs.readFileSync(path.join(__dirname, '..', product, 'client.js'), 'utf8');
    assert.doesNotMatch(source, /__napiBindingTarget/);
  }
});

test('platform dependencies are bound only when the release package is packed', () => {
  const manifest = require('../package.json');
  assert.equal(manifest.optionalDependencies, undefined);
});

test('every platform package exports each public product addon', () => {
  const vm = require('node:vm');
  for (const platform of ['darwin-arm64', 'linux-arm64-gnu', 'linux-x64-gnu']) {
    const source = fs.readFileSync(path.join(__dirname, '..', 'npm', platform, 'index.js'), 'utf8');
    const module = { exports: {} };
    vm.runInNewContext(source, { module, require: filename => filename });
    assert.deepEqual(Object.keys(module.exports).sort(), [...PRODUCTS].sort());
    for (const product of PRODUCTS) {
      assert.equal(module.exports[product], `./${product}-client.${platform}.node`);
    }
  }
});
