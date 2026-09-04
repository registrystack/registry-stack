'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

test('the public package exposes one namespace per product', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
  for (const product of ['discovery', 'evidence', 'relay', 'breg']) {
    assert.match(source, new RegExp(`${product}: require\\('./${product}/client'\\)`));
  }
});

test('platform dependencies are bound only when the release package is packed', () => {
  const manifest = require('../package.json');
  assert.equal(manifest.optionalDependencies, undefined);
});
