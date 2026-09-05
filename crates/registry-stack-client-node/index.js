'use strict';

// One assignment per namespace, never a `module.exports` object literal: Node
// scans this file for these statements to synthesise the named exports an ESM
// consumer imports, and `require()` sees the same four properties either way.
exports.discovery = require('./discovery/client');
exports.evidence = require('./evidence/client');
exports.relay = require('./relay/client');
exports.breg = require('./breg/client');
