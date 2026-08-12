'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const wrapper = require('..');
const native = require('../index.js');

const METHODS = [
  'health',
  'ready',
  'openapi',
  'serviceMetadata',
  'resources',
  'continueResources',
  'resource',
  'listRecords',
  'continueListRecords',
  'readRecord',
  'lookup',
  'search',
  'continueSearch',
  'artifact',
  'sdmxData',
  'sdmxStructure',
];

test('the error wrapper accounts for every native client method', () => {
  const actual = Object.getOwnPropertyNames(native.RelayClient.prototype)
    .filter((name) => name !== 'constructor')
    .filter((name) => typeof Object.getOwnPropertyDescriptor(native.RelayClient.prototype, name).value === 'function')
    .sort();
  assert.deepEqual(actual, [...METHODS].sort());
});

test('the handwritten facade declares every method', () => {
  const declaration = fs.readFileSync(path.join(__dirname, '..', 'client.d.ts'), 'utf8');
  for (const name of METHODS) {
    assert.match(declaration, new RegExp(`\\b${name}\\(`));
  }
});

test('continuation format literals match the core wire projection', () => {
  const declaration = fs.readFileSync(path.join(__dirname, '..', 'client.d.ts'), 'utf8');
  const continuation = declaration.match(
    /export interface CollectionContinuation[\s\S]*?\n}/,
  );
  assert.ok(continuation);
  assert.match(continuation[0], /'geojson-rfc7946'/);
  assert.doesNotMatch(continuation[0], /'geo-json-rfc7946'/);
});

test('public input literals match the canonical Python vocabulary', () => {
  const declaration = fs.readFileSync(path.join(__dirname, '..', 'client.d.ts'), 'utf8');
  const recordFormat = declaration.match(/export type RecordFormat = ([^\n]+)/);
  const structure = declaration.match(/export interface SdmxStructureRequest[\s\S]*?\n}/);
  assert.ok(recordFormat);
  assert.ok(structure);
  assert.match(recordFormat[1], /'geojson'/);
  assert.doesNotMatch(recordFormat[1], /'geo-json-rfc7946'/);
  assert.match(structure[0], /'datastructure'/);
  assert.doesNotMatch(structure[0], /'data-structure'/);
});

test('list and search declarations expose distinct closed option shapes', () => {
  const declaration = fs.readFileSync(path.join(__dirname, '..', 'client.d.ts'), 'utf8');
  const list = declaration.match(/export interface ListOptions[\s\S]*?\n}/);
  const search = declaration.match(/export interface SearchOptions[\s\S]*?\n}/);
  assert.ok(list);
  assert.ok(search);
  assert.match(list[0], /filters\?:/);
  assert.doesNotMatch(list[0], /\bbbox\??:/);
  assert.match(search[0], /\bbbox:/);
  assert.doesNotMatch(search[0], /filters\?:/);
  assert.match(declaration, /listRecords\(resource: string, options\?: ListOptions \| null,/);
  assert.match(declaration, /search\(resource: string, search: string, options: SearchOptions,/);
});

test('only the normalized package entry point is exported', () => {
  assert.equal(require('@registrystack/relay-client').RelayClient, wrapper.RelayClient);
  assert.throws(
    () => require('@registrystack/relay-client/index.js'),
    (error) => error.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  );
});

test('the package carries its declared Apache license', () => {
  const packageJson = require('../package.json');
  assert.equal(packageJson.license, 'Apache-2.0');
  const license = fs.readFileSync(path.join(__dirname, '..', 'LICENSE'), 'utf8');
  assert.match(license, /Apache License/);
});
