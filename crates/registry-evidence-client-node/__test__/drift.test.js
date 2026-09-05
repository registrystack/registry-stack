'use strict';

// `client.js`/`client.d.ts` are hand-written, unlike every other file in this
// package: they are not regenerated from `src/lib.rs` the way `index.js`/
// `index.d.ts` are, so nothing forces them to stay honest about the native
// module's actual surface when that surface changes. This is the Node analog
// of the stub-drift check the Python binding carries for the same reason
// (introspect the built module and assert the hand-written stub names
// exactly what exists, and nothing more).

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const wrapper = require('..');
const native = require('../index.js');

// Every synchronous native `EvidenceClient` method `client.js` must patch
// through `wrapSync`, and every asynchronous (Promise-returning) one through
// `wrapAsync`, so a mapped failure normalizes to an `EvidenceClientError`
// instead of throwing the raw JSON-envelope message. If the native surface
// grows, this list (and `client.js`'s own wrapping calls) must grow with it.
const SYNC_METHODS = [
  'prepare',
  'prepareBatch',
  'verify',
  'verifyBatch',
  'verifyAsOf',
  'verifyBatchAsOf',
];
const ASYNC_METHODS = [
  'discover',
  'fetchJwks',
  'refreshMetadata',
  'request',
  'send',
  'sendBatch',
  'requestAndVerify',
  'requestAndVerifyBatch',
];

const STATIC_METHODS = ['fromProfile'];

function ownMethodNames(prototype) {
  return Object.getOwnPropertyNames(prototype)
    .filter((name) => name !== 'constructor')
    .filter((name) => typeof Object.getOwnPropertyDescriptor(prototype, name).value === 'function');
}

function ownGetterNames(prototype) {
  return Object.getOwnPropertyNames(prototype).filter(
    (name) => typeof Object.getOwnPropertyDescriptor(prototype, name).get === 'function',
  );
}

function clientDeclaration() {
  return fs.readFileSync(path.join(__dirname, '..', 'client.d.ts'), 'utf8');
}

function interfaceFields(name) {
  const declaration = clientDeclaration();
  const start = declaration.indexOf(`export interface ${name} {`);
  assert.notEqual(start, -1, `${name} is missing from client.d.ts`);
  const body = declaration.slice(start, declaration.indexOf('\n}', start));
  return [...body.matchAll(/^  (\w+)[?:]/gm)].map((match) => match[1]);
}

// The configuration members `client.d.ts` names by hand are only honest while
// they are the members `src/convert.rs` actually reads out of the object a
// caller passes. Both readers name every key as a string literal, either as
// the second argument to a `required_*`/`optional_*` helper or as a direct
// `.get("...")`, so the function body is the list.
function configurationKeysRead(functionName) {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'convert.rs'), 'utf8');
  const start = source.indexOf(`fn ${functionName}(`);
  assert.notEqual(start, -1, `${functionName} is missing from src/convert.rs`);
  const end = source.indexOf('\n}\n', start);
  assert.notEqual(end, -1, `${functionName} has no closing brace in src/convert.rs`);
  const body = source.slice(start, end);
  const keys = new Set();
  for (const match of body.matchAll(/object, "(\w+)"|\.get\("(\w+)"\)/g)) {
    keys.add(match[1] ?? match[2]);
  }
  return [...keys].sort();
}

test('every native EvidenceClient method is accounted for as sync or async', () => {
  const actual = ownMethodNames(native.EvidenceClient.prototype).sort();
  const expected = [...SYNC_METHODS, ...ASYNC_METHODS].sort();
  assert.deepEqual(
    actual,
    expected,
    'the native EvidenceClient surface changed; update SYNC_METHODS/ASYNC_METHODS and the ' +
      'matching wrapSync/wrapAsync calls in client.js',
  );
});

test('every native EvidenceClient static method is normalized by the wrapper', () => {
  const actual = Object.getOwnPropertyNames(native.EvidenceClient)
    .filter((name) => !['length', 'name', 'prototype'].includes(name))
    .filter((name) => typeof native.EvidenceClient[name] === 'function')
    .sort();
  assert.deepEqual(
    actual,
    STATIC_METHODS,
    'the native EvidenceClient static surface changed; update client.js and client.d.ts',
  );
  for (const name of STATIC_METHODS) {
    assert.equal(typeof wrapper.EvidenceClient[name], 'function');
  }
});

test('every native prepared and raw response getter is wrapped', () => {
  assert.deepEqual(ownGetterNames(native.PreparedEvidenceRequest.prototype).sort(), [
    'policyDocument',
    'requestNonce',
    'subjectExpectations',
  ]);
  assert.deepEqual(ownGetterNames(native.RawEvidenceResponse.prototype).sort(), ['body', 'traceId']);
  assert.deepEqual(ownGetterNames(native.PreparedEvidenceRequestBatch.prototype).sort(), [
    'count',
    'policyDocuments',
    'requestNonces',
    'subjectExpectations',
  ]);
  assert.deepEqual(ownGetterNames(native.RawEvidenceRequestBatchResponse.prototype).sort(), [
    'body',
    'traceId',
  ]);
});

test('every native SdJwtVcBatchResponse member is wrapped', () => {
  // Reading an envelope is the native constructor, so `client.js` subclasses
  // this one rather than patching it, the way it does for `EvidenceClient`.
  assert.notEqual(wrapper.SdJwtVcBatchResponse, native.SdJwtVcBatchResponse);
  assert.ok(wrapper.SdJwtVcBatchResponse.prototype instanceof native.SdJwtVcBatchResponse);
  assert.deepEqual(ownMethodNames(native.SdJwtVcBatchResponse.prototype).sort(), [
    'credentialForHolderKey',
  ]);
  assert.deepEqual(ownGetterNames(native.SdJwtVcBatchResponse.prototype).sort(), [
    'count',
    'credentials',
  ]);
});

test('every native progressive result getter is wrapped', () => {
  assert.equal(wrapper.AudienceScopedResult, native.AudienceScopedResult);
  assert.deepEqual(ownGetterNames(native.AudienceScopedResult.prototype).sort(), [
    'assertion',
    'credential',
    'evidence',
    'responseFormat',
    'subjectContinuity',
    'traceId',
    'value',
    'values',
  ]);
});

test('every class client.js exports is declared in client.d.ts or the index.d.ts it re-exports', () => {
  // `client.d.ts` re-exports `index.d.ts` wholesale (`export * from './index'`)
  // rather than repeating each declaration, so a name may legitimately live
  // in either file.
  const clientDeclaration = fs.readFileSync(path.join(__dirname, '..', 'client.d.ts'), 'utf8');
  const indexDeclaration = fs.readFileSync(path.join(__dirname, '..', 'index.d.ts'), 'utf8');
  for (const name of Object.keys(wrapper)) {
    const pattern = new RegExp(`\\b${name}\\b`);
    assert.ok(
      pattern.test(clientDeclaration) || pattern.test(indexDeclaration),
      `neither client.d.ts nor index.d.ts mentions '${name}', which client.js exports`,
    );
  }
});

test('the handwritten request-batch input types preserve the common and item field boundary', () => {
  assert.deepEqual(interfaceFields('EvidenceRequestBatchItemSpec'), [
    'subjects',
    'subjectExpectations',
  ]);
  assert.deepEqual(interfaceFields('EvidenceRequestBatchSpec'), [
    'requirement',
    'purpose',
    'audience',
    'evidenceType',
    'issuedBy',
    'providedBy',
    'configurationRevision',
    'expectedAssuranceProfile',
    'expectedOutputs',
    'maximumAssertionLifetimeSeconds',
    'clockSkewSeconds',
    'items',
  ]);
});

test('the handwritten client configuration names exactly the keys the binding reads', () => {
  // `token` is read by `token_provider_from_json`, which `config_from_json`
  // delegates to, so it is added here rather than found in that body.
  const read = [...configurationKeysRead('config_from_json'), 'token'].sort();
  assert.deepEqual(interfaceFields('EvidenceClientConfig').sort(), read);
});

test('the handwritten token configuration covers exactly the sources the binding accepts', () => {
  const sources = configurationKeysRead('token_provider_from_json').filter(
    (key) => key !== 'token',
  );
  const declaration = clientDeclaration();
  const start = declaration.indexOf('export type EvidenceTokenConfig =');
  assert.notEqual(start, -1, 'EvidenceTokenConfig is missing from client.d.ts');
  const union = declaration.slice(start).split('\n\n')[0];
  const declared = [...union.matchAll(/\| \{ (\w+):/g)].map((match) => match[1]).sort();
  assert.deepEqual(declared, sources);
});

test('the handwritten private-key-JWT configuration names exactly the keys the binding reads', () => {
  assert.deepEqual(
    interfaceFields('PrivateKeyJwtConfig').sort(),
    configurationKeysRead('private_key_jwt_provider_from_json'),
  );
});

test('the generated request-batch result remains an available/notAvailable union', () => {
  const declaration = fs.readFileSync(path.join(__dirname, '..', 'index.d.ts'), 'utf8');
  assert.match(
    declaration,
    /export type VerifiedEvidenceRequestBatchItem =\s*\| \{ status: 'available', verified: VerifiedEvidence \}\s*\| \{ status: 'notAvailable' \}/,
  );
});

test('the exports map is the only resolvable entry point, not index.js', () => {
  // `package.json`'s `exports` map exists to stop a caller from reaching the
  // raw native module (and its unpatched, JSON-message errors) through a
  // subpath require that bypasses `client.js`. A package with an `exports`
  // map can self-reference by its own name, so this asserts both halves from
  // inside the package itself: the package name resolves to the same wrapper
  // `require('..')` gives, and the subpath `index.js` no longer resolves at
  // all.
  const byName = require('@registrystack/evidence-client');
  assert.equal(byName.EvidenceClient, wrapper.EvidenceClient);
  assert.throws(
    () => require('@registrystack/evidence-client/index.js'),
    (error) => error.code === 'ERR_PACKAGE_PATH_NOT_EXPORTED',
  );
});

test('client.d.ts declares no EvidenceClientError field client.js never sets', () => {
  // The exact field list `normalize` copies onto a new `EvidenceClientError`,
  // plus `kind`, which the constructor always sets directly.
  const settableFields = [
    'kind',
    'status',
    'code',
    'traceId',
    'retryAfterSeconds',
    'transportKind',
    'tokenKind',
  ];
  const declaration = fs.readFileSync(path.join(__dirname, '..', 'client.d.ts'), 'utf8');
  const classBody = declaration.slice(declaration.indexOf('class EvidenceClientError'));
  const declaredFields = [...classBody.matchAll(/readonly (\w+)[?:]/g)].map((match) => match[1]);
  assert.ok(declaredFields.length > 0, 'no fields were found; client.d.ts may have been reshaped');
  for (const field of declaredFields) {
    assert.ok(
      settableFields.includes(field),
      `client.d.ts declares '${field}' but client.js's EvidenceClientError never sets it`,
    );
  }
});
