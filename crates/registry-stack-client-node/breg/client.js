'use strict';

const { types: { isProxy } } = require('node:util');
const native = require('./index');

const MAX_JSON_DEPTH = 128;
const MAX_JSON_NODES = 100_000;
const MAX_JSON_STRING_BYTES = 4 * 1024 * 1024;

class BaseRegistryClientError extends Error {
  constructor(envelope) {
    super(envelope.message);
    this.name = 'BaseRegistryClientError';
    this.kind = envelope.kind;
    for (const field of ['code', 'planRefusal', 'status', 'traceId', 'transportKind', 'tokenKind']) {
      if (envelope[field] !== undefined && envelope[field] !== null) this[field] = envelope[field];
    }
  }
}

function normalize(error, fallbackKind) {
  if (error instanceof BaseRegistryClientError) return error;
  if (error instanceof Error && typeof error.message === 'string') {
    try {
      const envelope = JSON.parse(error.message);
      if (envelope && typeof envelope === 'object' && typeof envelope.kind === 'string') {
        return new BaseRegistryClientError(envelope);
      }
    } catch {
      // napi argument conversion errors are not mapped Rust error envelopes.
    }
  }
  if (fallbackKind) {
    return new BaseRegistryClientError({
      kind: fallbackKind,
      message: fallbackKind === 'configuration'
        ? 'Base Registry client configuration is invalid'
        : 'Base Registry client arguments are invalid',
    });
  }
  return error;
}

function inputError(kind) {
  return new BaseRegistryClientError({
    kind,
    message: kind === 'configuration'
      ? 'Base Registry client configuration is invalid'
      : 'Base Registry client arguments are invalid',
  });
}

function chargeString(value, budget, kind) {
  budget.stringBytes += Buffer.byteLength(value, 'utf8');
  if (budget.stringBytes > MAX_JSON_STRING_BYTES) throw inputError(kind);
}

function cloneJson(value, budget, depth, kind) {
  if (depth > MAX_JSON_DEPTH) throw inputError(kind);
  budget.nodes += 1;
  if (budget.nodes > MAX_JSON_NODES) throw inputError(kind);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    chargeString(value, budget, kind);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw inputError(kind);
    return value;
  }
  if (value === undefined || typeof value !== 'object' || isProxy(value)) throw inputError(kind);

  const prototype = Object.getPrototypeOf(value);
  const array = Array.isArray(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    throw inputError(kind);
  }
  if (budget.active.has(value)) throw inputError(kind);
  budget.active.add(value);
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key === 'symbol')) throw inputError(kind);
    if (array) {
      if (value.length + budget.nodes > MAX_JSON_NODES) throw inputError(kind);
      const clone = new Array(value.length);
      let count = 0;
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw inputError(kind);
        if (key === 'length') continue;
        chargeString(key, budget, kind);
        const index = Number(key);
        if (!descriptor.enumerable || !Number.isInteger(index) || index < 0
          || index >= value.length || String(index) !== key) throw inputError(kind);
        clone[index] = cloneJson(descriptor.value, budget, depth + 1, kind);
        count += 1;
      }
      if (count !== value.length) throw inputError(kind);
      return clone;
    }
    const clone = Object.create(null);
    for (const key of keys) {
      chargeString(key, budget, kind);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw inputError(kind);
      if (!descriptor.enumerable) continue;
      clone[key] = cloneJson(descriptor.value, budget, depth + 1, kind);
    }
    return clone;
  } finally {
    budget.active.delete(value);
  }
}

function sanitizeArguments(args, jsonIndexes, requiredIndexes) {
  const budget = { nodes: 0, stringBytes: 0, active: new WeakSet() };
  return args.map((value, index) => {
    if (!jsonIndexes.has(index)) return value;
    if (value === undefined || value === null) {
      if (requiredIndexes.has(index)) throw inputError('invalid_request');
      return value;
    }
    return cloneJson(value, budget, 0, 'invalid_request');
  });
}

function wrapAsync(name, jsonIndexes = [], requiredIndexes = []) {
  const original = native.BaseRegistryClient.prototype[name];
  native.BaseRegistryClient.prototype[name] = function (...args) {
    try {
      const sanitized = sanitizeArguments(args, new Set(jsonIndexes), new Set(requiredIndexes));
      return original.apply(this, sanitized).catch((error) => { throw normalize(error); });
    } catch (error) {
      throw normalize(error, 'invalid_request');
    }
  };
}

for (const [method, jsonIndexes, requiredIndexes] of [
  ['health'], ['ready'], ['openapi'], ['registryMetadata'], ['registryContract'], ['entitySchema'],
  ['getRecord', [2]], ['listRecords', [1]], ['continueList', [0], [0]],
  ['lookupRecord', [2, 3]], ['createRecord', [1], [1]],
  ['patchRecord', [3], [3]], ['executeLifecycleAction'],
]) wrapAsync(method, jsonIndexes, requiredIndexes);

const lifecycleActions = native.BaseRegistryClient.prototype.lifecycleActions;
native.BaseRegistryClient.prototype.lifecycleActions = function (...args) {
  try {
    const sanitized = sanitizeArguments(args, new Set([1]), new Set([1]));
    return lifecycleActions.apply(this, sanitized);
  } catch (error) {
    throw normalize(error, 'invalid_request');
  }
};

for (const name of ['selectCreate', 'selectPatch', 'selectLifecycle']) {
  const original = native.BRegMetadata.prototype[name];
  native.BRegMetadata.prototype[name] = function (...args) {
    try {
      return original.apply(this, args);
    } catch (error) {
      throw normalize(error, 'invalid_request');
    }
  };
}

class BaseRegistryClient extends native.BaseRegistryClient {
  constructor(config) {
    try {
      super(cloneJson(config, { nodes: 0, stringBytes: 0, active: new WeakSet() }, 0, 'configuration'));
    } catch (error) {
      throw normalize(error, 'configuration');
    }
  }
}

module.exports = {
  BaseRegistryClient,
  BaseRegistryClientError,
  BRegMetadata: native.BRegMetadata,
  BRegCreateBinding: native.BRegCreateBinding,
  BRegPatchBinding: native.BRegPatchBinding,
  BRegLifecycleAuthority: native.BRegLifecycleAuthority,
  BRegLifecycleAction: native.BRegLifecycleAction,
};
