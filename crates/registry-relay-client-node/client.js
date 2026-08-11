'use strict';

const { types: { isProxy } } = require('node:util');
const native = require('./index');

const MAX_JSON_DEPTH = 128;
const MAX_JSON_NODES = 100_000;
const MAX_JSON_STRING_BYTES = 4 * 1024 * 1024;

class RelayClientError extends Error {
  constructor(envelope) {
    super(envelope.message);
    this.name = 'RelayClientError';
    this.kind = envelope.kind;
    for (const field of ['code', 'status', 'traceId', 'retryAfterSeconds', 'transportKind', 'tokenKind']) {
      if (envelope[field] !== undefined && envelope[field] !== null) this[field] = envelope[field];
    }
  }
}

function normalize(error, fallbackKind) {
  if (error instanceof RelayClientError) return error;
  if (error instanceof Error && typeof error.message === 'string') {
    try {
      const envelope = JSON.parse(error.message);
      if (envelope && typeof envelope === 'object' && typeof envelope.kind === 'string') {
        return new RelayClientError(envelope);
      }
    } catch {
      // napi argument conversion errors are not mapped Rust error envelopes.
    }
  }
  if (fallbackKind) {
    return new RelayClientError({
      kind: fallbackKind,
      message: fallbackKind === 'configuration'
        ? 'Relay client configuration is invalid'
        : 'Relay client arguments are invalid',
    });
  }
  return error;
}

function inputError(kind) {
  return new RelayClientError({
    kind,
    message: kind === 'configuration'
      ? 'Relay client configuration is invalid'
      : 'Relay client arguments are invalid',
  });
}

function chargeString(value, budget, kind) {
  budget.stringBytes += Buffer.byteLength(value, 'utf8');
  if (budget.stringBytes > MAX_JSON_STRING_BYTES) throw inputError(kind);
}

function cloneJson(value, budget, depth, allowUndefined, kind) {
  if (depth > MAX_JSON_DEPTH) throw inputError(kind);
  budget.nodes += 1;
  if (budget.nodes > MAX_JSON_NODES) throw inputError(kind);

  if (value === undefined) {
    if (allowUndefined) return undefined;
    throw inputError(kind);
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    chargeString(value, budget, kind);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw inputError(kind);
    return value;
  }
  if (typeof value !== 'object' || isProxy(value)) throw inputError(kind);

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
      let elementCount = 0;
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw inputError(kind);
        if (key === 'length') continue;
        chargeString(key, budget, kind);
        const index = Number(key);
        if (!descriptor.enumerable || !Number.isInteger(index) || index < 0
          || index >= value.length || String(index) !== key) {
          throw inputError(kind);
        }
        clone[index] = cloneJson(descriptor.value, budget, depth + 1, false, kind);
        elementCount += 1;
      }
      if (elementCount !== value.length) throw inputError(kind);
      return clone;
    }

    const clone = Object.create(null);
    for (const key of keys) {
      chargeString(key, budget, kind);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw inputError(kind);
      if (!descriptor.enumerable) continue;
      clone[key] = cloneJson(descriptor.value, budget, depth + 1, false, kind);
    }
    return clone;
  } finally {
    budget.active.delete(value);
  }
}

function cloneArguments(args, kind, requiredJsonArguments = new Set()) {
  const budget = { nodes: 0, stringBytes: 0, active: new WeakSet() };
  return args.map((value, index) => (
    cloneJson(value, budget, 0, !requiredJsonArguments.has(index), kind)
  ));
}

function wrapAsync(prototype, name, requiredJsonArguments) {
  const original = prototype[name];
  prototype[name] = function (...args) {
    try {
      const clonedArgs = cloneArguments(args, 'invalid_request', requiredJsonArguments);
      return original.apply(this, clonedArgs).catch((error) => { throw normalize(error); });
    } catch (error) {
      throw normalize(error, 'invalid_request');
    }
  };
}

const METHODS = [
  'health', 'ready', 'openapi', 'serviceMetadata', 'resources', 'continueResources', 'resource',
  'listRecords', 'continueListRecords', 'readRecord', 'lookup', 'search', 'continueSearch',
  'artifact', 'sdmxData', 'sdmxStructure',
];
const REQUIRED_JSON_ARGUMENTS = {
  continueResources: new Set([0]),
  continueListRecords: new Set([0]),
  lookup: new Set([2]),
  search: new Set([2]),
  continueSearch: new Set([0]),
  sdmxData: new Set([0]),
  sdmxStructure: new Set([0]),
};
for (const method of METHODS) {
  wrapAsync(native.RelayClient.prototype, method, REQUIRED_JSON_ARGUMENTS[method]);
}

class RelayClient extends native.RelayClient {
  constructor(config) {
    try {
      super(...cloneArguments([config], 'configuration', new Set([0])));
    } catch (error) {
      throw normalize(error, 'configuration');
    }
  }
}

module.exports = { RelayClient, RelayClientError };
