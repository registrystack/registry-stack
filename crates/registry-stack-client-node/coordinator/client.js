'use strict';

const { types: { isProxy } } = require('node:util');
const native = require('./index');

const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 20_000;
const MAX_JSON_STRING_BYTES = 1024 * 1024;

class CoordinatorClientError extends Error {
  constructor(envelope) {
    super(envelope.message);
    this.name = 'CoordinatorClientError';
    this.kind = envelope.kind;
    this.outcomeUnknown = envelope.outcomeUnknown === true;
    for (const field of ['code', 'status', 'transportKind', 'protocolFailure']) {
      if (envelope[field] !== undefined && envelope[field] !== null) this[field] = envelope[field];
    }
  }
}

const FALLBACK_MESSAGES = {
  configuration: 'Coordinator client configuration is invalid',
  invalid_request: 'Coordinator client arguments are invalid',
  protocol: 'Registry Coordinator client failed',
};

function normalized(error, fallbackKind) {
  if (error instanceof CoordinatorClientError) return error;
  if (error instanceof Error && typeof error.message === 'string') {
    try {
      const envelope = JSON.parse(error.message);
      if (envelope && typeof envelope.kind === 'string') return new CoordinatorClientError(envelope);
    } catch {
      // napi argument conversion errors have no mapped envelope.
    }
  }
  if (fallbackKind) {
    return new CoordinatorClientError({
      kind: fallbackKind,
      message: FALLBACK_MESSAGES[fallbackKind],
      outcomeUnknown: fallbackKind === 'protocol',
    });
  }
  return error;
}

function cloneJson(value, budget, depth, kind) {
  if (depth > MAX_JSON_DEPTH || ++budget.nodes > MAX_JSON_NODES) throw normalized({}, kind);
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value, 'utf8');
    if (budget.bytes > MAX_JSON_STRING_BYTES) throw normalized({}, kind);
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw normalized({}, kind);
    }
    return value;
  }
  if (value === undefined || typeof value !== 'object' || isProxy(value)) throw normalized({}, kind);
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    throw normalized({}, kind);
  }
  if (budget.active.has(value)) throw normalized({}, kind);
  budget.active.add(value);
  try {
    if (array) return value.map((member) => cloneJson(member, budget, depth + 1, kind));
    const result = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') throw normalized({}, kind);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw normalized({}, kind);
      if (descriptor.enumerable) {
        budget.bytes += Buffer.byteLength(key, 'utf8');
        if (budget.bytes > MAX_JSON_STRING_BYTES) throw normalized({}, kind);
        result[key] = cloneJson(descriptor.value, budget, depth + 1, kind);
      }
    }
    return result;
  } finally {
    budget.active.delete(value);
  }
}

function sanitize(value, kind) {
  return cloneJson(value, { nodes: 0, bytes: 0, active: new WeakSet() }, 0, kind);
}

const NativeCoordinatorClient = native.CoordinatorClient;

class CoordinatorClient {
  constructor(config) {
    try {
      this.native = new NativeCoordinatorClient(sanitize(config, 'configuration'));
    } catch (error) {
      throw normalized(error, 'configuration');
    }
  }
}

for (const [method, jsonIndexes] of [
  ['start', [2]],
  ['status', []],
  ['inspect', []],
  ['reconcile', []],
]) {
  CoordinatorClient.prototype[method] = function (...args) {
    try {
      for (const index of jsonIndexes) {
        if (args[index] !== undefined && args[index] !== null) {
          args[index] = sanitize(args[index], 'invalid_request');
        }
      }
      return this.native[method](...args).catch((error) => { throw normalized(error, 'protocol'); });
    } catch (error) {
      throw normalized(error, 'invalid_request');
    }
  };
}

module.exports = { CoordinatorClient, CoordinatorClientError };
