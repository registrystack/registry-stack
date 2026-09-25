'use strict';

const { types: { isProxy } } = require('node:util');
const native = require('./index');

const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 20_000;
const MAX_JSON_STRING_BYTES = 1024 * 1024;

class MessagingClientError extends Error {
  constructor(envelope) {
    super(envelope.message);
    this.name = 'MessagingClientError';
    this.kind = envelope.kind;
    for (const field of ['code', 'title', 'detail', 'status', 'traceId', 'retryAfterSeconds', 'transportKind', 'protocolFailure']) {
      if (envelope[field] !== undefined && envelope[field] !== null) this[field] = envelope[field];
    }
  }
}

function normalized(error, fallbackKind) {
  if (error instanceof MessagingClientError) return error;
  if (error instanceof Error && typeof error.message === 'string') {
    try {
      const envelope = JSON.parse(error.message);
      if (envelope && typeof envelope.kind === 'string') return new MessagingClientError(envelope);
    } catch {
      // napi argument conversion errors have no mapped envelope.
    }
  }
  if (fallbackKind) {
    return new MessagingClientError({
      kind: fallbackKind,
      message: fallbackKind === 'configuration'
        ? 'Messaging client configuration is invalid'
        : 'Messaging client arguments are invalid',
    });
  }
  return error;
}

function cloneJson(value, budget, depth) {
  if (depth > MAX_JSON_DEPTH || ++budget.nodes > MAX_JSON_NODES) throw normalized({}, 'invalid_request');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value, 'utf8');
    if (budget.bytes > MAX_JSON_STRING_BYTES) throw normalized({}, 'invalid_request');
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw normalized({}, 'invalid_request');
    }
    return value;
  }
  if (value === undefined || typeof value !== 'object' || isProxy(value)) {
    throw normalized({}, 'invalid_request');
  }
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    throw normalized({}, 'invalid_request');
  }
  if (budget.active.has(value)) throw normalized({}, 'invalid_request');
  budget.active.add(value);
  try {
    if (array) return value.map((member) => cloneJson(member, budget, depth + 1));
    const result = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') throw normalized({}, 'invalid_request');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw normalized({}, 'invalid_request');
      if (descriptor.enumerable) result[key] = cloneJson(descriptor.value, budget, depth + 1);
    }
    return result;
  } finally {
    budget.active.delete(value);
  }
}

function sanitize(value) {
  return cloneJson(value, { nodes: 0, bytes: 0, active: new WeakSet() }, 0);
}

const NativeMessagingClient = native.MessagingClient;

class MessagingClient {
  constructor(config) {
    try {
      this.native = new NativeMessagingClient(sanitize(config));
    } catch (error) {
      throw normalized(error, 'configuration');
    }
  }
}

for (const [method, jsonIndexes] of [
  ['health', []],
  ['ready', []],
  ['submit', [2]],
  ['message', []],
  ['cancel', []],
  ['preview', [3]],
]) {
  MessagingClient.prototype[method] = function (...args) {
    try {
      for (const index of jsonIndexes) {
        if (args[index] !== undefined && args[index] !== null) args[index] = sanitize(args[index]);
      }
      return this.native[method](...args).catch((error) => { throw normalized(error); });
    } catch (error) {
      throw normalized(error, 'invalid_request');
    }
  };
}

module.exports = { MessagingClient, MessagingClientError };
