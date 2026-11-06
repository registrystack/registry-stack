'use strict';

const { types: { isProxy } } = require('node:util');
const native = require('./index');

const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 20_000;
const MAX_JSON_STRING_BYTES = 8 * 1024 * 1024;

class RenderClientError extends Error {
  constructor(envelope) {
    super(envelope.message ?? 'Registry Render client failed');
    this.name = 'RenderClientError';
    this.kind = envelope.kind;
    this.outcomeUnknown = envelope.outcomeUnknown === true;
    for (const field of ['code', 'title', 'detail', 'status', 'traceId', 'retryAfterSeconds', 'transportKind', 'protocolFailure']) {
      if (envelope[field] !== undefined && envelope[field] !== null) this[field] = envelope[field];
    }
  }
}

const FALLBACK_MESSAGES = {
  configuration: 'Render client configuration is invalid',
  'invalid-request': 'Render client arguments are invalid',
  protocol: 'Registry Render client failed',
};

function normalized(error, fallbackKind) {
  if (error instanceof RenderClientError) return error;
  if (error instanceof Error && typeof error.message === 'string') {
    try {
      const envelope = JSON.parse(error.message);
      if (envelope && typeof envelope.kind === 'string') return new RenderClientError(envelope);
    } catch {
      // napi argument conversion errors have no mapped envelope.
    }
  }
  if (fallbackKind) {
    return new RenderClientError({
      kind: fallbackKind,
      message: FALLBACK_MESSAGES[fallbackKind],
      // A rejection after the native client took the call may follow an
      // exchange, so it leaves the outcome unknown as a native protocol
      // failure does.
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
  if (value === undefined || typeof value !== 'object' || isProxy(value)) {
    throw normalized({}, kind);
  }
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    throw normalized({}, kind);
  }
  if (budget.active.has(value)) throw normalized({}, kind);
  budget.active.add(value);
  try {
    if (array) {
      if (value.length > MAX_JSON_NODES - budget.nodes) throw normalized({}, kind);
      const keys = Reflect.ownKeys(value);
      if (keys.length !== value.length + 1) throw normalized({}, kind);
      const result = new Array(value.length);
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw normalized({}, kind);
        result[index] = cloneJson(descriptor.value, budget, depth + 1, kind);
      }
      return result;
    }
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

// A refusal is reported as `kind`: `configuration` for the constructor's
// settings, `invalid-request` for a method's arguments.
function sanitize(value, kind) {
  return cloneJson(value, { nodes: 0, bytes: 0, active: new WeakSet() }, 0, kind);
}

class RenderClient {
  constructor(config) {
    try { this.native = new native.RenderClient(sanitize(config, 'configuration')); }
    catch (error) { throw normalized(error, 'configuration'); }
  }
  // `correlationKey` is optional: 1 to 128 visible ASCII characters, sent as
  // `Idempotency-Key` and checked when echoed. It is not a deduplication
  // promise, and neither method resends.
  async render(tokenOrProvider, documentType, request, correlationKey) {
    return this.#exchange('render', tokenOrProvider, documentType, request, correlationKey);
  }
  async seal(tokenOrProvider, documentType, request, correlationKey) {
    return this.#exchange('seal', tokenOrProvider, documentType, request, correlationKey);
  }
  async #exchange(method, tokenOrProvider, documentType, request, correlationKey) {
    try {
      request = sanitize(request, 'invalid-request');
      if (typeof documentType !== 'string') throw normalized({}, 'invalid-request');
      if (correlationKey !== undefined && typeof correlationKey !== 'string') {
        throw normalized({}, 'invalid-request');
      }
      native.validateRenderRequest(documentType, request);
      native.validateCorrelationKey(correlationKey);
    } catch (error) { throw normalized(error, 'invalid-request'); }
    // Providers own token-acquisition failures, including the shared OAuth
    // helper's typed classification. Preserve it for caller recovery.
    let token;
    if (typeof tokenOrProvider === 'string') token = tokenOrProvider;
    else if (tokenOrProvider && typeof tokenOrProvider.bearerToken === 'function') {
      token = await tokenOrProvider.bearerToken();
    } else throw normalized({}, 'invalid-request');
    if (typeof token !== 'string') throw normalized({}, 'invalid-request');
    try { return await this.native[method](token, documentType, request, correlationKey); }
    catch (error) { throw normalized(error, 'protocol'); }
  }
}
module.exports = { RenderClient, RenderClientError };
