'use strict';

const { types: { isProxy } } = require('node:util');
const native = require('./index');

const MAX_JSON_DEPTH = 128;
const MAX_REQUEST_JSON_NODES = 100_000;
// A valid 16 MiB result can contain far more collection nodes than a request.
const MAX_RESPONSE_JSON_NODES = 3_000_000;
const MAX_JSON_STRING_BYTES = 16 * 1024 * 1024;
const ACCEPTED_CONSTRUCTION = Symbol('accepted-service-selection');

class DiscoveryClientError extends Error {
  constructor(envelope) {
    super(envelope.message);
    this.name = 'DiscoveryClientError';
    this.kind = envelope.kind;
    for (const field of ['status', 'problem', 'transportKind']) {
      if (envelope[field] !== undefined && envelope[field] !== null) this[field] = envelope[field];
    }
  }
}

function normalize(error, fallbackKind = undefined) {
  if (error instanceof DiscoveryClientError) return error;
  if (error instanceof Error && typeof error.message === 'string') {
    try {
      const envelope = JSON.parse(error.message);
      if (envelope && typeof envelope === 'object' && typeof envelope.kind === 'string') {
        return new DiscoveryClientError(envelope);
      }
    } catch {
      // napi argument conversion failures are mapped below.
    }
  }
  if (fallbackKind) {
    return new DiscoveryClientError({
      kind: fallbackKind,
      message: fallbackKind === 'configuration'
        ? 'the Discovery client configuration is invalid'
        : 'the Discovery query is invalid',
    });
  }
  return error;
}

function inputError(kind) {
  return new DiscoveryClientError({
    kind,
    message: kind === 'configuration'
      ? 'the Discovery client configuration is invalid'
      : 'the Discovery query is invalid',
  });
}

function localAcceptanceError() {
  return new DiscoveryClientError({
    kind: 'local_acceptance_refused',
    message: 'the relying application refused the advertised service',
  });
}

class AcceptedServiceSelection {
  #selection;

  constructor(construction, selection) {
    if (construction !== ACCEPTED_CONSTRUCTION) throw inputError('query');
    this.#selection = selection;
  }

  get endpointUrl() {
    return this.#selection.endpointUrl;
  }

  get selection() {
    return responseValue(this.#selection);
  }
}

function cloneJson(value, budget, depth) {
  if (depth > MAX_JSON_DEPTH) throw inputError('query');
  budget.nodes += 1;
  if (budget.nodes > budget.maximumNodes) throw inputError('query');

  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    budget.stringBytes += Buffer.byteLength(value, 'utf8');
    if (budget.stringBytes > MAX_JSON_STRING_BYTES) throw inputError('query');
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw inputError('query');
    return value;
  }
  if (typeof value !== 'object' || isProxy(value)) throw inputError('query');

  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) {
    throw inputError('query');
  }
  if (budget.active.has(value)) throw inputError('query');
  budget.active.add(value);
  try {
    const clone = array ? [] : Object.create(null);
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string')) throw inputError('query');
    let elementCount = 0;
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        throw inputError('query');
      }
      if (array && key === 'length') continue;
      if (!descriptor.enumerable) throw inputError('query');
      if (array) {
        const index = Number(key);
        if (!Number.isInteger(index) || index < 0 || index >= value.length || String(index) !== key) {
          throw inputError('query');
        }
        elementCount += 1;
      } else {
        budget.stringBytes += Buffer.byteLength(key, 'utf8');
        if (budget.stringBytes > MAX_JSON_STRING_BYTES) throw inputError('query');
      }
      clone[key] = cloneJson(descriptor.value, budget, depth + 1);
    }
    if (array && elementCount !== value.length) throw inputError('query');
    return clone;
  } finally {
    budget.active.delete(value);
  }
}

function requestValue(value) {
  return cloneJson(value, {
    nodes: 0,
    maximumNodes: MAX_REQUEST_JSON_NODES,
    stringBytes: 0,
    active: new Set(),
  }, 1);
}

function responseValue(value) {
  return cloneJson(value, {
    nodes: 0,
    maximumNodes: MAX_RESPONSE_JSON_NODES,
    stringBytes: 0,
    active: new Set(),
  }, 1);
}

function configurationValue(options) {
  if (typeof options === 'string') return options;
  if (!options || typeof options !== 'object' || isProxy(options)
      || Object.getPrototypeOf(options) !== Object.prototype) {
    throw inputError('configuration');
  }
  const allowed = new Set([
    'baseUrl',
    'requestTimeoutMilliseconds',
    'connectTimeoutMilliseconds',
    'maximumResponseBytes',
    'trustedRootCertificates',
  ]);
  const copy = Object.create(null);
  for (const key of Reflect.ownKeys(options)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw inputError('configuration');
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw inputError('configuration');
    }
    const value = descriptor.value;
    if (key === 'trustedRootCertificates') {
      if (!Buffer.isBuffer(value) || value.length > 4 * 1024 * 1024) {
        throw inputError('configuration');
      }
      copy[key] = Buffer.from(value);
    } else if (key === 'baseUrl') {
      if (typeof value !== 'string') throw inputError('configuration');
      copy[key] = value;
    } else {
      if (!Number.isSafeInteger(value) || value < 0) throw inputError('configuration');
      copy[key] = value;
    }
  }
  return copy;
}

class DiscoveryClient {
  #inner;

  constructor(options) {
    try {
      this.#inner = new native.DiscoveryClient(configurationValue(options));
    } catch (error) {
      throw normalize(error, 'configuration');
    }
  }

  async resolveEvidenceTypes(request) {
    try {
      return await this.#inner.resolveEvidenceTypes(requestValue(request));
    } catch (error) {
      throw normalize(error, 'query');
    }
  }

  async searchServices(filters = {}) {
    try {
      return await this.#inner.searchServices(requestValue(filters));
    } catch (error) {
      throw normalize(error, 'query');
    }
  }

  async searchEvidenceServices(query) {
    try {
      return await this.#inner.searchEvidenceServices(requestValue(query));
    } catch (error) {
      throw normalize(error, 'query');
    }
  }

  async searchRelayServices(query) {
    try {
      return await this.#inner.searchRelayServices(requestValue(query));
    } catch (error) {
      throw normalize(error, 'query');
    }
  }

  selectExact(response, request) {
    try {
      return this.#inner.selectExact(responseValue(response), requestValue(request));
    } catch (error) {
      throw normalize(error, 'query');
    }
  }

  selectEvidenceAlternative(response, evidenceTypeListId = undefined) {
    return selectEvidenceAlternative(response, evidenceTypeListId);
  }

  selectEvidenceService(response, request) {
    return selectEvidenceService(response, request);
  }

  selectRelayService(response, request) {
    return selectRelayService(response, request);
  }
}

function selectExact(response, request) {
  try {
    return native.selectExact(responseValue(response), requestValue(request));
  } catch (error) {
    throw normalize(error, 'query');
  }
}

function selectEvidenceAlternative(response, evidenceTypeListId = undefined) {
  try {
    if (evidenceTypeListId !== undefined && typeof evidenceTypeListId !== 'string') {
      throw inputError('query');
    }
    return native.selectEvidenceAlternative(responseValue(response), evidenceTypeListId);
  } catch (error) {
    throw normalize(error, 'query');
  }
}

function selectEvidenceService(response, request) {
  try {
    return native.selectEvidenceService(responseValue(response), requestValue(request));
  } catch (error) {
    throw normalize(error, 'query');
  }
}

function selectRelayService(response, request) {
  try {
    return native.selectRelayService(responseValue(response), requestValue(request));
  } catch (error) {
    throw normalize(error, 'query');
  }
}

function validateSelectionStructure(selection) {
  try {
    return native.validateSelectionStructure(requestValue(selection));
  } catch (error) {
    throw normalize(error, 'query');
  }
}

function validateSelection(selection) {
  return validateSelectionStructure(selection);
}

function acceptSelection(selection, accepts) {
  const checked = validateSelectionStructure(selection);
  if (typeof accepts !== 'function') throw inputError('query');
  const accepted = accepts(responseValue(checked));
  if (accepted !== true) throw localAcceptanceError();
  return new AcceptedServiceSelection(ACCEPTED_CONSTRUCTION, checked);
}

function renewUnchangedSelection(previous, current) {
  try {
    return native.renewUnchangedSelection(requestValue(previous), requestValue(current));
  } catch (error) {
    throw normalize(error, 'query');
  }
}

module.exports = {
  AcceptedServiceSelection,
  DiscoveryClient,
  DiscoveryClientError,
  acceptSelection,
  renewUnchangedSelection,
  selectEvidenceAlternative,
  selectEvidenceService,
  selectExact,
  selectRelayService,
  validateSelection,
  validateSelectionStructure,
};
