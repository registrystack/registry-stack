'use strict';

const { types: { isProxy } } = require('node:util');
const native = require('./index');

const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 20_000;
const MAX_JSON_STRING_BYTES = 1024 * 1024;

class CaseworkClientError extends Error {
  constructor(envelope) {
    super(envelope.message);
    this.name = 'CaseworkClientError';
    this.kind = envelope.kind;
    this.outcomeUnknown = envelope.outcomeUnknown === true;
    for (const field of ['code', 'detail', 'status', 'traceId', 'validation', 'transportKind', 'protocolFailure']) {
      if (envelope[field] !== undefined && envelope[field] !== null) this[field] = envelope[field];
    }
  }
}

function normalized(error, fallbackKind) {
  if (error instanceof CaseworkClientError) return error;
  if (error instanceof Error && typeof error.message === 'string') {
    try {
      const envelope = JSON.parse(error.message);
      if (envelope && typeof envelope.kind === 'string') return new CaseworkClientError(envelope);
    } catch {
      // napi argument conversion errors have no mapped envelope.
    }
  }
  if (fallbackKind) {
    return new CaseworkClientError({
      kind: fallbackKind,
      message: fallbackKind === 'configuration'
        ? 'Casework client configuration is invalid'
        : 'Casework client arguments are invalid',
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
    if (array) return value.map((member) => cloneJson(member, budget, depth + 1, kind));
    const result = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') throw normalized({}, kind);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw normalized({}, kind);
      if (descriptor.enumerable) result[key] = cloneJson(descriptor.value, budget, depth + 1, kind);
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

function configurationValue(config) {
  if (!config || typeof config !== 'object' || Array.isArray(config) || isProxy(config)) {
    throw normalized({}, 'configuration');
  }
  const prototype = Object.getPrototypeOf(config);
  if (prototype !== Object.prototype && prototype !== null) {
    throw normalized({}, 'configuration');
  }
  const allowed = new Set([
    'baseUrl',
    'attemptTimeoutMilliseconds',
    'connectTimeoutMilliseconds',
    'maximumResponseBytes',
    'userAgent',
    'trustedRootCertificates',
    'maximumMutationRetries',
  ]);
  const copy = Object.create(null);
  for (const key of Reflect.ownKeys(config)) {
    if (typeof key !== 'string' || !allowed.has(key)) throw normalized({}, 'configuration');
    const descriptor = Object.getOwnPropertyDescriptor(config, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw normalized({}, 'configuration');
    }
    const value = descriptor.value;
    if (key === 'baseUrl' || key === 'userAgent' || key === 'trustedRootCertificates') {
      if (typeof value !== 'string') throw normalized({}, 'configuration');
      copy[key] = value;
    } else {
      if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw normalized({}, 'configuration');
      }
      copy[key] = value;
    }
  }
  return copy;
}

const NativeCaseworkClient = native.CaseworkClient;

class CaseworkClient {
  constructor(config) {
    try {
      this.native = new NativeCaseworkClient(configurationValue(config));
    } catch (error) {
      throw normalized(error, 'configuration');
    }
  }

  taskAssertionEndpoint(grantId) {
    try {
      return this.native.taskAssertionEndpoint(grantId);
    } catch (error) {
      throw normalized(error, 'invalid-request');
    }
  }
}

for (const [method, jsonIndexes] of [
  ['description', []],
  ['createOrRecoverReviewRequest', [3]],
  ['reviewRequest', []],
  ['reviewResult', [2]],
  ['reviewResults', [2]],
  ['cancelReviewRequest', [2, 4]],
  ['reviewPolicies', []],
  ['reviewPolicy', []],
  ['reviewTasks', [2]],
  ['ownReviewDecisions', [2]],
  ['supervisoryReviewTasks', [2]],
  ['reviewTask', []],
  ['reviewTaskContext', []],
  ['previewReviewTaskTemplates', [2]],
  ['listReviewTaskGrants', [2]],
  ['approveReviewTaskGrant', [5]],
  ['revokeReviewTaskGrant', []],
  ['claimReviewTask', []],
  ['releaseReviewTask', []],
  ['assignReviewTask', [5]],
  ['delegateReviewTask', [5]],
  ['reviewTaskDraft', []],
  ['saveReviewTaskDraft', [5]],
  ['deleteReviewTaskDraft', []],
  ['decideReviewTask', [5]],
  ['reviewHistory', [3]],
  ['addReviewNote', [4]],
  ['reviewClocks', []],
  ['reviewAccountability', []],
  ['taskAssertion', []],
  ['taskGrantStatus', []],
  ['nextReviewTask', [2]],
  ['reviewTaskHoldings', [2]],
  ['directory', []],
  ['directoryTargets', [2]],
  ['bootstrapDirectory', [4]],
  ['updateDirectoryTeam', [5]],
  ['holidayRevision', []],
  ['createHolidayRevision', [3]],
  ['previewClockRecompute', [2]],
  ['applyClockRecompute', [3]],
  ['absences', [2]],
  ['createAbsence', [4]],
  ['updateAbsence', [5]],
  ['deleteAbsence', []],
  ['previewCaseloadMove', [2]],
  ['applyCaseloadMove', [3]],
]) {
  CaseworkClient.prototype[method] = function (...args) {
    try {
      for (const index of jsonIndexes) {
        if (args[index] !== undefined && args[index] !== null) args[index] = sanitize(args[index], 'invalid-request');
      }
      return this.native[method](...args).catch((error) => { throw normalized(error); });
    } catch (error) {
      throw normalized(error, 'invalid-request');
    }
  };
}

// Hash the same sanitized request that admission sends. Rust owns canonical
// ordering, portable JSON validation, and the producer/namespace binding.
function submissionDigest(producer, sourceNamespace, request) {
  try {
    return native.submissionDigest(producer, sourceNamespace, sanitize(request, 'invalid-request'));
  } catch (error) {
    throw normalized(error, 'invalid-request');
  }
}

module.exports = { CaseworkClient, CaseworkClientError, submissionDigest };
