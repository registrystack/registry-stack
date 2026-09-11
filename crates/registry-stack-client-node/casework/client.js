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
    for (const field of ['code', 'detail', 'status', 'traceId', 'originalAttemptId', 'validation', 'transportKind', 'protocolFailure']) {
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

const NativeCaseworkClient = native.CaseworkClient;

class CaseworkClient {
  constructor(config) {
    try {
      this.native = new NativeCaseworkClient(sanitize(config));
    } catch (error) {
      throw normalized(error, 'configuration');
    }
  }
}

for (const [method, jsonIndexes] of [
  ['description', []],
  ['createHostedItem', [3]],
  ['getHostedItem', []],
  ['addHostedNote', [5]],
  ['requesterHostedNotes', [3]],
  ['cancelHostedItem', [5]],
  ['hostedTerminalItems', [2]],
  ['listHostedWorkItems', [2]],
  ['getHostedWorkItem', []],
  ['hostedWorkItemHistory', [3]],
  ['hostedAccountabilityRecord', []],
  ['claimHostedWorkItem', [2]],
  ['releaseHostedWorkItem', [2]],
  ['decideHostedWorkItem', [2, 4]],
  ['listWorkItems', [3]],
  ['nextWorkItem', [3]],
  ['getWorkItem', []],
  ['claimWorkItem', [3]],
  ['releaseWorkItem', [3]],
  ['getDraft', []],
  ['saveDraft', [6]],
  ['deleteDraft', []],
  ['decideWorkItem', [3, 5]],
  ['recoverDecision', [5]],
  ['recoverDecisionByKey', [5]],
  ['workItemHistory', [4]],
  ['holdings', [3]],
  ['directory', []],
  ['directoryTargets', [2]],
  ['bootstrapDirectory', [4]],
  ['updateDirectoryTeam', [5]],
  ['workItemClocks', []],
  ['holidayRevision', []],
  ['createHolidayRevision', [3]],
  ['previewClockRecompute', [2]],
  ['applyClockRecompute', [3]],
  ['absences', [2]],
  ['createAbsence', [4]],
  ['updateAbsence', [5]],
  ['deleteAbsence', []],
  ['assignWorkItem', [5]],
  ['delegateWorkItem', [5]],
  ['previewCaseloadMove', [2, 3]],
  ['applyCaseloadMove', [3]],
]) {
  CaseworkClient.prototype[method] = function (...args) {
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

module.exports = { CaseworkClient, CaseworkClientError };
