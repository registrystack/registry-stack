// SPDX-License-Identifier: Apache-2.0

export { fn } from '@openfn/language-common';

export class NotaryRequestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotaryRequestError';
  }
}

export function assertNotaryRequest(state) {
  const data = dataObject(state);
  requireString(data.source_id, 'state.data.source_id');
  requireString(data.dataset, 'state.data.dataset');
  requireString(data.entity, 'state.data.entity');
  if (isBatchMatch(state)) {
    assertBatchRequest(state);
  } else {
    assertLookupRequest(state);
  }
  return state;
}

export function assertLookupRequest(state) {
  const lookup = lookupObject(state);
  requireString(lookup.field, 'state.data.lookup.field');
  if (lookup.value === undefined || lookup.value === null || lookup.value === '') {
    throw new NotaryRequestError('state.data.lookup.value is required');
  }
  requestedFields(state);
  return state;
}

export function assertBatchRequest(state) {
  const signature = querySignature(state);
  const items = batchItems(state);
  for (const term of signature) {
    requireString(term.field, 'state.data.query_signature[].field');
    if ((term.op ?? 'eq') !== 'eq') {
      throw new NotaryRequestError('only eq query_signature operations are supported');
    }
  }
  for (const item of items) {
    requireString(item.id, 'state.data.items[].id');
    if (!Array.isArray(item.values) || item.values.length !== signature.length) {
      throw new NotaryRequestError(
        'state.data.items[].values must match query_signature length',
      );
    }
  }
  requestedFields(state);
  return state;
}

export function isBatchMatch(state) {
  return dataObject(state).mode === 'batch_match' || Array.isArray(dataObject(state).items);
}

export function lookupField(state) {
  return lookupObject(state).field;
}

export function lookupValue(state) {
  return lookupObject(state).value;
}

export function lookup(state) {
  return { field: lookupField(state), value: lookupValue(state) };
}

export function queryTerms(state) {
  const data = dataObject(state);
  if (Array.isArray(data.lookup?.terms)) {
    return data.lookup.terms.map((term) => ({
      field: term.field,
      op: term.op ?? 'eq',
      value: term.value,
    }));
  }
  return [{ field: lookupField(state), op: 'eq', value: lookupValue(state) }];
}

export function querySignature(state) {
  const signature = dataObject(state).query_signature;
  if (!Array.isArray(signature)) {
    throw new NotaryRequestError('state.data.query_signature must be an array');
  }
  return signature.map((term) => ({
    field: term?.field,
    op: term?.op ?? 'eq',
  }));
}

export function batchItems(state) {
  const items = dataObject(state).items;
  if (!Array.isArray(items)) {
    throw new NotaryRequestError('state.data.items must be an array');
  }
  return items.map((item) => ({
    id: String(item?.id ?? ''),
    values: Array.isArray(item?.values) ? item.values : [],
  }));
}

export function requestedFields(state) {
  const fields = dataObject(state).fields;
  if (!Array.isArray(fields) || fields.length === 0 || fields.some((field) => typeof field !== 'string' || field === '')) {
    throw new NotaryRequestError('state.data.fields must be a non-empty string array');
  }
  return fields;
}

export function purpose(state) {
  return dataObject(state).purpose;
}

export function correlationId(state) {
  return dataObject(state).correlation_id;
}

export function returnRecords(state, records) {
  const normalized = normalizeRecords(records);
  return {
    ...state,
    data: normalized,
  };
}

export function returnNotFound(state) {
  return returnRecords(state, []);
}

export function returnTargetAuthError(state) {
  return returnError(state, { code: 'target_auth' });
}

export function returnTargetRateLimit(state, options = {}) {
  const error = { code: 'target_rate_limit' };
  const retryAfter = Number(options?.retryAfterSeconds ?? options?.retry_after_seconds);
  if (Number.isSafeInteger(retryAfter) && retryAfter > 0) {
    error.retry_after_seconds = retryAfter;
  }
  return returnError(state, error);
}

export function returnError(state, error) {
  const code = error?.code;
  if (!['target_auth', 'target_rate_limit', 'openfn_execution'].includes(code)) {
    throw new NotaryRequestError(`unsupported error code: ${String(code)}`);
  }
  return {
    ...state,
    data: {
      error,
    },
  };
}

export function returnBatchItems(state, items) {
  assertBatchRequest(state);
  if (!Array.isArray(items)) {
    throw new NotaryRequestError('items must be an array');
  }
  const requestedIds = new Set(batchItems(state).map((item) => item.id));
  const seen = new Set();
  const normalized = items.map((item) => {
    const id = String(item?.id ?? '');
    if (!requestedIds.has(id)) {
      throw new NotaryRequestError(`batch item id was not requested: ${id}`);
    }
    if (seen.has(id)) {
      throw new NotaryRequestError(`batch item id is duplicated: ${id}`);
    }
    seen.add(id);
    if (item.error) {
      return { id, error: normalizeItemError(item.error) };
    }
    return { id, data: normalizeRecords(item.data ?? item.records ?? []) };
  });
  return {
    ...state,
    data: {
      ...dataObject(state),
      items: normalized,
    },
  };
}

export function batchItemLookup(state, item) {
  const signature = querySignature(state);
  const values = Array.isArray(item?.values) ? item.values : [];
  const terms = signature.map((term, index) => ({
    field: term.field,
    op: term.op ?? 'eq',
    value: values[index],
  }));
  if (terms.length === 1) {
    return { field: terms[0].field, value: terms[0].value };
  }
  return { terms };
}

function normalizeRecords(records) {
  if (!Array.isArray(records)) {
    throw new NotaryRequestError('records must be an array');
  }
  return records.map((record, index) => {
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new NotaryRequestError(`record at index ${index} must be an object`);
    }
    return record;
  });
}

function normalizeItemError(error) {
  if (error?.code === 'target_auth') {
    return { code: 'target_auth' };
  }
  if (error?.code === 'target_rate_limit') {
    const normalized = { code: 'target_rate_limit' };
    const retryAfter = Number(error.retryAfterSeconds ?? error.retry_after_seconds);
    if (Number.isSafeInteger(retryAfter) && retryAfter > 0) {
      normalized.retry_after_seconds = retryAfter;
    }
    return normalized;
  }
  throw new NotaryRequestError(`unsupported batch item error code: ${String(error?.code)}`);
}

function lookupObject(state) {
  const lookupValue = dataObject(state).lookup;
  if (!lookupValue || typeof lookupValue !== 'object' || Array.isArray(lookupValue)) {
    throw new NotaryRequestError('state.data.lookup must be an object');
  }
  return lookupValue;
}

function dataObject(state) {
  if (!state?.data || typeof state.data !== 'object' || Array.isArray(state.data)) {
    throw new NotaryRequestError('state.data must be an object');
  }
  return state.data;
}

function requireString(value, label) {
  if (typeof value !== 'string' || value === '') {
    throw new NotaryRequestError(`${label} must be a non-empty string`);
  }
}
