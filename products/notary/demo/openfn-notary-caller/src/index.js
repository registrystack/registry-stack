// SPDX-License-Identifier: Apache-2.0

import { createHmac, randomUUID } from "node:crypto";

const DEFAULT_MULTI_CLAIM_POLICY = "all_must_be_satisfied";
const PROBLEM_BRANCHES = new Map([
  ["target.not_found", "not_found"],
  ["target.match_ambiguous", "ambiguous"],
  ["evidence.not_available", "evidence_not_available"],
  ["source.unavailable", "source_unavailable"],
  ["idempotency.conflict", "idempotency_conflict"],
  ["request.invalid", "invalid_request"],
]);
const POLICY_DENIED_CODES = new Set([
  "purpose.not_allowed",
  "profile.unsupported",
  "requester.reauthentication_required",
  "requester.matching_policy_rejected",
  "relationship.policy_rejected",
]);
const UNSAFE_PATH_PARTS = new Set(["__proto__", "prototype", "constructor"]);

export class NotaryCallerError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "NotaryCallerError";
    this.code = options.code ?? "notary_caller.error";
  }
}

export function buildEvaluationRequest(state, options = {}) {
  const data = dataObject(state);
  const configuration = configurationObject(state);
  const claimIds = normalizeClaimIds(options);
  const purpose = requireString(options.purpose, "options.purpose");
  const bodyPurpose = options.bodyPurpose ?? purpose;
  if (bodyPurpose !== purpose) {
    throw new NotaryCallerError("Data-Purpose header and request body purpose must match", {
      code: "purpose.mismatch",
    });
  }
  const requestId = stringOrUndefined(data.request_id)
    ?? stringOrUndefined(options.requestId)
    ?? (typeof options.requestIdFactory === "function" ? options.requestIdFactory() : randomUUID());
  const target = buildTarget(data, options.target);
  const targetFingerprint = fingerprintTarget(configuration, target, options);
  const baseUrl = trimTrailingSlash(requireString(configuration.notary_base_url, "configuration.notary_base_url"));
  const token = requireString(configuration.token ?? configuration.notary_token, "configuration.token");
  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    "Data-Purpose": purpose,
    "X-Request-Id": requireString(requestId, "request id"),
  };
  if (stringOrUndefined(data.traceparent) !== undefined) {
    headers.traceparent = data.traceparent;
  }

  return {
    ...state,
    data: {
      ...data,
      notary_request: {
        url: `${baseUrl}/v1/evaluations`,
        headers,
        body: {
          target,
          ...(options.relationship ? { relationship: normalizeRelationship(options.relationship) } : {}),
          claims: claimIds.length === 1 ? [claimIds[0]] : claimIds,
          ...(options.disclosure ? { disclosure: options.disclosure } : {}),
          purpose: bodyPurpose,
        },
      },
      notary_context: {
        claim_ids: claimIds,
        purpose,
        target_fingerprint: targetFingerprint,
        multi_claim_policy: normalizeMultiClaimPolicy(options.multiClaimPolicy),
        redact_data_paths: redactDataPaths(options),
      },
    },
  };
}

export function shouldSkipEvaluation(state, options = {}) {
  const data = dataObject(state);
  if (!data.notary || typeof data.notary !== "object" || Array.isArray(data.notary)) {
    return false;
  }
  const claimIds = normalizeClaimIds(options);
  const purpose = requireString(options.purpose, "options.purpose");
  const target = buildTarget(data, options.target);
  const targetFingerprint = fingerprintTarget(configurationObject(state), target, options);
  if (data.notary.purpose !== purpose || data.notary.target_fingerprint !== targetFingerprint) {
    return false;
  }
  if (claimIds.length === 1) {
    return data.notary.claim === claimIds[0] && typeof data.notary.evaluation_id === "string";
  }
  const completedClaims = Array.isArray(data.notary.claims)
    ? data.notary.claims.map((claim) => claim.claim)
    : [];
  return claimIds.every((claimId) => completedClaims.includes(claimId));
}

export async function callNotaryEvaluation(state, options = {}) {
  if (shouldSkipEvaluation(state, options)) {
    return state;
  }
  const prepared = buildEvaluationRequest(state, options);
  const request = prepared.data.notary_request;
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new NotaryCallerError("fetch is required to call Registry Notary", {
      code: "fetch.required",
    });
  }
  let response;
  try {
    response = await fetchImpl(request.url, {
      method: "POST",
      headers: request.headers,
      body: JSON.stringify(request.body),
    });
  } catch (_error) {
    return handleEvaluationTransportError(prepared, options);
  }
  const body = await readJsonResponse(response);
  const responseState = {
    ...prepared,
    response: {
      statusCode: response.status,
      headers: headersObject(response.headers),
      body,
    },
  };
  if (response.status >= 200 && response.status < 300) {
    return handleEvaluationSuccess(responseState, options);
  }
  return handleEvaluationProblem(responseState, options);
}

function handleEvaluationTransportError(state, options = {}) {
  const data = dataObject(state);
  const context = notaryContext(data, options);
  return redactFinishedState(state, {
    branch: "retryable_infrastructure",
    ...(context.claim_ids.length === 1
      ? { claim: context.claim_ids[0] }
      : { claims: context.claim_ids.map((claim) => ({ claim, branch: "retryable_infrastructure" })) }),
    purpose: context.purpose,
    request_id: data.notary_request?.headers?.["X-Request-Id"],
    target_fingerprint: context.target_fingerprint,
    problem: {
      code: "transport.error",
      status: 0,
      title: "Registry Notary request failed",
      retryable: true,
    },
  }, context.redact_data_paths);
}

export function handleEvaluationSuccess(state, options = {}) {
  const data = dataObject(state);
  const context = notaryContext(data, options);
  const body = responseBody(state);
  if (!Array.isArray(body.results)) {
    throw new NotaryCallerError("Notary EvaluationResponse.results must be an array", {
      code: "response.invalid_results",
    });
  }
  const claims = context.claim_ids.map((claimId) => {
    const result = body.results.find((item) => item?.claim_id === claimId);
    if (!result) {
      return {
        claim: claimId,
        branch: "not_satisfied",
        satisfied: false,
      };
    }
    const hasValue = Object.prototype.hasOwnProperty.call(result, "value") && result.value !== null;
    const satisfied = typeof result.satisfied === "boolean" ? result.satisfied : undefined;
    return {
      claim: claimId,
      branch: satisfied === false ? "not_satisfied" : "satisfied",
      evaluation_id: stringOrUndefined(result.evaluation_id),
      ...(satisfied !== undefined ? { satisfied } : {}),
      ...(hasValue ? { value: result.value } : {}),
    };
  });
  const branch = context.multi_claim_policy === "per_claim_routing"
    ? "per_claim_routing"
    : claims.every((claim) => claim.branch === "satisfied") ? "satisfied" : "not_satisfied";
  const selected = claims[0];

  return redactFinishedState(state, {
    branch,
    ...(context.claim_ids.length === 1
      ? {
          claim: selected.claim,
          evaluation_id: selected.evaluation_id,
          ...(selected.satisfied !== undefined ? { satisfied: selected.satisfied } : {}),
          ...(Object.prototype.hasOwnProperty.call(selected, "value") ? { value: selected.value } : {}),
        }
      : {
          claims,
          satisfied: branch === "satisfied",
        }),
    purpose: context.purpose,
    request_id: responseHeader(state, "x-request-id") ?? data.notary_request?.headers?.["X-Request-Id"],
    target_fingerprint: context.target_fingerprint,
  }, context.redact_data_paths);
}

export function handleEvaluationProblem(state, options = {}) {
  const data = dataObject(state);
  const body = responseBody(state);
  const status = numberOrUndefined(body.status) ?? numberOrUndefined(state.response?.statusCode) ?? 0;
  const code = stringOrUndefined(body.code) ?? statusToFallbackCode(status);
  const branch = problemBranch(code, status);
  const retryAfter = retryAfterSeconds(state);
  return redactFinishedState(state, {
    branch,
    ...(options.claimId ? { claim: options.claimId } : {}),
    ...(options.claimIds ? { claims: options.claimIds.map((claim) => ({ claim, branch })) } : {}),
    purpose: options.purpose ?? data.notary_context?.purpose,
    request_id: responseHeader(state, "x-request-id") ?? stringOrUndefined(body.request_id) ?? data.request_id,
    ...(retryAfter !== undefined ? { retry_after_seconds: retryAfter } : {}),
    problem: {
      code,
      status,
      title: stringOrUndefined(body.title),
      retryable: branch === "retryable_infrastructure",
    },
  }, redactDataPaths(options, data.notary_context?.redact_data_paths));
}

export function selectClaimResult(response, claimId) {
  const body = response?.body ?? response?.data ?? response;
  if (!Array.isArray(body?.results)) {
    throw new NotaryCallerError("response.results must be an array", {
      code: "response.invalid_results",
    });
  }
  return body.results.find((item) => item?.claim_id === claimId);
}

export function assertClaimSatisfied(state, claimId) {
  const notary = dataObject(state).notary;
  const claim = notary?.claim === claimId
    ? notary
    : Array.isArray(notary?.claims)
      ? notary.claims.find((item) => item.claim === claimId)
      : undefined;
  if (!claim || claim.satisfied !== true) {
    throw new NotaryCallerError(`claim is not satisfied: ${claimId}`, {
      code: "claim.not_satisfied",
    });
  }
  return state;
}

export function assertAllClaimsSatisfied(state, claimIds) {
  for (const claimId of claimIds) {
    assertClaimSatisfied(state, claimId);
  }
  return state;
}

export function redactNotaryResponse(response) {
  const body = response?.body ?? response?.data ?? response;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return {};
  }
  const { detail: _detail, ...safe } = body;
  return safe;
}

function problemBranch(code, status) {
  if (PROBLEM_BRANCHES.has(code)) {
    return PROBLEM_BRANCHES.get(code);
  }
  if (POLICY_DENIED_CODES.has(code) || code?.startsWith("requester.") || code?.startsWith("relationship.")) {
    return "policy_denied";
  }
  if (status === 429 || status === 503) {
    return "retryable_infrastructure";
  }
  if (status >= 500) {
    return "retryable_infrastructure";
  }
  return "invalid_request";
}

function redactFinishedState(state, notary, paths = []) {
  const data = dataObject(state);
  const {
    national_id: _nationalId,
    notary_request: _notaryRequest,
    notary_context: _notaryContext,
    ...safeData
  } = data;
  for (const path of paths) {
    deleteDataPath(safeData, path);
  }
  const {
    configuration: _configuration,
    response: _response,
    ...safeState
  } = state;
  return {
    ...safeState,
    data: {
      ...safeData,
      notary,
    },
  };
}

function notaryContext(data, options) {
  const context = data.notary_context && typeof data.notary_context === "object"
    ? data.notary_context
    : {};
  return {
    claim_ids: Array.isArray(context.claim_ids) ? context.claim_ids : normalizeClaimIds(options),
    purpose: stringOrUndefined(context.purpose) ?? requireString(options.purpose, "purpose"),
    target_fingerprint: stringOrUndefined(context.target_fingerprint),
    multi_claim_policy: normalizeMultiClaimPolicy(context.multi_claim_policy ?? options.multiClaimPolicy),
    redact_data_paths: redactDataPaths(options, context.redact_data_paths),
  };
}

function responseBody(state) {
  const response = state?.response;
  const body = response?.body ?? response?.data;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new NotaryCallerError("state.response.body must be an object", {
      code: "response.invalid_body",
    });
  }
  return body;
}

function responseHeader(state, name) {
  const headers = state?.response?.headers;
  if (!headers || typeof headers !== "object") {
    return undefined;
  }
  const exact = headers[name];
  if (typeof exact === "string") {
    return exact;
  }
  const lowerName = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === lowerName && typeof value === "string") {
      return value;
    }
  }
  return undefined;
}

function retryAfterSeconds(state) {
  const raw = responseHeader(state, "retry-after");
  if (raw === undefined) {
    return undefined;
  }
  const parsed = Number(raw);
  if (Number.isSafeInteger(parsed) && parsed > 0) {
    return parsed;
  }
  const retryAt = Date.parse(raw);
  if (!Number.isFinite(retryAt)) {
    return undefined;
  }
  const serverDate = Date.parse(responseHeader(state, "date") ?? "");
  const referenceTime = Number.isFinite(serverDate) ? serverDate : Date.now();
  const seconds = Math.ceil((retryAt - referenceTime) / 1000);
  return Number.isSafeInteger(seconds) && seconds > 0 ? seconds : undefined;
}

function normalizeClaimIds(options) {
  if (typeof options.claimId === "string" && options.claimId.length > 0) {
    return [options.claimId];
  }
  if (Array.isArray(options.claimIds) && options.claimIds.every((claim) => typeof claim === "string" && claim.length > 0)) {
    return [...options.claimIds];
  }
  throw new NotaryCallerError("options.claimId or options.claimIds is required", {
    code: "claim.required",
  });
}

function normalizeMultiClaimPolicy(policy) {
  const normalized = policy ?? DEFAULT_MULTI_CLAIM_POLICY;
  if (!["all_must_be_satisfied", "per_claim_routing"].includes(normalized)) {
    throw new NotaryCallerError("unsupported multi-claim policy", {
      code: "multi_claim_policy.unsupported",
    });
  }
  return normalized;
}

function buildTarget(data, target) {
  if (!target || typeof target !== "object" || Array.isArray(target)) {
    throw new NotaryCallerError("options.target is required", { code: "target.required" });
  }
  const built = {
    type: requireString(target.type, "target.type"),
  };
  if (target.id !== undefined) {
    built.id = resolveValue(data, target.id, "target.id");
  }
  if (Array.isArray(target.identifiers)) {
    built.identifiers = target.identifiers.map((identifier, index) => ({
      scheme: requireString(identifier?.scheme, `target.identifiers[${index}].scheme`),
      value: resolveValue(data, identifier.value ?? valueFrom(data, identifier.valueFrom), `target.identifiers[${index}].value`),
      ...(identifier.issuer ? { issuer: identifier.issuer } : {}),
      ...(identifier.country ? { country: identifier.country } : {}),
    }));
  }
  if (!built.id && (!Array.isArray(built.identifiers) || built.identifiers.length === 0)) {
    throw new NotaryCallerError("target requires id or identifiers", { code: "target.identifier_required" });
  }
  return built;
}

function redactDataPaths(options, existing = []) {
  const paths = new Set(Array.isArray(existing) ? existing.filter((path) => typeof path === "string" && path.length > 0) : []);
  if (Array.isArray(options.redactDataPaths)) {
    for (const path of options.redactDataPaths) {
      if (typeof path === "string" && path.length > 0) {
        paths.add(path);
      }
    }
  }
  for (const identifier of options.target?.identifiers ?? []) {
    if (typeof identifier?.valueFrom === "string" && identifier.valueFrom.length > 0) {
      paths.add(identifier.valueFrom);
    }
  }
  return [...paths];
}

function deleteDataPath(data, path) {
  const parts = safePathParts(path);
  if (!parts || parts.length === 0) {
    return;
  }
  if (parts.length === 1) {
    delete data[parts[0]];
    return;
  }
  let current = data;
  for (let index = 0; index < parts.length - 1; index += 1) {
    const part = parts[index];
    if (!isPlainObject(current) || !Object.hasOwn(current, part)) {
      return;
    }
    const next = current[part];
    if (!isPlainObject(next)) {
      return;
    }
    current[part] = { ...next };
    current = current[part];
  }
  delete current[parts[parts.length - 1]];
}

function valueFrom(data, path) {
  const parts = safePathParts(path);
  if (!parts || parts.length === 0) {
    return undefined;
  }
  let current = data;
  for (const part of parts) {
    if (!isPlainObject(current) || !Object.hasOwn(current, part)) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function safePathParts(path) {
  if (typeof path !== "string" || path.length === 0) {
    return undefined;
  }
  const parts = path.split(".").filter((part) => part.length > 0);
  if (parts.some((part) => UNSAFE_PATH_PARTS.has(part))) {
    return undefined;
  }
  return parts;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function resolveValue(_data, value, label) {
  if (value === undefined || value === null || value === "") {
    throw new NotaryCallerError(`${label} is required`, { code: "target.value_required" });
  }
  return String(value);
}

function normalizeRelationship(relationship) {
  if (!relationship || typeof relationship !== "object" || Array.isArray(relationship)) {
    throw new NotaryCallerError("relationship must be an object", { code: "relationship.invalid" });
  }
  const type = stringOrUndefined(relationship.type) ?? stringOrUndefined(relationship.relationship_type);
  if (type !== undefined) {
    return {
      type,
      ...(relationship.attributes && typeof relationship.attributes === "object" && !Array.isArray(relationship.attributes)
        ? { attributes: { ...relationship.attributes } }
        : {}),
    };
  }
  throw new NotaryCallerError("relationship type is required", { code: "relationship.type_required" });
}

function fingerprintTarget(configuration, target, options) {
  if (typeof options.targetFingerprint === "string" && options.targetFingerprint.length > 0) {
    return options.targetFingerprint;
  }
  const key = requireString(
    configuration.openfn_target_fingerprint_key
      ?? configuration.openfn_request_fingerprint_key
      ?? configuration.notary_target_fingerprint_key,
    "configuration.openfn_target_fingerprint_key",
  );
  return createHmac("sha256", key)
    .update(JSON.stringify(target))
    .digest("hex");
}

function dataObject(state) {
  if (!state?.data || typeof state.data !== "object" || Array.isArray(state.data)) {
    throw new NotaryCallerError("state.data must be an object", { code: "state.data_required" });
  }
  return state.data;
}

function configurationObject(state) {
  if (!state?.configuration || typeof state.configuration !== "object" || Array.isArray(state.configuration)) {
    throw new NotaryCallerError("state.configuration must be an object", { code: "state.configuration_required" });
  }
  return state.configuration;
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new NotaryCallerError(`${label} must be a non-empty string`, { code: "string.required" });
  }
  return value;
}

function stringOrUndefined(value) {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberOrUndefined(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function trimTrailingSlash(value) {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") {
    end -= 1;
  }
  return value.slice(0, end);
}

function statusToFallbackCode(status) {
  if (status === 429) {
    return "rate_limited";
  }
  if (status === 503) {
    return "source.unavailable";
  }
  return "request.invalid";
}

async function readJsonResponse(response) {
  const text = await response.text();
  if (text.length === 0) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch (_error) {
    throw new NotaryCallerError("Notary response body was not valid JSON", {
      code: "response.invalid_json",
    });
  }
}

function headersObject(headers) {
  const out = {};
  if (!headers || typeof headers !== "object") {
    return out;
  }
  if (typeof headers.forEach === "function") {
    headers.forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      out[key] = value.join(", ");
    } else if (value !== undefined && value !== null) {
      out[key] = String(value);
    }
  }
  return out;
}
