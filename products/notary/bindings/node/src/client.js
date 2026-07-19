import { camelToSnakeKey, convertJsonKeys, snakeToCamelKey } from "./case.js";
import { NotaryError, NotaryProblemError, NotaryTransportError } from "./errors.js";

const CLAIM_RESULT_JSON = "application/vnd.registry-notary.claim-result+json";
const APPLICATION_JWT = "application/jwt";
const PROBLEM_JSON = "application/problem+json";
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const JWKS_TTL_MS = 10 * 60 * 1000;
const MAX_REDIRECTS = 10;
/** @type {RequestRedirect} */
const MANUAL_REDIRECT = "manual";

const DEFAULT_RETRY_POLICY = Object.freeze({
  maxAttempts: 1,
  baseDelayMs: 50,
  maxDelayMs: 1000,
  retryTransportErrors: false,
  retryRateLimited: false,
  retryUnavailable: false,
});

/**
 * Promise-based Registry Notary Node.js client.
 */
export class RegistryNotaryClient {
  #apiKey;
  #baseUrl;
  #bearerToken;
  #defaultPurpose;
  #fetch;
  /** @type {{ body: unknown, expiresAt: number } | undefined} */
  #jwksCache;
  /** @type {ReturnType<typeof normalizeRetryPolicy>} */
  #retryPolicy;
  #userAgent;

  /**
   * @param {{
   *   baseUrl: string,
   *   bearerToken?: string,
   *   apiKey?: string,
   *   defaultPurpose?: string,
   *   userAgent?: string,
   *   retryPolicy?: Partial<typeof DEFAULT_RETRY_POLICY>,
   *   fetch?: typeof fetch
   * }} options
   */
  constructor(options) {
    if (!options || typeof options.baseUrl !== "string" || options.baseUrl.length === 0) {
      throw new NotaryError("baseUrl is required", { code: "invalid_base_url" });
    }
    if (options.bearerToken !== undefined && options.apiKey !== undefined) {
      throw new NotaryError("only one auth mode can be configured", { code: "multiple_auth_modes" });
    }

    this.#baseUrl = normalizeBaseUrl(options.baseUrl);
    this.#bearerToken = options.bearerToken;
    this.#apiKey = options.apiKey;
    this.#defaultPurpose = options.defaultPurpose;
    this.#userAgent = options.userAgent;
    this.#retryPolicy = normalizeRetryPolicy(options.retryPolicy);
    this.#fetch = options.fetch;
    this.#jwksCache = undefined;
  }

  /**
   * High-level evaluate API. Accepts camelCase object keys and returns response
   * object keys converted to camelCase.
   *
   * @param {Record<string, unknown> & { signal?: AbortSignal }} request
   * @param {{ purpose?: string, requestId?: string, traceparent?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async evaluate(request, options = {}) {
    const { signal: requestSignal, ...bodyRequest } = request;
    const body = /** @type {Record<string, unknown>} */ (convertJsonKeys(bodyRequest, camelToSnakeKey));
    const response = await this.evaluateRequest(body, {
      ...options,
      signal: options.signal ?? requestSignal,
      camelCaseResponse: true,
    });
    return response;
  }

  /**
   * Low-level evaluate API. Request JSON is the canonical snake_case wire shape.
   *
   * @param {Record<string, unknown>} request
   * @param {{
   *   purpose?: string,
   *   requestId?: string,
   *   request_id?: string,
   *   traceparent?: string,
   *   signal?: AbortSignal,
   *   camelCaseResponse?: boolean
   * }} [options]
   * @returns {Promise<unknown>}
   */
  async evaluateRequest(request, options = {}) {
    rejectEvaluateOnlyOptions(options);
    const bodyPurpose = stringProperty(request, "purpose");
    const headerPurpose = options.purpose ?? this.#defaultPurpose;
    assertPurposeCompatible(bodyPurpose, headerPurpose);

    const body = await this.requestJson("/v1/evaluations", request, {
      accept: CLAIM_RESULT_JSON,
      purpose: headerPurpose,
      requestId: options.requestId ?? options.request_id,
      traceparent: options.traceparent,
      signal: options.signal,
      retryKind: "post_no_retry",
    });

    if (options.camelCaseResponse === true) {
      return convertJsonKeys(body, snakeToCamelKey);
    }
    return body;
  }

  /**
   * High-level batch evaluation API. Accepts camelCase object keys and returns
   * response object keys converted to camelCase.
   *
   * @param {Record<string, unknown> & { signal?: AbortSignal }} request
   * @param {{ purpose?: string, requestId?: string, traceparent?: string, idempotencyKey?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async batchEvaluate(request, options = {}) {
    const { signal: requestSignal, ...bodyRequest } = request;
    const body = /** @type {Record<string, unknown>} */ (convertJsonKeys(bodyRequest, camelToSnakeKey));
    const response = await this.batchEvaluateRequest(body, {
      ...options,
      signal: options.signal ?? requestSignal,
      camelCaseResponse: true,
    });
    return response;
  }

  /**
   * Low-level batch evaluation API. Request JSON is the canonical snake_case
   * wire shape.
   *
   * @param {Record<string, unknown>} request
   * @param {{
   *   purpose?: string,
   *   requestId?: string,
   *   request_id?: string,
   *   traceparent?: string,
   *   idempotencyKey?: string,
   *   idempotency_key?: string,
   *   signal?: AbortSignal,
   *   camelCaseResponse?: boolean
   * }} [options]
   * @returns {Promise<unknown>}
   */
  async batchEvaluateRequest(request, options = {}) {
    const bodyPurpose = stringProperty(request, "purpose");
    const headerPurpose = options.purpose ?? this.#defaultPurpose;
    assertPurposeCompatible(bodyPurpose, headerPurpose);

    const body = await this.requestJson("/v1/batch-evaluations", request, {
      accept: CLAIM_RESULT_JSON,
      purpose: headerPurpose,
      requestId: options.requestId ?? options.request_id,
      traceparent: options.traceparent,
      idempotencyKey: options.idempotencyKey ?? options.idempotency_key,
      signal: options.signal,
      retryKind: "post_batch",
    });

    if (options.camelCaseResponse === true) {
      return convertJsonKeys(body, snakeToCamelKey);
    }
    return body;
  }

  /**
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async listClaims(options = {}) {
    return await this.getJson("/v1/claims", {
      accept: "application/json",
      requestId: options.requestId,
      signal: options.signal,
    });
  }

  /**
   * @param {string} claimId
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async getClaim(claimId, options = {}) {
    return await this.getJson(`/v1/claims/${encodeURIComponent(claimId)}`, {
      accept: "application/json",
      requestId: options.requestId,
      signal: options.signal,
    });
  }

  /**
   * Render evidence from canonical snake_case JSON.
   *
   * `evaluation_id` is required in the request object and is used as the route
   * path parameter. It is not sent in the request body.
   *
   * @param {Record<string, unknown>} request
   * @param {{ requestId?: string, traceparent?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async renderRequest(request, options = {}) {
    if (request === null || request === undefined || typeof request !== "object" || Array.isArray(request)) {
      throw new NotaryError("render request requires a request object", {
        kind: "client",
        code: "request.invalid_type",
      });
    }
    const evaluationId = stringProperty(request, "evaluation_id");
    if (evaluationId === undefined || evaluationId.length === 0) {
      throw new NotaryError("render request requires evaluation_id", {
        kind: "client",
        code: "request.missing_evaluation_id",
      });
    }
    const { evaluation_id: _evaluationId, ...body } = request;
    return await this.requestJson(`/v1/evaluations/${encodeURIComponent(evaluationId)}/render`, body, {
      accept: "application/json",
      requestId: options.requestId,
      traceparent: options.traceparent,
      signal: options.signal,
      retryKind: "post_no_retry",
    });
  }

  /**
   * @param {Record<string, unknown>} request
   * @param {{ requestId?: string, traceparent?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async issueCredentialRequest(request, options = {}) {
    return await this.requestJson("/v1/credentials", request, {
      accept: "application/json",
      requestId: options.requestId,
      traceparent: options.traceparent,
      signal: options.signal,
      retryKind: "post_no_retry",
    });
  }

  /**
   * @param {string} credentialId
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async credentialStatus(credentialId, options = {}) {
    return await this.getJson(`/v1/credentials/${encodeURIComponent(credentialId)}/status`, {
      accept: "application/json",
      requestId: options.requestId,
      signal: options.signal,
    });
  }

  /**
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async serviceDocument(options = {}) {
    return await this.getJson("/.well-known/evidence-service", {
      accept: "application/json",
      requestId: options.requestId,
      signal: options.signal,
    });
  }

  /**
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async issuerJwks(options = {}) {
    if (options.requestId === undefined && this.#jwksCache !== undefined && this.#jwksCache.expiresAt > Date.now()) {
      return this.#jwksCache.body;
    }
    return await this.refreshJwks(options);
  }

  /**
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async refreshJwks(options = {}) {
    const body = await this.rawIssuerJwks(options);
    this.#jwksCache = { body, expiresAt: Date.now() + JWKS_TTL_MS };
    return body;
  }

  /**
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async rawIssuerJwks(options = {}) {
    return await this.getJson("/.well-known/evidence/jwks.json", {
      accept: "application/json",
      requestId: options.requestId,
      signal: options.signal,
    });
  }

  /**
   * @param {string} kid
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<Record<string, unknown> | undefined>}
   */
  async getJwk(kid, options = {}) {
    const cached = await this.issuerJwks(options);
    const found = findJwk(cached, kid);
    if (found !== undefined) {
      return found;
    }
    const refreshed = await this.refreshJwks(options);
    return findJwk(refreshed, kid);
  }

  /**
   * @param {{ requestId?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async oid4vciIssuerMetadata(options = {}) {
    return await this.getJson("/.well-known/openid-credential-issuer", {
      accept: "application/json",
      requestId: options.requestId,
      signal: options.signal,
      errorKind: "oid4vci",
    });
  }

  /**
   * @param {Record<string, unknown>} request
   * @param {{ requestId?: string, traceparent?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<unknown>}
   */
  async oid4vciCredential(request, options = {}) {
    return await this.requestJson("/oid4vci/credential", request, {
      accept: "application/json",
      requestId: options.requestId,
      traceparent: options.traceparent,
      signal: options.signal,
      retryKind: "post_no_retry",
      errorKind: "oid4vci",
    });
  }

  /**
   * @param {string} compactJws
   * @param {{ requestId?: string, traceparent?: string, signal?: AbortSignal }} [options]
   * @returns {Promise<string>}
   */
  async federationEvaluateJws(compactJws, options = {}) {
    return await this.requestText("/federation/v1/evaluations", compactJws, {
      accept: APPLICATION_JWT,
      contentType: APPLICATION_JWT,
      requestId: options.requestId,
      traceparent: options.traceparent,
      signal: options.signal,
      retryKind: "post_no_retry",
    });
  }

  /**
   * @param {string} path
   * @param {{ accept: string, requestId?: string, signal?: AbortSignal, errorKind?: string }} options
   */
  async getJson(path, options) {
    const headers = this.headersFor(options);
    const response = await this.sendWithRetry("get", undefined, options.signal, async () => {
      return await this.sendOnce(path, {
        method: "GET",
        headers,
        signal: options.signal,
      });
    });

    return await parseJsonResponse(response, options.errorKind);
  }

  /**
   * @param {string} path
   * @param {Record<string, unknown>} request
   * @param {{ accept: string, purpose?: string, requestId?: string, traceparent?: string, idempotencyKey?: string, signal?: AbortSignal, retryKind?: string, errorKind?: string }} options
   */
  async requestJson(path, request, options) {
    const headers = this.headersFor(options);
    const response = await this.sendWithRetry(options.retryKind ?? "post_no_retry", options.idempotencyKey, options.signal, async () => {
      return await this.sendOnce(path, {
        method: "POST",
        headers,
        body: JSON.stringify(request),
        signal: options.signal,
      });
    });

    return await parseJsonResponse(response, options.errorKind);
  }

  /**
   * @param {string} path
   * @param {string} request
   * @param {{ accept: string, contentType: string, requestId?: string, traceparent?: string, signal?: AbortSignal, retryKind?: string }} options
   */
  async requestText(path, request, options) {
    const headers = this.headersFor({ ...options, accept: options.accept });
    headers.set("content-type", options.contentType);
    const response = await this.sendWithRetry(options.retryKind ?? "post_no_retry", undefined, options.signal, async () => {
      return await this.sendOnce(path, {
        method: "POST",
        headers,
        body: request,
        signal: options.signal,
      });
    });

    return await parseTextResponse(response);
  }

  /**
   * @param {string} retryKind
   * @param {string | undefined} idempotencyKey
   * @param {AbortSignal | undefined} signal
   * @param {() => Promise<Response>} sendOnce
   * @returns {Promise<Response>}
   */
  async sendWithRetry(retryKind, idempotencyKey, signal, sendOnce) {
    const attempts = allowedAttempts(this.#retryPolicy, retryKind, idempotencyKey);
    for (let attempt = 1; ; attempt += 1) {
      try {
        const response = await sendOnce();
        if (response.ok) {
          return response;
        }
        if (attempt < attempts && shouldRetryResponse(this.#retryPolicy, response)) {
          await sleep(retryDelayMs(this.#retryPolicy, attempt, response), signal);
          continue;
        }
        return response;
      } catch (error) {
        const mapped = mapTransportError(error);
        if (attempt < attempts && this.#retryPolicy.retryTransportErrors && mapped.retryable) {
          await sleep(retryDelayMs(this.#retryPolicy, attempt), signal);
          continue;
        }
        throw mapped;
      }
    }
  }

  /**
   * @param {string} path
   * @param {RequestInit} init
   */
  async sendOnce(path, init) {
    const fetchImpl = this.#fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new NotaryTransportError({ code: "fetch_unavailable", retryable: false });
    }
    let url = new URL(path.replace(/^\//, ""), this.#baseUrl);
    /** @type {RequestInit & { headers: Headers }} */
    let requestInit = { ...init, headers: new Headers(init.headers), redirect: MANUAL_REDIRECT };
    for (let redirectCount = 0; ; redirectCount += 1) {
      const response = await fetchImpl(url, requestInit);
      if (!isRedirectResponse(response)) {
        return response;
      }
      const location = response.headers.get("location");
      if (location === null) {
        return response;
      }
      if (redirectCount >= MAX_REDIRECTS) {
        throw new NotaryTransportError({ code: "redirect_loop", retryable: false });
      }
      const nextUrl = new URL(location, url);
      const headers = new Headers(requestInit.headers);
      if (nextUrl.origin !== url.origin) {
        headers.delete("authorization");
        headers.delete("x-api-key");
      }
      requestInit = redirectInitForNextRequest(requestInit, headers, response.status);
      url = nextUrl;
    }
  }

  /**
   * @param {{ accept: string, purpose?: string, requestId?: string, traceparent?: string, idempotencyKey?: string }} options
   */
  headersFor(options) {
    const headers = new Headers({
      accept: options.accept,
      "content-type": "application/json",
    });
    if (this.#bearerToken !== undefined) {
      headers.set("authorization", `Bearer ${this.#bearerToken}`);
    }
    if (this.#apiKey !== undefined) {
      headers.set("x-api-key", this.#apiKey);
    }
    if (this.#userAgent !== undefined) {
      headers.set("user-agent", this.#userAgent);
    }
    if (options.purpose !== undefined) {
      headers.set("data-purpose", options.purpose);
    }
    if (options.requestId !== undefined) {
      headers.set("x-request-id", options.requestId);
    }
    if (options.traceparent !== undefined) {
      headers.set("traceparent", options.traceparent);
    }
    if (options.idempotencyKey !== undefined) {
      headers.set("Idempotency-Key", options.idempotencyKey);
    }
    return headers;
  }
}

/**
 * @param {Response} response
 */
function isRedirectResponse(response) {
  return [301, 302, 303, 307, 308].includes(response.status);
}

/**
 * @param {RequestInit & { headers: Headers }} init
 * @param {Headers} headers
 * @param {number} status
 * @returns {RequestInit & { headers: Headers }}
 */
function redirectInitForNextRequest(init, headers, status) {
  const method = (init.method ?? "GET").toUpperCase();
  if (status === 303 || ((status === 301 || status === 302) && method === "POST")) {
    headers.delete("content-type");
    headers.delete("content-length");
    const next = { ...init, method: "GET", headers, redirect: MANUAL_REDIRECT };
    delete next.body;
    return next;
  }
  return { ...init, headers, redirect: MANUAL_REDIRECT };
}

/**
 * @param {Response} response
 * @param {string | undefined} requestId
 */
async function problemErrorFromResponse(response, requestId, errorKind = "problem") {
  const contentType = response.headers.get("content-type") ?? "";
  let payload = undefined;
  if (contentType.toLowerCase().startsWith(PROBLEM_JSON) || contentType.toLowerCase().includes("json")) {
    try {
      payload = JSON.parse(await readBoundedText(response, requestId));
    } catch {
      payload = undefined;
    }
  }

  if (errorKind === "oid4vci" && isRecord(payload)) {
    const status = response.status;
    return new NotaryProblemError({
      kind: "oid4vci",
      status,
      code: stringProperty(payload, "error") ?? `http.${status}`,
      title: "OID4VCI request failed",
      retryable: isRetryableStatus(status),
      requestId,
      retryAfter: parseRetryAfter(response.headers.get("retry-after")),
    });
  }

  if (isRecord(payload)) {
    const status = numberProperty(payload, "status") ?? response.status;
    return new NotaryProblemError({
      kind: stringProperty(payload, "kind") ?? "problem",
      status,
      code: stringProperty(payload, "code") ?? `http.${status}`,
      title: stringProperty(payload, "title") ?? response.statusText,
      retryable: booleanProperty(payload, "retryable") ?? isRetryableStatus(status),
      requestId: stringProperty(payload, "request_id") ?? requestId,
      retryAfter: parseRetryAfter(response.headers.get("retry-after")),
      problemType: stringProperty(payload, "type"),
    });
  }

  return new NotaryProblemError({
    kind: "http",
    status: response.status,
    code: `http.${response.status}`,
    title: response.statusText,
    retryable: isRetryableStatus(response.status),
    requestId,
    retryAfter: parseRetryAfter(response.headers.get("retry-after")),
  });
}

/**
 * @param {string} baseUrl
 */
function normalizeBaseUrl(baseUrl) {
  let url;
  try {
    url = new URL(baseUrl);
  } catch (error) {
    throw new NotaryError("invalid baseUrl", { code: "invalid_base_url", cause: error });
  }
  if (!url.pathname.endsWith("/")) {
    url.pathname = `${url.pathname}/`;
  }
  if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) {
    throw new NotaryError("baseUrl must use https unless the host is loopback", { code: "insecure_base_url" });
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new NotaryError("invalid baseUrl", { code: "invalid_base_url" });
  }
  return url;
}

/**
 * @param {Response} response
 * @param {string | undefined} errorKind
 */
async function parseJsonResponse(response, errorKind = "problem") {
  const requestId = response.headers.get("x-request-id") ?? undefined;
  if (!response.ok) {
    throw await problemErrorFromResponse(response, requestId, errorKind);
  }

  try {
    return JSON.parse(await readBoundedText(response, requestId));
  } catch (error) {
    if (error instanceof NotaryProblemError) {
      throw error;
    }
    throw new NotaryProblemError({
      kind: "decode",
      status: response.status,
      code: "decode_error",
      title: "Failed to decode response body",
      retryable: false,
      requestId,
      cause: error,
    });
  }
}

/**
 * @param {Response} response
 */
async function parseTextResponse(response) {
  const requestId = response.headers.get("x-request-id") ?? undefined;
  if (!response.ok) {
    throw await problemErrorFromResponse(response, requestId);
  }

  try {
    return await readBoundedText(response, requestId);
  } catch (error) {
    if (error instanceof NotaryProblemError) {
      throw error;
    }
    throw new NotaryProblemError({
      kind: "decode",
      status: response.status,
      code: "decode_error",
      title: "Failed to decode response body",
      retryable: false,
      requestId,
      cause: error,
    });
  }
}

/**
 * @param {Response} response
 * @param {string | undefined} requestId
 */
async function readBoundedText(response, requestId) {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const parsed = Number.parseInt(contentLength, 10);
    if (Number.isFinite(parsed) && parsed > MAX_RESPONSE_BYTES) {
      throw bodyTooLargeError(response.status, requestId);
    }
  }

  if (response.body === null || typeof response.body.getReader !== "function") {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
      throw bodyTooLargeError(response.status, requestId);
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      try {
        await reader.cancel();
      } catch {
        // Nothing useful to add if cancellation itself fails.
      }
      throw bodyTooLargeError(response.status, requestId);
    }
    chunks.push(value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

/**
 * @param {number} status
 * @param {string | undefined} requestId
 */
function bodyTooLargeError(status, requestId) {
  return new NotaryProblemError({
    kind: "body_too_large",
    status,
    code: "body.too_large",
    title: "Response body exceeded configured size limit",
    retryable: false,
    requestId,
  });
}

/**
 * @param {string} hostname
 */
function isLoopbackHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

/**
 * @param {Record<string, unknown>} options
 */
function rejectEvaluateOnlyOptions(options) {
  if (options.idempotencyKey !== undefined || options.idempotency_key !== undefined) {
    throw new NotaryError("idempotency keys are not supported for evaluate", {
      code: "unsupported_idempotency_key",
    });
  }
}

/**
 * @param {string | undefined} bodyPurpose
 * @param {string | undefined} headerPurpose
 */
function assertPurposeCompatible(bodyPurpose, headerPurpose) {
  if (bodyPurpose !== undefined && headerPurpose !== undefined && bodyPurpose !== headerPurpose) {
    throw new NotaryError("request purpose conflicts with header purpose", {
      code: "purpose_conflict",
    });
  }
}

/**
 * @param {unknown} value
 */
function isAbortError(value) {
  return isRecord(value) && value.name === "AbortError";
}

/**
 * @param {number} status
 */
function isRetryableStatus(status) {
  return [408, 425, 429, 500, 502, 503, 504].includes(status);
}

/**
 * @param {Partial<typeof DEFAULT_RETRY_POLICY> | undefined} policy
 */
function normalizeRetryPolicy(policy) {
  return {
    ...DEFAULT_RETRY_POLICY,
    ...(policy ?? {}),
  };
}

/**
 * @param {typeof DEFAULT_RETRY_POLICY} policy
 * @param {string} retryKind
 * @param {string | undefined} idempotencyKey
 */
function allowedAttempts(policy, retryKind, idempotencyKey) {
  if (retryKind === "get") {
    return Math.max(1, policy.maxAttempts);
  }
  if (retryKind === "post_batch" && idempotencyKey !== undefined) {
    return Math.max(1, policy.maxAttempts);
  }
  return 1;
}

/**
 * @param {typeof DEFAULT_RETRY_POLICY} policy
 * @param {Response} response
 */
function shouldRetryResponse(policy, response) {
  return (
    (response.status === 429 && policy.retryRateLimited) ||
    (response.status === 503 && policy.retryUnavailable)
  );
}

/**
 * @param {typeof DEFAULT_RETRY_POLICY} policy
 * @param {number} attempt
 * @param {Response | undefined} response
 */
function retryDelayMs(policy, attempt, response = undefined) {
  const retryAfter = response === undefined ? undefined : response.headers.get("retry-after");
  if (retryAfter !== null && retryAfter !== undefined && /^[0-9]+$/.test(retryAfter.trim())) {
    return Math.min(Number.parseInt(retryAfter.trim(), 10) * 1000, policy.maxDelayMs);
  }
  if (retryAfter !== null && retryAfter !== undefined) {
    const parsed = Date.parse(retryAfter);
    if (Number.isFinite(parsed)) {
      const serverDate = response === undefined ? undefined : response.headers.get("date");
      const parsedServerDate = serverDate === null || serverDate === undefined ? NaN : Date.parse(serverDate);
      const referenceNow = Number.isFinite(parsedServerDate) ? parsedServerDate : Date.now();
      return Math.min(Math.max(0, parsed - referenceNow), policy.maxDelayMs);
    }
  }
  return Math.min(policy.baseDelayMs * 2 ** Math.max(0, attempt - 1), policy.maxDelayMs);
}

/**
 * @param {string | null} value
 * @returns {number | string | undefined}
 */
function parseRetryAfter(value) {
  if (value === null) {
    return undefined;
  }
  const trimmed = value.trim();
  if (/^[0-9]+$/.test(trimmed)) {
    return Number.parseInt(trimmed, 10);
  }
  return Number.isFinite(Date.parse(trimmed)) ? trimmed : undefined;
}

/**
 * @param {number} delayMs
 * @param {AbortSignal | undefined} signal
 */
async function sleep(delayMs, signal) {
  if (delayMs <= 0) {
    return;
  }
  if (signal?.aborted === true) {
    throw new NotaryTransportError({ kind: "abort", code: "aborted", retryable: false });
  }
  await new Promise((resolve, reject) => {
    /** @type {ReturnType<typeof setTimeout> | undefined} */
    let timeout;
    const cleanup = () => {
      if (timeout !== undefined) {
        clearTimeout(timeout);
      }
      signal?.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(new NotaryTransportError({ kind: "abort", code: "aborted", retryable: false }));
    };
    timeout = setTimeout(() => {
      cleanup();
      resolve(undefined);
    }, delayMs);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * @param {unknown} error
 */
function mapTransportError(error) {
  if (error instanceof NotaryError) {
    return error;
  }
  if (isAbortError(error)) {
    return new NotaryTransportError({ kind: "abort", code: "aborted", retryable: false, cause: error });
  }
  return new NotaryTransportError({ cause: error });
}

/**
 * @param {unknown} jwks
 * @param {string} kid
 * @returns {Record<string, unknown> | undefined}
 */
function findJwk(jwks, kid) {
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) {
    return undefined;
  }
  return jwks.keys.find((key) => isRecord(key) && key.kid === kid);
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return value !== null && typeof value === "object";
}

/**
 * @param {Record<string, unknown>} value
 * @param {string} key
 */
function stringProperty(value, key) {
  const item = value[key];
  return typeof item === "string" ? item : undefined;
}

/**
 * @param {Record<string, unknown>} value
 * @param {string} key
 */
function numberProperty(value, key) {
  const item = value[key];
  return typeof item === "number" ? item : undefined;
}

/**
 * @param {Record<string, unknown>} value
 * @param {string} key
 */
function booleanProperty(value, key) {
  const item = value[key];
  return typeof item === "boolean" ? item : undefined;
}
