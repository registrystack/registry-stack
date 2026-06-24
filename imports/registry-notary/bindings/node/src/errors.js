/**
 * Base class for Registry Notary client errors.
 */
export class NotaryError extends Error {
  /**
   * @param {string} message
   * @param {{ kind?: string, code?: string, retryable?: boolean, requestId?: string, retryAfter?: number | string, cause?: unknown }} [options]
   */
  constructor(message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "NotaryError";
    this.kind = options.kind ?? "client";
    this.code = options.code;
    this.retryable = options.retryable ?? false;
    this.requestId = options.requestId;
    this.retryAfter = options.retryAfter;
  }

  toJSON() {
    /** @type {{ kind: string, code?: string, retryable: boolean, request_id?: string, retry_after?: number | string, title: string }} */
    const json = {
      kind: this.kind,
      code: this.code,
      retryable: this.retryable,
      request_id: this.requestId,
      title: this.message,
    };
    if (this.retryAfter !== undefined) {
      json.retry_after = this.retryAfter;
    }
    return json;
  }
}

/**
 * Transport-level error such as a network failure or caller abort.
 */
export class NotaryTransportError extends NotaryError {
  /**
   * @param {{ kind?: string, code?: string, retryable?: boolean, requestId?: string, retryAfter?: number | string, cause?: unknown }} [options]
   */
  constructor(options = {}) {
    super("registry notary transport error", {
      kind: options.kind ?? "transport",
      code: options.code ?? "transport_error",
      retryable: options.retryable ?? true,
      requestId: options.requestId,
      retryAfter: options.retryAfter,
      cause: options.cause,
    });
    this.name = "NotaryTransportError";
  }
}

/**
 * Error mapped from Registry Notary Problem Details or response decoding.
 */
export class NotaryProblemError extends NotaryError {
  /**
   * @param {{
   *   kind?: string,
   *   status?: number,
   *   code?: string,
   *   title?: string,
   *   retryable?: boolean,
   *   requestId?: string,
   *   retryAfter?: number | string,
   *   problemType?: string,
   *   cause?: unknown
   * }} options
   */
  constructor(options) {
    const title = options.title ?? "Registry Notary request failed";
    const code = options.code ?? (options.status === undefined ? "notary_problem" : `http.${options.status}`);
    const statusPrefix = options.status === undefined ? "" : `${options.status} `;
    super(`registry notary problem (${statusPrefix}${code}): ${title}`, {
      kind: options.kind ?? "problem",
      code,
      retryable: options.retryable ?? false,
      requestId: options.requestId,
      retryAfter: options.retryAfter,
      cause: options.cause,
    });
    this.name = "NotaryProblemError";
    this.status = options.status;
    this.title = title;
    this.problemType = options.problemType;
  }

  toJSON() {
    /** @type {{ kind: string, status?: number, code?: string, title: string, retryable: boolean, request_id?: string, retry_after?: number | string }} */
    const json = {
      kind: this.kind,
      status: this.status,
      code: this.code,
      title: this.title,
      retryable: this.retryable,
      request_id: this.requestId,
    };
    if (this.retryAfter !== undefined) {
      json.retry_after = this.retryAfter;
    }
    return json;
  }
}
