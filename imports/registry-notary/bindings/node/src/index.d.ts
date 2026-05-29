export interface RegistryNotaryClientOptions {
  baseUrl: string;
  bearerToken?: string;
  apiKey?: string;
  defaultPurpose?: string;
  userAgent?: string;
  retryPolicy?: Partial<RetryPolicy>;
  fetch?: typeof fetch;
}

export interface RetryPolicy {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  retryTransportErrors: boolean;
  retryRateLimited: boolean;
  retryUnavailable: boolean;
}

export interface RequestOptions {
  purpose?: string;
  requestId?: string;
  traceparent?: string;
  signal?: AbortSignal;
}

export interface BatchRequestOptions extends RequestOptions {
  idempotencyKey?: string;
}

export interface GetRequestOptions {
  requestId?: string;
  signal?: AbortSignal;
}

export interface EvaluateSubject {
  id: string;
  idType?: string;
}

export interface EvaluateRequest {
  subject: EvaluateSubject;
  claims: Array<string | { id: string; version?: string }>;
  disclosure?: string;
  format?: string;
  purpose?: string;
  signal?: AbortSignal;
}

export interface RawEvaluateSubject {
  id: string;
  id_type?: string;
}

export interface RawEvaluateRequest {
  subject: RawEvaluateSubject;
  claims: Array<string | { id: string; version?: string }>;
  disclosure?: string;
  format?: string;
  purpose?: string;
  [key: string]: unknown;
}

export interface BatchSubject {
  id: string;
  idType?: string;
  purpose?: string;
}

export interface BatchEvaluateRequest {
  subjects: BatchSubject[];
  claims: Array<string | { id: string; version?: string }>;
  disclosure?: string;
  format?: string;
  purpose?: string;
  signal?: AbortSignal;
}

export interface RawBatchSubject {
  id: string;
  id_type?: string;
  purpose?: string;
}

export interface RawBatchEvaluateRequest {
  subjects: RawBatchSubject[];
  claims: Array<string | { id: string; version?: string }>;
  disclosure?: string;
  format?: string;
  purpose?: string;
  [key: string]: unknown;
}

export class RegistryNotaryClient {
  constructor(options: RegistryNotaryClientOptions);
  evaluate(request: EvaluateRequest, options?: RequestOptions): Promise<unknown>;
  evaluateRequest(request: RawEvaluateRequest, options?: RequestOptions): Promise<unknown>;
  batchEvaluate(request: BatchEvaluateRequest, options?: BatchRequestOptions): Promise<unknown>;
  batchEvaluateRequest(request: RawBatchEvaluateRequest, options?: BatchRequestOptions): Promise<unknown>;
  listClaims(options?: GetRequestOptions): Promise<unknown>;
  getClaim(claimId: string, options?: GetRequestOptions): Promise<unknown>;
  serviceDocument(options?: GetRequestOptions): Promise<unknown>;
  issuerJwks(options?: GetRequestOptions): Promise<unknown>;
  refreshJwks(options?: GetRequestOptions): Promise<unknown>;
  rawIssuerJwks(options?: GetRequestOptions): Promise<unknown>;
  getJwk(kid: string, options?: GetRequestOptions): Promise<Record<string, unknown> | undefined>;
  renderRequest(request: Record<string, unknown>, options?: RequestOptions): Promise<unknown>;
  issueCredentialRequest(request: Record<string, unknown>, options?: RequestOptions): Promise<unknown>;
  credentialStatus(credentialId: string, options?: GetRequestOptions): Promise<unknown>;
  oid4vciIssuerMetadata(options?: GetRequestOptions): Promise<unknown>;
  oid4vciCredentialOffer(credentialConfigurationId?: string, options?: GetRequestOptions): Promise<unknown>;
  oid4vciNonce(request?: Record<string, unknown>, options?: RequestOptions): Promise<unknown>;
  oid4vciCredential(request: Record<string, unknown>, options?: RequestOptions): Promise<unknown>;
  federationEvaluateJws(compactJws: string, options?: RequestOptions): Promise<string>;
}

export class NotaryError extends Error {
  constructor(
    message: string,
    options?: {
      kind?: string;
      code?: string;
      retryable?: boolean;
      requestId?: string;
      retryAfter?: number | string;
      cause?: unknown;
    },
  );
  readonly kind: string;
  readonly code?: string;
  readonly retryable: boolean;
  readonly requestId?: string;
  readonly retryAfter?: number | string;
  toJSON(): {
    kind: string;
    code?: string;
    retryable: boolean;
    request_id?: string;
    retry_after?: number | string;
    title: string;
  };
}

export class NotaryTransportError extends NotaryError {
  constructor(options?: {
    kind?: string;
    code?: string;
    retryable?: boolean;
    requestId?: string;
    retryAfter?: number | string;
    cause?: unknown;
  });
}

export class NotaryProblemError extends NotaryError {
  constructor(options: {
    kind?: string;
    status?: number;
    code?: string;
    title?: string;
    retryable?: boolean;
    requestId?: string;
    retryAfter?: number | string;
    problemType?: string;
    cause?: unknown;
  });
  readonly status?: number;
  readonly title: string;
  readonly problemType?: string;
  toJSON(): {
    kind: string;
    status?: number;
    code?: string;
    title: string;
    retryable: boolean;
    request_id?: string;
    retry_after?: number | string;
  };
}
