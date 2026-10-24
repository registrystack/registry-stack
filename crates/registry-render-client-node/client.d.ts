export interface RenderClientConfig {
  baseUrl: string;
  attemptTimeoutMilliseconds?: number;
  connectTimeoutMilliseconds?: number;
  maximumResponseBytes?: number;
  trustedRootCertificates?: string;
}
export interface RenderedDocument { pdfBase64: string; pdfSha256: string; dataSha256: string; documentVersion: string; warnings: string[]; }
export interface RenderRequest { issuedAt: string; data: unknown; locale?: string; assets?: Record<string,string>; }
export interface TokenProvider { bearerToken(): Promise<string>; }
export class RenderClientError extends Error { kind: string; outcomeUnknown: boolean; transportKind?: "connect" | "timeout" | "exchange" | "response-too-large"; status?: number; code?: string; traceId?: string; }
export class RenderClient { constructor(config: RenderClientConfig); render(token: string | TokenProvider, documentType: string, request: RenderRequest): Promise<RenderedDocument>; }
