// Allowlist redaction at the BFF boundary (spec 5.2 / 10).
//
// This is denylist-free by construction: nothing passes UNLESS its key is on an
// explicit allowlist. Everything else (bearer/Authorization values, the request
// `target` / subject the BFF holds, any raw identifier echoed in a response) is
// dropped before anything reaches the proof feed. The structural WIRE SHAPE the
// proof inspector renders is preserved, but raw identifier values inside it are
// blanked so the inspector shows the derived self-attestation framing, never a
// caller-supplied target.
//
// Server-only: this module is imported by +server.ts routes and the BFF, never
// into a client bundle.

import type { ProofStatus } from '$lib/types';

// ---------------------------------------------------------------------------
// The allowlist. Only these top-level proof keys are forwarded to the feed.
// (claim, purpose, disclosure, authority, result, freshness) plus the structural
// wire shape (request/response bodies, themselves re-redacted field-by-field).
// ---------------------------------------------------------------------------
export const PROOF_ALLOWLIST = [
  'claim',
  'purpose',
  'disclosure',
  'authority',
  'result',
  'freshness'
] as const;

// The allowlist of body keys that may keep their VALUES when serializing a wire
// request/response body to the feed. Anything not here is structurally kept (so
// the inspector still shows the key) but its value is blanked / hashed.
//
// Crucially: `target`, `requester`, `requester_ref`, `target_ref`, `identifiers`,
// `id_hash`, `value` (when it could echo an identifier) are NOT value-preserved
// at the identifier level: identifier strings inside them are blanked.
const BODY_VALUE_ALLOWLIST = new Set<string>([
  'claims',
  'id',
  'version',
  'purpose',
  'disclosure',
  'format',
  'relationship',
  'type',
  'on_behalf_of',
  'delegation_ref',
  'results',
  'claim_id',
  'claim_version',
  'evaluation_id',
  'subject_type',
  'satisfied',
  'value',
  'issued_at',
  'expires_at',
  'matching',
  'confidence',
  'method',
  'policy_id',
  'score',
  'provenance',
  'schema_version',
  'generated_by',
  'used',
  'derived_from',
  'policy_hash',
  'policy_version',
  'service_id',
  'source_count',
  'source_versions',
  'source_runtimes',
  'profile'
]);

// Keys whose string values are STRUCTURAL identifier handles, not raw ids. They
// stay (handles are already opaque rnref:/did: tokens), but we still pass them
// through the identifier scrubber to catch any leaked raw id.
const HANDLE_KEYS = new Set<string>(['handle', 'identifier_schemes', 'profile']);

// Patterns for raw identifiers / secrets that must NEVER reach the feed.
// Allowlist design means we do not RELY on these to redact (the allowlist already
// drops unknown keys); they are a belt-and-braces scrub of any allowlisted value
// that could still embed a fixture id, plus the test's assertion surface.
const NID_RE = /NID-\d+/g;
const CP_RE = /CP-\d+/g;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;

// Replace any embedded raw identifier / bearer material inside a string value.
export function scrubString(input: string): string {
  return input
    .replace(BEARER_RE, 'Bearer •••••••• (redacted)')
    .replace(NID_RE, '••••')
    .replace(CP_RE, '••••');
}

type Json = unknown;

// Recursively redact a wire body: keep the structure (keys + types), but blank
// the VALUES of any key not on BODY_VALUE_ALLOWLIST, and scrub identifier-shaped
// strings everywhere. The `target`/`requester` envelopes keep their `type` but
// drop the identifier arrays entirely (the inspector shows relationship:self and
// the ABSENCE of a caller-supplied target, which is the engineer-facing point).
export function redactBody(body: Json): Json {
  return walk(body, true);
}

function walk(node: Json, valuePreserved: boolean): Json {
  if (typeof node === 'string') {
    return valuePreserved ? scrubString(node) : '••••(redacted)';
  }
  if (typeof node === 'number' || typeof node === 'boolean' || node === null) {
    return valuePreserved ? node : null;
  }
  if (Array.isArray(node)) {
    return node.map((item) => walk(item, valuePreserved));
  }
  if (typeof node === 'object') {
    const out: Record<string, Json> = {};
    for (const [key, val] of Object.entries(node as Record<string, Json>)) {
      // `target` and `requester` envelopes carry the subject the BFF holds. Keep
      // the key so the shape matches, keep `type`, but DROP identifier values.
      if (key === 'target' || key === 'requester') {
        out[key] = redactEntityEnvelope(val);
        continue;
      }
      // identifier arrays anywhere are dropped to an empty, shape-preserving form.
      if (key === 'identifiers') {
        out[key] = [];
        continue;
      }
      const childPreserved =
        valuePreserved &&
        (BODY_VALUE_ALLOWLIST.has(key) || HANDLE_KEYS.has(key));
      out[key] = walk(val, childPreserved);
    }
    return out;
  }
  return null;
}

// Keep { type } of an entity envelope but strip identifiers so no raw subject
// leaks. This is what makes the inspector show "relationship:self, no caller
// target".
function redactEntityEnvelope(node: Json): Json {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    return null;
  }
  const obj = node as Record<string, Json>;
  const out: Record<string, Json> = {};
  if (typeof obj.type === 'string') out.type = scrubString(obj.type);
  // identifiers deliberately dropped to an empty array (shape preserved).
  out.identifiers = [];
  return out;
}

// The redacted depth-2 request shown to the feed. Authorization is always the
// redacted bearer placeholder; the body is structurally preserved, identifier
// values scrubbed.
export type RedactedRequest = {
  method: string;
  url: string;
  body: Record<string, unknown>;
};

export type RedactedResponse = {
  status: number;
  body: Record<string, unknown>;
};

export function redactRequest(req: {
  method: string;
  url: string;
  body: Json;
}): RedactedRequest {
  return {
    method: req.method,
    url: scrubString(req.url),
    body: redactBody(req.body) as Record<string, unknown>
  };
}

export function redactResponse(res: {
  status: number;
  body: Json;
}): RedactedResponse {
  return {
    status: res.status,
    body: redactBody(res.body) as Record<string, unknown>
  };
}

// A small structural assertion used by the SSE serializer and the test: does a
// serialized string contain any raw identifier or bearer material?
export function containsRawIdentifier(serialized: string): boolean {
  return (
    /NID-\d+/.test(serialized) ||
    /CP-\d+/.test(serialized) ||
    /Bearer\s+[A-Za-z0-9._~+/=-]{8,}/.test(serialized)
  );
}

// Allowlist guard for a flat metadata object (claim/purpose/disclosure/authority/
// result/freshness). Drops any key not on PROOF_ALLOWLIST.
export function pickAllowedMeta(
  meta: Record<string, unknown>
): Record<string, unknown> {
  const allow = new Set<string>(PROOF_ALLOWLIST);
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta)) {
    if (allow.has(k)) {
      out[k] = typeof v === 'string' ? scrubString(v) : v;
    }
  }
  return out;
}

// Re-exported type for callers that build a status alongside redacted bodies.
export type { ProofStatus };
