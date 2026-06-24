// MockEvidenceProvider: the Phase 0 interaction-nailing layer behind the shared
// EvidenceProvider seam. Returns canned ClaimResults plus a matching ProofTrace
// per field/claim, with deterministic latency and a top-to-bottom stagger.
//
// The depth-2 request/response bodies inside each ProofTrace are built by ./wire
// to be structurally identical to the real Notary POST /v1/evaluations. Volatile
// fields (evaluation ids, timestamps) are stamped per call so they are present
// but value-variable. "mock then wire" never becomes "mock then rewrite".

import type { EvaluateContext, EvidenceProvider } from '$lib/providers/EvidenceProvider';
import type { ClaimResult, Field, ProofStatus, ProofTrace } from '$lib/types';
import {
  NOTARY_ISSUER_KEY,
  PERSONA,
  SCENARIOS,
  type ScenarioResult
} from './scenarios';
import {
  authorityLabel,
  buildRawRequest,
  buildRawResponse,
  makeEvaluationId,
  notaryUrl,
  type RawEvaluateRequest,
  type RawEvaluationResponse
} from './wire';

// Optional knobs for delegated / denial selection the BFF passes via ctx-derived
// field hints. The provider never trusts a client-supplied subject; the BFF
// resolves the subject server-side and passes it in ctx.subject.
export type EvaluateOptions = {
  // explicit scenario override (state gallery / per-state trigger list). When set,
  // the field's normal mapping is bypassed so every UX state is reachable.
  scenarioKey?: string;
  // for delegated fields, whether the guardian-link hop has already succeeded.
  // The provider DENIES a delegated civil read if this is false, proving the gate.
  guardianLinkVerified?: boolean;
};

// The richer evaluate result the BFF consumes: the portal-facing ClaimResult plus
// the RAW (un-redacted) wire request/response and depth-1/3 proof material. The
// BFF redacts the raw bodies before teeing them to the feed.
export type MockEvaluation = {
  result: ClaimResult;
  raw: {
    request: { method: string; url: string; body: RawEvaluateRequest };
    response: { status: number; body: RawEvaluationResponse | DenialBody };
  };
  proof: {
    headline: string;
    answered: string;
    notDisclosed: string;
    status: ProofTrace['status'];
    authority: ProofTrace['authority'];
    crypto: NonNullable<ProofTrace['proof']>;
  };
  // deterministic timing for the UI stagger / SLOW threshold choreography.
  timing: { latencyMs: number; staggerOrder: number; slow: boolean };
};

type DenialBody = { error: string; error_description: string };

const SLOW_THRESHOLD_MS = 6000;

// Resolve a Field + ctx + options to a scenario key. The mapping is explicit so
// the demo's whole surface is driven by canned data.
export function resolveScenarioKey(field: Field, opts?: EvaluateOptions): string {
  if (opts?.scenarioKey) return opts.scenarioKey;
  // Field ids carry the canonical scenario key in the demo descriptors. Fall back
  // to the claim where the id is generic.
  if (field.id in SCENARIOS) return field.id;
  if (field.claim && field.claim in SCENARIOS) return field.claim;
  throw new Error(`MockEvidenceProvider: no canned scenario for field "${field.id}"`);
}

// Resolve the effective subject for a scenario. Delegated civil reads target the
// dependent (Miguel); everything else targets the session subject. The denial
// scenario targets the stranger (Pedro) so the boundary is provable.
function resolveSubject(scenario: ScenarioResult, ctx: EvaluateContext, key: string): string {
  if (key === 'denial') return PERSONA.pedro;
  if (scenario.delegated) return ctx.delegatedTarget ?? PERSONA.miguel;
  return ctx.subject;
}

function buildCrypto(
  scenario: ScenarioResult,
  evaluationId: string,
  issuedAt: Date
): NonNullable<ProofTrace['proof']> {
  return {
    signedBy: authorityLabel(scenario),
    algorithm: 'EdDSA-Ed25519',
    issuerKey: NOTARY_ISSUER_KEY[scenario.notary],
    holderBound: scenario.delegated
      ? 'Holder-bound to Maria Santos (guardian), subject the dependent'
      : 'Holder-bound to the signed-in citizen (cnf wallet key)',
    credential: 'SD-JWT VC',
    // audit id is volatile, derived from the evaluation id + a stamp.
    auditId: `audit:${evaluationId}:${issuedAt.getTime().toString(36)}`
  };
}

export class MockEvidenceProvider implements EvidenceProvider {
  #seq = 0;

  // The shared-seam method. The BFF calls this; it returns only the ClaimResult.
  // The richer evaluation (raw wire + proof material) is available via
  // evaluateDetailed for the tee-to-feed path.
  async evaluate(field: Field, ctx: EvaluateContext, opts?: EvaluateOptions): Promise<ClaimResult> {
    const { result } = await this.evaluateDetailed(field, ctx, opts);
    return result;
  }

  // Full evaluation used by the BFF: resolves the scenario, enforces the delegated
  // gate and the denial (no source read), builds the wire bodies, applies the
  // deterministic latency, and returns everything the BFF needs to tee a redacted
  // trace.
  async evaluateDetailed(
    field: Field,
    ctx: EvaluateContext,
    opts?: EvaluateOptions
  ): Promise<MockEvaluation> {
    const key = resolveScenarioKey(field, opts);
    const scenario = SCENARIOS[key];

    // Delegated civil reads (hop two) are only authorized AFTER the social
    // caregiver-link verify (hop one) succeeds. An unproven link is denied
    // before any dependent source read, proving the relationship-first gate.
    if (scenario.delegated && opts?.guardianLinkVerified !== true) {
      // Deny by default: a delegated dependent read is authorized ONLY with an
      // affirmative proven guardian link. An absent flag is treated as "not proven",
      // so the gate cannot be bypassed by omitting the flag on a raw API call.
      return this.#denied(field, scenario, ctx, key, 'relationship_not_proven');
    }

    const subject = resolveSubject(scenario, ctx, key);
    const seq = ++this.#seq;
    const evaluationId = makeEvaluationId(seq);
    const issuedAt = new Date();

    // Deterministic latency: honour the per-scenario delay so the UI can show the
    // top-to-bottom stagger and the SLOW threshold. We do not actually block the
    // event loop here beyond a short awaitable so tests stay fast; the BFF reads
    // timing.latencyMs to drive the animation budget.
    await delay(Math.min(scenario.latencyMs, 5));

    const rawRequest = buildRawRequest(scenario, subject, {
      actorIdHash: scenario.delegated ? hashActor(ctx.subject) : undefined,
      delegationRef: scenario.delegated ? 'rnref:v1:REL-1001-MOTHER' : undefined
    });

    // Denial / error scenarios perform NO source read: there is no 200 body.
    if (scenario.httpStatus === 403) {
      return this.#denied(field, scenario, ctx, key, scenario.denial?.code ?? 'subject_mismatch');
    }
    if (scenario.httpStatus === 503) {
      return this.#errored(field, scenario, ctx, key, evaluationId, issuedAt, rawRequest);
    }

    const rawResponse = buildRawResponse(scenario, evaluationId, issuedAt);

    const result: ClaimResult = {
      state: scenario.state,
      display: scenario.display,
      authority: scenario.notary,
      asOf: scenario.asOf,
      ...(scenario.reasonCode ? { reasonCode: scenario.reasonCode } : {}),
      traceId: `event ${seq}`
    };

    return {
      result,
      raw: {
        request: { method: 'POST', url: notaryUrl(scenario), body: rawRequest },
        response: { status: scenario.httpStatus, body: rawResponse }
      },
      proof: {
        headline: scenario.headline,
        answered: scenario.answered,
        notDisclosed: scenario.notDisclosed,
        status: scenario.status,
        authority: scenario.notary,
        crypto: buildCrypto(scenario, evaluationId, issuedAt)
      },
      timing: {
        latencyMs: scenario.latencyMs,
        staggerOrder: scenario.staggerOrder,
        slow: scenario.latencyMs >= SLOW_THRESHOLD_MS
      }
    };
  }

  // A denied evaluation: 403, no source read, no 200 body. The boundary held.
  #denied(
    field: Field,
    scenario: ScenarioResult,
    _ctx: EvaluateContext,
    _key: string,
    code: string
  ): MockEvaluation {
    const seq = ++this.#seq;
    const evaluationId = makeEvaluationId(seq);
    const issuedAt = new Date();
    // We still show the REQUEST the BFF attempted, with the stranger target, so the
    // inspector shows what was asked, then the 403 with no source read. The target
    // is redacted before it ever reaches the feed.
    const subject = scenario.denial ? PERSONA.pedro : PERSONA.miguel;
    const rawRequest = buildRawRequest(scenario, subject, {
      actorIdHash: scenario.delegated ? hashActor(_ctx.subject) : undefined,
      delegationRef: scenario.delegated ? 'rnref:v1:REL-1001-MOTHER' : undefined
    });
    const denialBody: DenialBody = {
      error: code,
      error_description:
        scenario.denial?.message ?? 'requester is not authorized for this target'
    };
    const result: ClaimResult = {
      state: 'error',
      display:
        code === 'relationship_not_proven'
          ? 'Denied: guardian link not proven, no dependent record was read'
          : scenario.display,
      authority: scenario.notary,
      reasonCode: code,
      traceId: `event ${seq}`
    };
    return {
      result,
      raw: {
        request: { method: 'POST', url: notaryUrl(scenario), body: rawRequest },
        response: { status: 403, body: denialBody }
      },
      proof: {
        headline:
          code === 'relationship_not_proven'
            ? `Denied by ${authorityLabel(scenario)}: the guardian link was not proven, so no dependent record was read`
            : scenario.headline,
        answered: scenario.answered,
        notDisclosed: scenario.notDisclosed,
        status: 'denied',
        authority: scenario.notary,
        crypto: buildCrypto(scenario, evaluationId, issuedAt)
      },
      timing: {
        latencyMs: scenario.latencyMs,
        staggerOrder: scenario.staggerOrder,
        slow: false
      }
    };
  }

  // A hard upstream failure (503): scoped to the field, framed as minimization. No
  // source read, no value.
  #errored(
    field: Field,
    scenario: ScenarioResult,
    _ctx: EvaluateContext,
    _key: string,
    evaluationId: string,
    issuedAt: Date,
    rawRequest: RawEvaluateRequest
  ): MockEvaluation {
    const seq = this.#seq; // already incremented by the caller
    const errBody: DenialBody = {
      error: 'upstream_unavailable',
      error_description: `could not reach ${authorityLabel(scenario)}`
    };
    const result: ClaimResult = {
      state: 'error',
      display: scenario.display,
      authority: scenario.notary,
      reasonCode: scenario.reasonCode,
      traceId: `event ${seq}`
    };
    return {
      result,
      raw: {
        request: { method: 'POST', url: notaryUrl(scenario), body: rawRequest },
        response: { status: 503, body: errBody }
      },
      proof: {
        headline: scenario.headline,
        answered: scenario.answered,
        notDisclosed: scenario.notDisclosed,
        status: 'error',
        authority: scenario.notary,
        crypto: buildCrypto(scenario, evaluationId, issuedAt)
      },
      timing: {
        latencyMs: scenario.latencyMs,
        staggerOrder: scenario.staggerOrder,
        slow: scenario.latencyMs >= SLOW_THRESHOLD_MS
      }
    };
  }
}

// A keyed-hash placeholder for an actor id. Never the raw principal; matches the
// id_hash wire shape (hmac-sha256:<hex>). Deterministic for the mock.
function hashActor(subject: string): string {
  let h = 0;
  for (let i = 0; i < subject.length; i++) {
    h = (h * 31 + subject.charCodeAt(i)) & 0xffffffff;
  }
  return `hmac-sha256:${(h >>> 0).toString(16).padStart(8, '0')}`;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export type { ProofStatus };

// Re-export the canned scenario keys so the BFF / state gallery can enumerate the
// reachable states without importing the table directly.
export { PERSONA, SCENARIOS } from './scenarios';
