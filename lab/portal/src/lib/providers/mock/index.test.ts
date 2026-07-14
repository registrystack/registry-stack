import { describe, expect, it } from 'vitest';
import type { EvaluateContext } from '$lib/providers/EvidenceProvider';
import type { Field } from '$lib/types';
import { MockEvidenceProvider, PERSONA } from './index';

const provider = new MockEvidenceProvider();
const ctx: EvaluateContext = { subject: PERSONA.maria };

function field(id: string): Field {
  return { id, label: id, kind: 'verify' };
}

describe('MockEvidenceProvider.evaluate', () => {
  it('returns a GREEN verified state for a true predicate', async () => {
    const res = await provider.evaluate(field('registered-farmer'), ctx);
    expect(res.state).toBe('verified');
    expect(res.authority).toBe('agri');
    expect(res.traceId).toMatch(/^event \d+$/);
  });

  it('returns an AMBER false state, still signed with a reason code', async () => {
    const res = await provider.evaluate(field('disability-determination'), ctx);
    expect(res.state).toBe('false');
    expect(res.reasonCode).toBe('SP-DIS-02');
  });

  it('returns a BLUE fetched value for a date', async () => {
    // date-of-birth is a delegated civil read, so the guardian link must be proven
    // for the value to be returned (see the deny-by-default gate).
    const ev = await provider.evaluateDetailed(field('date-of-birth'), ctx, {
      guardianLinkVerified: true
    });
    expect(ev.result.state).toBe('fetched');
    const view = ev.raw.response.body as { results: { value: unknown }[] };
    expect(view.results[0].value).toBe('2016-01-15');
  });

  it('returns a fetched object summary for a certificate', async () => {
    const ev = await provider.evaluateDetailed(field('certificate-summary'), ctx);
    expect(ev.result.state).toBe('fetched');
    const view = ev.raw.response.body as { results: { value: Record<string, unknown> }[] };
    expect(view.results[0].value).toMatchObject({ certificate_type: 'birth' });
  });

  it('returns a multi-authority decision with reason codes', async () => {
    const ev = await provider.evaluateDetailed(field('combined-support-eligibility'), ctx);
    expect(ev.result.state).toBe('verified');
    const view = ev.raw.response.body as { results: { provenance: { used: { relay_consultation_count: number } } }[] };
    expect(view.results[0].provenance.used.relay_consultation_count).toBe(3);
  });
});

describe('denial beat (cross-person stranger)', () => {
  it('produces a 403 subject_mismatch with no Relay consultation', async () => {
    const ev = await provider.evaluateDetailed(field('denial'), ctx);
    expect(ev.result.state).toBe('error');
    expect(ev.result.reasonCode).toBe('subject_mismatch');
    // 403 shape, no 200 results body
    expect(ev.raw.response.status).toBe(403);
    expect(ev.raw.response.body).not.toHaveProperty('results');
    expect(ev.raw.response.body).toHaveProperty('error', 'subject_mismatch');
    // the proof status is a denial; the rail will bounce
    expect(ev.proof.status).toBe('denied');
    // the request targeted the stranger, never the session subject
    const target = ev.raw.request.body.target;
    expect(target.identifiers[0].value).toBe(PERSONA.pedro);
  });

  it('starts no Relay consultation on a denial', async () => {
    const ev = await provider.evaluateDetailed(field('denial'), ctx);
    // there is no 200 results body at all, so no Relay consultation ran
    expect(ev.raw.response.body).not.toHaveProperty('results');
  });
});

describe('delegated two-hop gate', () => {
  it('denies a civil read before the guardian link is proven (no dependent read)', async () => {
    const ev = await provider.evaluateDetailed(field('date-of-birth'), ctx, {
      guardianLinkVerified: false
    });
    expect(ev.result.state).toBe('error');
    expect(ev.raw.response.status).toBe(403);
    expect(ev.raw.response.body).not.toHaveProperty('results');
    expect(ev.proof.status).toBe('denied');
  });

  it('denies a delegated civil read when the guardian flag is omitted (deny by default)', async () => {
    const ev = await provider.evaluateDetailed(field('date-of-birth'), ctx);
    expect(ev.result.state).toBe('error');
    expect(ev.raw.response.status).toBe(403);
    expect(ev.raw.response.body).not.toHaveProperty('results');
    expect(ev.proof.status).toBe('denied');
  });

  it('authorizes the civil read once the guardian link is proven', async () => {
    const ev = await provider.evaluateDetailed(field('date-of-birth'), ctx, {
      guardianLinkVerified: true
    });
    expect(ev.result.state).toBe('fetched');
    expect(ev.raw.response.status).toBe(200);
    // delegated reads carry the on_behalf_of envelope and target the dependent
    expect(ev.raw.request.body.on_behalf_of).toBeDefined();
    expect(ev.raw.request.body.target.identifiers[0].value).toBe(PERSONA.miguel);
  });
});

describe('resilience states', () => {
  it('flags a slow call (>= 6s budget) before it resolves verified', async () => {
    const ev = await provider.evaluateDetailed(field('slow'), ctx);
    expect(ev.timing.slow).toBe(true);
    expect(ev.result.state).toBe('verified');
  });

  it('lands an upstream failure in ERROR with no Relay consultation', async () => {
    const ev = await provider.evaluateDetailed(field('error'), ctx);
    expect(ev.result.state).toBe('error');
    expect(ev.raw.response.status).toBe(503);
    expect(ev.raw.response.body).not.toHaveProperty('results');
  });

  it('marks a fetched-but-old value as stale', async () => {
    const ev = await provider.evaluateDetailed(field('stale'), ctx);
    expect(ev.result.state).toBe('stale');
  });

  it('never collapses an ambiguous match to false', async () => {
    const ev = await provider.evaluateDetailed(field('ambiguous'), ctx);
    expect(ev.result.state).toBe('ambiguous');
  });
});

describe('structural match to the Notary OpenAPI', () => {
  // The depth-2 bodies must carry the same key set as EvaluateRequest /
  // EvaluationResponse -> ClaimResultView. We assert the required key sets here so
  // a drift from the OpenAPI fails loudly.
  it('request body matches EvaluateRequest key set', async () => {
    const ev = await provider.evaluateDetailed(field('registered-farmer'), ctx);
    const body = ev.raw.request.body as Record<string, unknown>;
    expect(Object.keys(body)).toEqual([
      'claims',
      'purpose',
      'disclosure',
      'format',
      'relationship',
      'target'
    ]);
    expect(Object.keys((body.claims as Record<string, unknown>[])[0])).toEqual(['id', 'version']);
  });

  it('200 response result matches the ClaimResultView required key set', async () => {
    const ev = await provider.evaluateDetailed(field('registered-farmer'), ctx);
    const view = (ev.raw.response.body as { results: Record<string, unknown>[] }).results[0];
    // every required key from the OpenAPI ClaimResultView is present
    for (const key of [
      'evaluation_id',
      'claim_id',
      'claim_version',
      'subject_type',
      'target_ref',
      'value',
      'satisfied',
      'disclosure',
      'format',
      'issued_at',
      'expires_at',
      'provenance'
    ]) {
      expect(view).toHaveProperty(key);
    }
    const prov = view.provenance as Record<string, unknown>;
    expect(prov).toHaveProperty('schema_version', 'registry-notary-claim-provenance/v2');
    expect(prov).toHaveProperty('generated_by');
    expect(prov).toHaveProperty('used');
    expect(prov).toHaveProperty('derived_from');
  });

  it('delegated request carries the on_behalf_of envelope shape', async () => {
    const ev = await provider.evaluateDetailed(field('date-of-birth'), ctx, {
      guardianLinkVerified: true
    });
    const oba = ev.raw.request.body.on_behalf_of;
    expect(oba).toBeDefined();
    expect(Object.keys(oba!)).toEqual(['actor', 'delegation_ref']);
    expect(Object.keys(oba!.actor)).toEqual(['type', 'id_hash']);
    // id_hash is a keyed hash, never a raw principal
    expect(oba!.actor.id_hash).toMatch(/^hmac-sha256:/);
  });
});
