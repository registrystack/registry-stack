import { describe, expect, it } from 'vitest';
import {
  containsRawIdentifier,
  pickAllowedMeta,
  redactBody,
  redactRequest,
  redactResponse,
  scrubString
} from './redact';
import { serializeTraceEvent } from './bff';
import type { ProofTrace } from '$lib/types';

// The load-bearing redaction test (spec 5.2 / 10): build a payload containing a
// fixture national id, a person id, and a fake bearer token; run it through the
// redactor AND the SSE serialization; assert NONE of /NID-\d+/, /CP-\d+/, or the
// bearer string survives, and that the allowlisted keys DO.

const FAKE_BEARER = 'Bearer eyJhbGciOiJFZERTQSJ9.FAKE_TOKEN_PAYLOAD.FAKE_SIGNATURE_abc123';

// A raw request body shaped like the BFF's un-redacted EvaluateRequest, carrying
// the subject the BFF holds (NID-2001) and a delegated dependent (NID-1001).
const rawRequest = {
  method: 'POST',
  url: 'https://civil.notary.solmara.gov.example/v1/evaluations',
  body: {
    claims: [{ id: 'person-is-alive', version: '2026-05' }],
    purpose: 'social_cash',
    disclosure: 'predicate',
    format: 'application/vnd.registry-notary.claim-result+json',
    relationship: { type: 'self' },
    target: {
      type: 'Person',
      identifiers: [{ scheme: 'national_id', value: 'NID-2001' }]
    },
    on_behalf_of: {
      actor: { type: 'Person', id_hash: 'hmac-sha256:deadbeef' },
      delegation_ref: 'rnref:v1:REL-1001-MOTHER'
    }
  }
};

// A raw response that echoes a person id (CP-2001) in a target_ref handle, plus a
// freshness timestamp, plus the satisfied predicate.
const rawResponse = {
  status: 200,
  body: {
    results: [
      {
        claim_id: 'person-is-alive',
        claim_version: '2026-05',
        disclosure: 'predicate',
        evaluation_id: '01HX7Y5F2WAJ7ZP0Q4M5K9E8NC',
        expires_at: '2026-05-25T12:00:00Z',
        issued_at: '2026-05-24T12:00:00Z',
        satisfied: true,
        subject_type: 'person',
        target_ref: {
          handle: 'rnref:v1:CP-2001',
          identifier_schemes: ['national_id'],
          profile: 'resident',
          type: 'Person'
        },
        value: true
      }
    ]
  }
};

describe('scrubString', () => {
  it('blanks NID, CP, and bearer material', () => {
    const dirty = 'subject NID-2001 (CP-2001) with Authorization: ' + FAKE_BEARER;
    const clean = scrubString(dirty);
    expect(clean).not.toMatch(/NID-\d+/);
    expect(clean).not.toMatch(/CP-\d+/);
    expect(clean).not.toContain('FAKE_TOKEN_PAYLOAD');
    expect(clean).toContain('Bearer •••••••• (redacted)');
  });
});

describe('redactBody / request / response', () => {
  it('drops identifier values but keeps the structural key set', () => {
    const red = redactRequest(rawRequest);
    const serialized = JSON.stringify(red);
    // raw identifiers gone
    expect(serialized).not.toMatch(/NID-\d+/);
    // structural keys preserved (allowlisted wire shape)
    expect(red.body).toHaveProperty('claims');
    expect(red.body).toHaveProperty('purpose', 'social_cash');
    expect(red.body).toHaveProperty('disclosure', 'predicate');
    expect(red.body).toHaveProperty('relationship');
    // target envelope kept structurally but identifiers stripped
    expect(red.body).toHaveProperty('target');
    const target = red.body.target as { type?: string; identifiers?: unknown[] };
    expect(target.identifiers).toEqual([]);
  });

  it('redacts a response that echoes a person id in a handle', () => {
    const red = redactResponse(rawResponse);
    const serialized = JSON.stringify(red);
    expect(serialized).not.toMatch(/CP-\d+/);
    // allowlisted result keys survive
    const result = (red.body.results as Record<string, unknown>[])[0];
    expect(result).toHaveProperty('claim_id', 'person-is-alive');
    expect(result).toHaveProperty('satisfied', true);
    expect(result).toHaveProperty('issued_at', '2026-05-24T12:00:00Z');
  });
});

describe('SSE serialization is identifier-free end to end', () => {
  it('produces an event frame with no NID / CP / bearer material', () => {
    const trace: ProofTrace = {
      id: 'event 1',
      seq: 1,
      fieldId: 'person-is-alive',
      authority: 'civil',
      headline: 'Confirmed by Civil Registry',
      answered: 'Civil Registry answered: person-is-alive = true',
      notDisclosed: 'Not disclosed: any other civil record detail',
      status: 'ok',
      ts: '2026-06-21T10:00:00.000Z',
      request: redactRequest(rawRequest),
      response: redactResponse(rawResponse)
    };
    const frame = serializeTraceEvent(trace);

    // the streamed bytes carry NONE of the secrets / identifiers
    expect(frame).not.toMatch(/NID-\d+/);
    expect(frame).not.toMatch(/CP-\d+/);
    expect(frame).not.toContain('FAKE_TOKEN_PAYLOAD');
    expect(containsRawIdentifier(frame)).toBe(false);

    // but the allowlisted, structural content DID survive
    expect(frame).toContain('person-is-alive');
    expect(frame).toContain('social_cash');
    expect(frame).toContain('Not disclosed:');
    expect(frame.startsWith('event: trace\ndata: ')).toBe(true);
  });
});

describe('pickAllowedMeta', () => {
  it('keeps only allowlisted keys and scrubs their values', () => {
    const picked = pickAllowedMeta({
      claim: 'person-is-alive',
      purpose: 'social_cash',
      disclosure: 'predicate',
      authority: 'Civil Registry',
      result: 'true',
      freshness: '2026-05-24',
      // these must be dropped
      bearer: FAKE_BEARER,
      target: 'NID-2001',
      subject: 'CP-2001'
    });
    expect(Object.keys(picked).sort()).toEqual(
      ['authority', 'claim', 'disclosure', 'freshness', 'purpose', 'result'].sort()
    );
    expect(JSON.stringify(picked)).not.toMatch(/NID-\d+/);
    expect(JSON.stringify(picked)).not.toMatch(/CP-\d+/);
    expect(JSON.stringify(picked)).not.toContain('FAKE_TOKEN_PAYLOAD');
  });
});

describe('redactBody catches a leaked identifier inside an allowlisted value', () => {
  it('scrubs an NID embedded in an otherwise-allowed string value', () => {
    const leaked = redactBody({
      purpose: 'lookup for NID-2001',
      value: 'belongs to CP-2001'
    });
    const serialized = JSON.stringify(leaked);
    expect(serialized).not.toMatch(/NID-\d+/);
    expect(serialized).not.toMatch(/CP-\d+/);
  });
});
