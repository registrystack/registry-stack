// Canned ProofTrace[] for the proof gallery demo and unit tests.
// Every ProofStatus and depth shape is represented.
import type { ProofTrace } from '$lib/types';

export const CANNED_TRACES: ProofTrace[] = [
  // 1. In-flight (skeleton at top)
  {
    id: 'event-1',
    seq: 1,
    fieldId: 'registered-farmer',
    authority: 'agri',
    headline: 'Checking Agriculture for registered-farmer status...',
    answered: 'Agriculture answered: registered-farmer = (pending)',
    notDisclosed: 'Only the yes/no result is checked, no farm details',
    status: 'in_flight',
    ts: '2026-06-21T12:04:05.000Z',
    request: {
      method: 'POST',
      url: 'https://agri-citizen-notary.solmara.example/v1/evaluations',
      body: {
        claim: 'registered-farmer',
        purpose: 'agri_subsidy',
        relationship: 'self'
      }
    }
  },

  // 2. Verified (farmer registration)
  {
    id: 'event-2',
    seq: 2,
    fieldId: 'registered-farmer',
    authority: 'agri',
    headline:
      'Confirmed by Agriculture: Maria did not have to prove this herself',
    answered: 'Agriculture answered: registered-farmer = true',
    notDisclosed: 'Only the yes/no, no farm details or parcel coordinates',
    status: 'ok',
    ts: '2026-06-21T12:04:09.000Z',
    request: {
      method: 'POST',
      url: 'https://agri-citizen-notary.solmara.example/v1/evaluations',
      body: {
        claim: 'registered-farmer',
        purpose: 'agri_subsidy',
        relationship: 'self'
      }
    },
    response: {
      status: 200,
      body: {
        registered: true,
        source_authority: 'Agriculture',
        as_of: '2026-05-01'
      }
    },
    proof: {
      signedBy: 'Agriculture Ministry Notary',
      algorithm: 'EdDSA/Ed25519',
      issuerKey: 'did:web:agri-citizen-notary.solmara.example',
      holderBound: 'NID-2001 (session-bound, not echoed)',
      credential: 'SD-JWT VC',
      auditId: 'AUD-20260621-AGR-0042'
    }
  },

  // 3. Fetched (household composition)
  {
    id: 'event-3',
    seq: 3,
    fieldId: 'household-composition',
    authority: 'social',
    headline:
      'Fetched by Social Welfare: household size confirmed, members not disclosed',
    answered: 'Social answered: household-composition = 3 members',
    notDisclosed: 'Size only, not member names or identifiers',
    status: 'ok',
    ts: '2026-06-21T12:04:12.000Z',
    request: {
      method: 'POST',
      url: 'https://social-citizen-notary.solmara.example/v1/evaluations',
      body: {
        claim: 'household-composition',
        purpose: 'social_cash',
        relationship: 'self'
      }
    },
    response: {
      status: 200,
      body: {
        household_size: 3,
        source_authority: 'Social Welfare',
        as_of: '2026-04-15'
      }
    },
    proof: {
      signedBy: 'Social Welfare Ministry Notary',
      algorithm: 'EdDSA/Ed25519',
      issuerKey: 'did:web:social-citizen-notary.solmara.example',
      holderBound: 'NID-2001 (session-bound, not echoed)',
      credential: 'SD-JWT VC',
      auditId: 'AUD-20260621-SOC-0017'
    }
  },

  // 4. Denial (cross-person attempt)
  {
    id: 'event-4',
    seq: 4,
    fieldId: 'person-is-alive',
    authority: 'civil',
    headline:
      'Denied by Civil Registry: subject mismatch, no data read for NID-1010',
    answered: 'Civil answered: person-is-alive = denied (subject_mismatch)',
    notDisclosed:
      'No data was read; the query was rejected before any registry access',
    status: 'denied',
    ts: '2026-06-21T12:04:15.000Z',
    request: {
      method: 'POST',
      url: 'https://civil-citizen-notary.solmara.example/v1/evaluations',
      body: {
        claim: 'person-is-alive',
        purpose: 'social_cash',
        relationship: 'self'
      }
    },
    response: {
      status: 403,
      body: {
        error: 'subject_mismatch',
        source_authority: 'Civil Registry',
        message: 'Token subject does not match requested target'
      }
    }
  },

  // 5. Identity-binding (pinned to bottom as the foundation)
  {
    id: 'event-0',
    seq: 0,
    fieldId: 'identity',
    authority: 'civil',
    headline:
      'Identity bound via eSignet: session linked to NID-2001 (Maria Santos)',
    answered: 'Civil answered: identity = bound (eSignet UserInfo)',
    notDisclosed:
      'Only name and national ID were shared; no other civil facts disclosed',
    status: 'ok',
    ts: '2026-06-21T12:03:58.000Z',
    request: {
      method: 'POST',
      url: 'https://esignet.solmara.example/v1/userinfo',
      body: {
        claim: 'identity',
        purpose: 'session_binding',
        relationship: 'self'
      }
    },
    response: {
      status: 200,
      body: {
        sub: 'NID-2001',
        name: 'Maria Santos',
        source_authority: 'Civil Registry via eSignet',
        as_of: '2026-06-21'
      }
    },
    proof: {
      signedBy: 'eSignet / Civil Registry',
      algorithm: 'EdDSA/Ed25519',
      issuerKey: 'did:web:civil-citizen-notary.solmara.example',
      holderBound: 'NID-2001 (session-bound, not echoed)',
      credential: 'SD-JWT VC',
      auditId: 'AUD-20260621-CIV-0001'
    }
  }
];

// The identity-binding entry is always pinned to the bottom.
export const IDENTITY_TRACE_ID = 'event-0';
