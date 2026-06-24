// Build the identity-binding proof trace: the foundation entry the inspector pins
// to the bottom (everything else rests on "who is this, and how do we know").
//
// Pushed client-side into clientFeed on sign-in (it is not an /api/evaluate call).
// Redaction-safe by construction: it carries the display name (already shown in the
// UI) but NEVER the raw national id or any token, which stay server-side only.

import type { ProofTrace } from '$lib/types';
import { IDENTITY_TRACE_ID } from '$lib/proof';

export function buildIdentityTrace(displayName: string): ProofTrace {
  return {
    id: IDENTITY_TRACE_ID,
    seq: 0,
    headline: `Identity bound by SolmaraID: ${displayName} signed in, the portal never typed her name`,
    answered: 'SolmaraID (eSignet) answered: identity verified, subject bound server-side',
    notDisclosed:
      'Not disclosed: the raw national id and the tokens, held server-side only and never sent to the browser',
    status: 'ok',
    ts: new Date().toISOString(),
    request: {
      method: 'POST',
      url: '/auth/callback',
      body: { grant_type: 'authorization_code', relationship: 'self' }
    },
    response: { status: 200, body: { subject_bound: true, name: displayName } },
    proof: {
      signedBy: 'SolmaraID (eSignet)',
      algorithm: 'EdDSA-Ed25519',
      issuerKey: 'did:web:esignet.solmara.gov.example#key-1',
      holderBound: 'Bound to the signed-in citizen (cnf wallet key)',
      credential: 'OIDC ID token (server-side session)',
      auditId: 'audit:login'
    }
  };
}
