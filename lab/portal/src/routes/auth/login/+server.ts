// GET /auth/login : MOCK-ONLY login stub for Phase 0.
//
// Phase 1 replaces this with real eSignet Authorization Code + PKCE: this handler
// will generate a PKCE verifier/challenge, store the verifier server-side, and
// redirect to the eSignet authorize endpoint. The login is ALWAYS real in Phase 1
// (spec 5.7); there is no forged or simulated login in the live build.
//
// For Phase 0 the mock provider needs a session, so this stub redirects straight
// to the callback, which establishes the canned Maria Santos (NID-2001) session.
// No token is ever generated, forged, or logged here.

import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = () => {
  // Phase 1: build PKCE + redirect to eSignet authorize. Phase 0: go to callback.
  throw redirect(302, '/auth/callback');
};
