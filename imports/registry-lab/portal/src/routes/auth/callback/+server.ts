// GET /auth/callback : MOCK-ONLY callback stub for Phase 0.
//
// Phase 1 replaces this with the real eSignet code exchange: read ?code + ?state,
// verify the PKCE verifier stored at /auth/login, exchange the code with
// private-key-jwt (the client private key stays server-side, never shipped to the
// browser, never logged), keep the access/ID token + UserInfo in a server session
// cookie, and prefill identity from UserInfo. The browser never sees raw tokens.
//
// For Phase 0 this establishes the canned Maria Santos (NID-2001) session WITHOUT
// real eSignet so the mock provider has a server-bound subject. No token is ever
// forged, stored, or logged.

import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { setMockSession } from '$lib/server/session';

export const GET: RequestHandler = ({ cookies }) => {
  // Phase 1: exchange ?code, verify PKCE, store tokens + UserInfo server-side.
  // Phase 0: set the canned subject-bound session and continue to the catalog.
  setMockSession(cookies);
  throw redirect(302, '/services');
};
