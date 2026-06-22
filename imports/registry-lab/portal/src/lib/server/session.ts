// Server-side session for Phase 0. A MOCK session: subject = NID-2001 (Maria
// Santos), established by the /auth/login + /auth/callback stubs WITHOUT real
// eSignet. Phase 1 replaces these stubs with real eSignet Authorization Code +
// PKCE; the session shape (subject bound server-side) does not change.
//
// We NEVER forge or store a token here: a mock session carries only the subject
// and display name, never bearer material. The real BFF holds eSignet tokens in
// the server session; the browser never sees them. Server-only module.

import type { Cookies } from '@sveltejs/kit';
import { PERSONA } from '$lib/providers/mock';

export type PortalSession = {
  subject: string; // national id bound server-side, e.g. NID-2001
  displayName: string; // from eSignet UserInfo in Phase 1; canned here
};

const SESSION_COOKIE = 'solmara_session';

// The single canned Phase 0 session. Maria Santos, NID-2001.
export const MOCK_SESSION: PortalSession = {
  subject: PERSONA.maria,
  displayName: 'Maria Santos'
};

// Establish the mock session cookie. httpOnly so the browser script never reads
// it; no token material is stored. Phase 1 stores the eSignet session server-side
// keyed by an opaque id instead of carrying the subject in the cookie value.
export function setMockSession(cookies: Cookies): void {
  cookies.set(SESSION_COOKIE, MOCK_SESSION.subject, {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // Phase 0 local; Phase 1 sets secure behind TLS.
    maxAge: 60 * 60
  });
}

// Resolve the session subject SERVER-SIDE. The BFF binds evaluations to this, so
// a client-supplied target is never trusted. Returns null when unauthenticated.
export function getSession(cookies: Cookies): PortalSession | null {
  const subject = cookies.get(SESSION_COOKIE);
  if (!subject) return null;
  // Phase 0: the only valid session subject is the canned applicant. We do not
  // accept an arbitrary cookie-supplied subject (that would be a forged session).
  if (subject !== MOCK_SESSION.subject) return null;
  return MOCK_SESSION;
}

export function clearSession(cookies: Cookies): void {
  cookies.delete(SESSION_COOKIE, { path: '/' });
}
