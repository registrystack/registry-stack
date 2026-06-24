// Server-side session for Phase 0. A MOCK session: subject = NID-2001 (Maria
// Santos), established by the /auth/login + /auth/callback stubs WITHOUT real
// eSignet. Phase 1 replaces these stubs with real eSignet Authorization Code +
// PKCE; the session shape (subject bound server-side) does not change.
//
// We NEVER forge or store a token here: a mock session carries only the subject
// and display name, never bearer material. The real BFF holds eSignet tokens in
// the server session; the browser never sees them. Server-only module.

import type { Cookies } from '@sveltejs/kit';
import { randomUUID } from 'node:crypto';
import { PERSONA } from '$lib/providers/mock';

export type PortalSession = {
  subject: string; // national id bound server-side, e.g. NID-2001
  displayName: string; // from eSignet UserInfo in Phase 1; canned here
};

export const SESSION_COOKIE = 'solmara_session';
const SESSION_MAX_AGE_SECONDS = 60 * 60;
const SESSION_MAX_AGE_MS = SESSION_MAX_AGE_SECONDS * 1000;

// The single canned Phase 0 session. Maria Santos, NID-2001.
export const MOCK_SESSION: PortalSession = {
  subject: PERSONA.maria,
  displayName: 'Maria Santos'
};

type StoredSession = {
  session: PortalSession;
  expiresAt: number;
};

const sessions = new Map<string, StoredSession>();

// Establish the mock session cookie. httpOnly so the browser script never reads
// it; no token material is stored. Phase 1 stores the eSignet session server-side
// keyed by an opaque id instead of carrying the subject in the cookie value.
export function setMockSession(cookies: Cookies): void {
  reclaimExpiredSessions();
  const sessionId = randomUUID();
  sessions.set(sessionId, {
    session: MOCK_SESSION,
    expiresAt: Date.now() + SESSION_MAX_AGE_MS
  });
  cookies.set(SESSION_COOKIE, sessionId, {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.PORTAL_SECURE_COOKIES === 'true',
    maxAge: SESSION_MAX_AGE_SECONDS
  });
}

export function getSessionId(cookies: Cookies): string | null {
  reclaimExpiredSessions();
  const sessionId = cookies.get(SESSION_COOKIE);
  if (!sessionId || !sessions.has(sessionId)) return null;
  return sessionId;
}

// Resolve the session subject SERVER-SIDE. The BFF binds evaluations to this, so
// a client-supplied target is never trusted. Returns null when unauthenticated.
export function getSession(cookies: Cookies): PortalSession | null {
  const sessionId = getSessionId(cookies);
  return sessionId ? sessions.get(sessionId)?.session ?? null : null;
}

export function clearSession(cookies: Cookies): void {
  const sessionId = cookies.get(SESSION_COOKIE);
  if (sessionId) sessions.delete(sessionId);
  cookies.delete(SESSION_COOKIE, { path: '/' });
}

export function resetMockSessions(): void {
  sessions.clear();
}

export function reclaimExpiredSessions(now = Date.now()): number {
  let reclaimed = 0;
  for (const [sessionId, stored] of sessions) {
    if (stored.expiresAt <= now) {
      sessions.delete(sessionId);
      reclaimed += 1;
    }
  }
  return reclaimed;
}
