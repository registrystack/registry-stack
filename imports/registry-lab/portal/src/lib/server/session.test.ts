import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Cookies } from '@sveltejs/kit';
import {
  clearSession,
  getSession,
  getSessionId,
  MOCK_SESSION,
  reclaimExpiredSessions,
  resetMockSessions,
  SESSION_COOKIE,
  setMockSession
} from './session';

class MemoryCookies {
  readonly values = new Map<string, string>();

  get(name: string): string | undefined {
    return this.values.get(name);
  }

  set(name: string, value: string): void {
    this.values.set(name, value);
  }

  delete(name: string): void {
    this.values.delete(name);
  }
}

function cookiesForTest(jar: MemoryCookies): Cookies {
  // Test double implements the cookie methods exercised by the session helpers.
  return jar as unknown as Cookies;
}

describe('mock portal sessions', () => {
  beforeEach(() => {
    resetMockSessions();
    vi.useRealTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('sets an opaque per-login session id and binds it server-side to Maria', () => {
    const first = new MemoryCookies();
    const second = new MemoryCookies();

    setMockSession(cookiesForTest(first));
    setMockSession(cookiesForTest(second));

    const firstId = getSessionId(cookiesForTest(first));
    const secondId = getSessionId(cookiesForTest(second));

    expect(firstId).toBeTruthy();
    expect(secondId).toBeTruthy();
    expect(firstId).not.toBe(secondId);
    expect(first.values.get(SESSION_COOKIE)).not.toMatch(/NID-\d+|CP-\d+/);
    expect(getSession(cookiesForTest(first))).toEqual(MOCK_SESSION);
    expect(getSession(cookiesForTest(second))).toEqual(MOCK_SESSION);
  });

  it('does not accept the raw canned subject as a session cookie', () => {
    const jar = new MemoryCookies();
    jar.values.set(SESSION_COOKIE, MOCK_SESSION.subject);

    expect(getSessionId(cookiesForTest(jar))).toBeNull();
    expect(getSession(cookiesForTest(jar))).toBeNull();
  });

  it('clears the server session and browser cookie together', () => {
    const jar = new MemoryCookies();
    setMockSession(cookiesForTest(jar));

    clearSession(cookiesForTest(jar));

    expect(jar.values.has(SESSION_COOKIE)).toBe(false);
    expect(getSession(cookiesForTest(jar))).toBeNull();
  });

  it('reclaims expired opaque sessions', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-22T12:00:00.000Z'));
    const jar = new MemoryCookies();
    setMockSession(cookiesForTest(jar));

    vi.setSystemTime(new Date('2026-06-22T13:00:01.000Z'));

    expect(reclaimExpiredSessions()).toBe(1);
    expect(getSessionId(cookiesForTest(jar))).toBeNull();
    expect(getSession(cookiesForTest(jar))).toBeNull();
  });
});
