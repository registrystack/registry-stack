import { beforeEach, describe, expect, it } from 'vitest';
import type { Cookies } from '@sveltejs/kit';
import { proofFeed, resetFeeds } from '$lib/providers/feeds.svelte';
import type { ProofTrace } from '$lib/types';
import {
  getSessionId,
  resetMockSessions,
  SESSION_COOKIE,
  setMockSession
} from '$lib/server/session';
import { GET } from './+server';

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
  // Test double implements the cookie methods exercised by this route.
  return jar as unknown as Cookies;
}

function trace(id: string): ProofTrace {
  return {
    id,
    seq: 1,
    fieldId: 'person-is-alive',
    authority: 'civil',
    headline: `Trace ${id}`,
    answered: 'Civil Registry answered: person-is-alive = true',
    notDisclosed: 'Not disclosed: any other civil record detail',
    status: 'ok',
    ts: '2026-06-22T12:00:00.000Z',
    request: {
      method: 'POST',
      url: 'https://civil.notary.solmara.gov.example/v1/evaluations',
      body: { claim: 'person-is-alive' }
    },
    response: {
      status: 200,
      body: { result: true }
    }
  };
}

async function readInitialFrames(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('missing response body');
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  try {
    for (let i = 0; i < 2; i += 1) {
      const result = await reader.read();
      if (result.done) break;
      chunks.push(decoder.decode(result.value));
    }
  } finally {
    await reader.cancel();
  }
  return chunks.join('');
}

type StreamHandlerForTest = (event: { cookies: Cookies }) => Response | Promise<Response>;

describe('/proof/stream', () => {
  beforeEach(() => {
    resetFeeds();
    resetMockSessions();
  });

  it('replays only the caller session traces and keeps SSE heartbeat headers', async () => {
    const first = new MemoryCookies();
    const second = new MemoryCookies();
    setMockSession(cookiesForTest(first));
    setMockSession(cookiesForTest(second));

    const firstSessionId = getSessionId(cookiesForTest(first));
    const secondSessionId = getSessionId(cookiesForTest(second));
    if (!firstSessionId || !secondSessionId) throw new Error('session setup failed');

    proofFeed.pushTrace(firstSessionId, trace('trace-for-first'));
    proofFeed.pushTrace(secondSessionId, trace('trace-for-second'));

    // Narrow test adapter for the route handler. The handler only reads cookies.
    const response = await (GET as unknown as StreamHandlerForTest)({
      cookies: cookiesForTest(first)
    });
    const frame = await readInitialFrames(response);

    expect(response.headers.get('content-type')).toContain('text/event-stream');
    expect(response.headers.get('x-accel-buffering')).toBe('no');
    expect(frame).toContain('event: heartbeat');
    expect(frame).toContain('trace-for-first');
    expect(frame).not.toContain('trace-for-second');
    expect(frame).not.toContain(first.values.get(SESSION_COOKIE));
  });
});
