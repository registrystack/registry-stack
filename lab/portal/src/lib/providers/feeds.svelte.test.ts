import { describe, expect, it } from 'vitest';
import { SessionScopedProofFeedStore } from './feeds.svelte';
import type { ProofTrace } from '$lib/types';

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

describe('SessionScopedProofFeedStore', () => {
  it('keeps traces isolated by session id', () => {
    const store = new SessionScopedProofFeedStore();

    store.pushTrace('session-a', trace('trace-a'));
    store.pushTrace('session-b', trace('trace-b'));

    expect(store.forSession('session-a').traces.map((t) => t.id)).toEqual(['trace-a']);
    expect(store.forSession('session-b').traces.map((t) => t.id)).toEqual(['trace-b']);
  });

  it('reclaims abandoned sessions after the TTL', () => {
    const store = new SessionScopedProofFeedStore({ ttlMs: 1_000, maxSessions: 10 });

    store.forSession('stale-session', 0).pushTrace(trace('stale-trace'));
    store.forSession('active-session', 500).pushTrace(trace('active-trace'));

    expect(store.reclaimAbandonedSessions(1_200)).toBe(1);
    expect(store.sessionCount).toBe(1);
    expect(store.forSession('active-session', 1_200).traces.map((t) => t.id)).toEqual([
      'active-trace'
    ]);
    expect(store.forSession('stale-session', 1_200).traces).toEqual([]);
  });
});
