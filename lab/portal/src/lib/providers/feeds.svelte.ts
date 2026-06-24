// Reactive feeds backed by Svelte 5 runes. The proof inspector and ministry rail
// components consume these by injection (read-only via the ProofFeed / RailFeed
// interfaces in EvidenceProvider.ts). The BFF / integration layer pushes into
// them. Client-safe: no server-only imports here.

import type { ProofFeed, RailFeed } from '$lib/providers/EvidenceProvider';
import type { ProofTrace, RailEvent } from '$lib/types';

export type FeedSessionId = string;

const DEFAULT_PROOF_SESSION_TTL_MS = 30 * 60 * 1000;
const DEFAULT_PROOF_SESSION_LIMIT = 100;

// ---------------------------------------------------------------------------
// Proof feed: an append/update log of redacted ProofTraces.
// ---------------------------------------------------------------------------
export class ProofFeedStore implements ProofFeed {
  #traces = $state<ProofTrace[]>([]);

  get traces(): ProofTrace[] {
    return this.#traces;
  }

  // Append a new trace (e.g. an in-flight skeleton entry).
  pushTrace(trace: ProofTrace): void {
    this.#traces = [...this.#traces, trace];
  }

  // Update an existing trace in place by id (e.g. in-flight -> resolved). If no
  // trace matches the id, the partial is appended as a new trace only when it is
  // a complete ProofTrace; otherwise the update is a no-op on an unknown id.
  updateTrace(id: string, patch: Partial<ProofTrace>): void {
    this.#traces = this.#traces.map((t) =>
      t.id === id ? { ...t, ...patch } : t
    );
  }

  reset(): void {
    this.#traces = [];
  }
}

type ProofSessionBucket = {
  feed: ProofFeedStore;
  lastAccessedAt: number;
};

export class SessionScopedProofFeedStore {
  readonly #ttlMs: number;
  readonly #maxSessions: number;
  #sessions = new Map<FeedSessionId, ProofSessionBucket>();

  constructor(opts?: { ttlMs?: number; maxSessions?: number }) {
    this.#ttlMs = opts?.ttlMs ?? DEFAULT_PROOF_SESSION_TTL_MS;
    this.#maxSessions = opts?.maxSessions ?? DEFAULT_PROOF_SESSION_LIMIT;
  }

  forSession(sessionId: FeedSessionId, now = Date.now()): ProofFeedStore {
    this.reclaimAbandonedSessions(now);
    const existing = this.#sessions.get(sessionId);
    if (existing) {
      existing.lastAccessedAt = now;
      return existing.feed;
    }

    const bucket: ProofSessionBucket = {
      feed: new ProofFeedStore(),
      lastAccessedAt: now
    };
    this.#sessions.set(sessionId, bucket);
    this.#evictLeastRecentlyUsed();
    return bucket.feed;
  }

  pushTrace(sessionId: FeedSessionId, trace: ProofTrace): void {
    this.forSession(sessionId).pushTrace(trace);
  }

  updateTrace(sessionId: FeedSessionId, id: string, patch: Partial<ProofTrace>): void {
    this.forSession(sessionId).updateTrace(id, patch);
  }

  reclaimAbandonedSessions(now = Date.now()): number {
    let reclaimed = 0;
    for (const [sessionId, bucket] of this.#sessions) {
      if (now - bucket.lastAccessedAt > this.#ttlMs) {
        this.#sessions.delete(sessionId);
        reclaimed += 1;
      }
    }
    return reclaimed;
  }

  get sessionCount(): number {
    return this.#sessions.size;
  }

  reset(sessionId?: FeedSessionId): void {
    if (sessionId) {
      this.#sessions.delete(sessionId);
      return;
    }
    this.#sessions.clear();
  }

  #evictLeastRecentlyUsed(): void {
    while (this.#sessions.size > this.#maxSessions) {
      let oldestSessionId: FeedSessionId | undefined;
      let oldestAccess = Infinity;
      for (const [sessionId, bucket] of this.#sessions) {
        if (bucket.lastAccessedAt < oldestAccess) {
          oldestSessionId = sessionId;
          oldestAccess = bucket.lastAccessedAt;
        }
      }
      if (!oldestSessionId) return;
      this.#sessions.delete(oldestSessionId);
    }
  }
}

// ---------------------------------------------------------------------------
// Rail feed: the ministry constellation event stream.
// ---------------------------------------------------------------------------
export class RailFeedStore implements RailFeed {
  #events = $state<RailEvent[]>([]);

  get events(): RailEvent[] {
    return this.#events;
  }

  pushRailEvent(event: RailEvent): void {
    this.#events = [...this.#events, event];
  }

  reset(): void {
    this.#events = [];
  }
}

// Singletons the UI and BFF share. The proof feed is keyed by the opaque
// solmara_session id, so a hosted viewer only replays traces from their own
// server session. The read-only ProofFeed/RailFeed views are the interface the
// proof + rail components depend on.
export const proofFeed = new SessionScopedProofFeedStore();
export const railFeed = new RailFeedStore();

// Convenience reset for tests and the "nothing shared yet" landing reset.
export function resetFeeds(): void {
  proofFeed.reset();
  railFeed.reset();
}
