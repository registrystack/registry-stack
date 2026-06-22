// Reactive feeds backed by Svelte 5 runes. The proof inspector and ministry rail
// components consume these by injection (read-only via the ProofFeed / RailFeed
// interfaces in EvidenceProvider.ts). The BFF / integration layer pushes into
// them. Client-safe: no server-only imports here.

import type { ProofFeed, RailFeed } from '$lib/providers/EvidenceProvider';
import type { ProofTrace, RailEvent } from '$lib/types';

// ---------------------------------------------------------------------------
// Proof feed: an append/update log of redacted ProofTraces.
// ---------------------------------------------------------------------------
class ProofFeedStore implements ProofFeed {
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

// ---------------------------------------------------------------------------
// Rail feed: the ministry constellation event stream.
// ---------------------------------------------------------------------------
class RailFeedStore implements RailFeed {
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

// Singletons the UI and BFF share. Exported as the concrete stores so callers can
// use the push/update methods; the read-only ProofFeed/RailFeed views are the
// interface the proof + rail components depend on.
//
// NOTE (Phase 0 single-tenant assumption): on the server these are process-global
// and the SSE stream replays the whole accumulated history to each new connection.
// That is correct for the single-presenter local demo. A hosted, multi-viewer build
// must scope the feed per session (key by the session cookie and stream only that
// session's traces) so viewers never see each other's activity. Tracked as a Phase 1
// / hosted-profile follow-up.
export const proofFeed = new ProofFeedStore();
export const railFeed = new RailFeedStore();

// Convenience reset for tests and the "nothing shared yet" landing reset.
export function resetFeeds(): void {
  proofFeed.reset();
  railFeed.reset();
}

export type { ProofFeedStore, RailFeedStore };
