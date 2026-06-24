// Client-side mirror of the proof feed, populated from the /proof/stream SSE.
//
// The server-side feeds.svelte.ts singleton lives in the BFF process; the browser
// cannot read it directly, so we mirror the REDACTED traces it streams out. The
// SSE transport only carries `event: trace` frames (the rail feed is server-only),
// so we DERIVE the ministry-rail events client-side from each trace's status and
// disclosure, the same mapping the BFF uses server-side (bff.ts railFromStatus).
//
// Client-safe: no server-only imports. Svelte 5 runes.

import type { ProofTrace, RailChannel, RailEvent } from '$lib/types';

// A heartbeat older than this is treated as a stalled feed (the SSE emits a
// heartbeat comment every ~10s; EventSource swallows comments, but the browser's
// auto-reconnect + our onopen/onerror handlers drive the connected flag instead).
const STALL_AFTER_MS = 15_000;

// Derive a rail channel + phase from a trace. Mirrors bff.ts railFromStatus so the
// constellation lights the same way the server intended. The disclosure is read
// from the redacted request body (an allowlisted key).
function railFromTrace(trace: ProofTrace): { channel: RailChannel; phase: RailEvent['phase'] } {
  switch (trace.status) {
    case 'denied':
    case 'error':
      return { channel: 'denied', phase: 'denied' };
    case 'false':
      return { channel: 'verify', phase: 'sealed' };
    case 'ok': {
      const disclosure = (trace.request.body.disclosure ?? '') as string;
      const channel: RailChannel =
        disclosure === 'predicate' || disclosure === 'decision' ? 'verify' : 'fetch';
      return { channel, phase: 'sealed' };
    }
    case 'in_flight':
    default:
      return { channel: 'verify', phase: 'request' };
  }
}

function railEventFromTrace(trace: ProofTrace): RailEvent {
  const { channel, phase } = railFromTrace(trace);
  return {
    id: `${trace.id}:${phase}`,
    authority: trace.authority ?? 'civil',
    channel,
    phase,
    ts: trace.ts
  };
}

class ClientFeedStore {
  #traces = $state<ProofTrace[]>([]);
  #rail = $state<RailEvent[]>([]);
  #connected = $state(true);
  #lastBeat = $state(Date.now());

  #source: EventSource | undefined;
  #stallTimer: ReturnType<typeof setInterval> | undefined;
  #seen = new Set<string>();

  get traces(): ProofTrace[] {
    return this.#traces;
  }

  get railEvents(): RailEvent[] {
    return this.#rail;
  }

  get connected(): boolean {
    return this.#connected;
  }

  // The feed showed a sign of life (open, a trace, or a heartbeat). Refresh the
  // watchdog clock and flag connected. `now` is injectable so the watchdog logic is
  // unit-testable without a live EventSource.
  markAlive(now: number = Date.now()): void {
    this.#lastBeat = now;
    this.#connected = true;
  }

  // Watchdog tick: if nothing (trace or heartbeat) has arrived within the stall
  // window, drop the connected flag so the reconnect pill shows. Driven by an
  // interval in connect(); separated out so it can be tested deterministically.
  tickWatchdog(now: number = Date.now()): void {
    if (now - this.#lastBeat > STALL_AFTER_MS) {
      this.#connected = false;
    }
  }

  // Apply one incoming (already redacted) trace: append/replace by id and add the
  // derived rail event. Deduped by id so a replay on reconnect is idempotent.
  applyTrace(trace: ProofTrace): void {
    this.#lastBeat = Date.now();
    if (this.#seen.has(trace.id)) {
      this.#traces = this.#traces.map((t) => (t.id === trace.id ? trace : t));
      return;
    }
    this.#seen.add(trace.id);
    this.#traces = [...this.#traces, trace];
    this.#rail = [...this.#rail, railEventFromTrace(trace)];
  }

  // Open the single app-wide EventSource. Idempotent: a second call is a no-op
  // while a source is live. Server-rendered first paint calls connect() in an
  // onMount effect, so this only runs in the browser.
  connect(): void {
    if (this.#source) return;
    const source = new EventSource('/proof/stream');
    this.#source = source;

    source.onopen = () => {
      this.markAlive();
    };
    source.addEventListener('trace', (ev: MessageEvent<string>) => {
      this.markAlive();
      try {
        const trace = JSON.parse(ev.data) as ProofTrace;
        this.applyTrace(trace);
      } catch {
        // A malformed frame must not crash the feed; surface it as a stall so the
        // reconnect pill shows rather than silently dropping the audit line.
        this.#connected = false;
      }
    });
    // Heartbeat: a named event (not a comment), so EventSource actually delivers it.
    // It carries no trace, only proof the channel is alive, which refreshes the
    // watchdog so the reconnect pill does not false-trip during a quiet stretch.
    source.addEventListener('heartbeat', () => {
      this.markAlive();
    });
    source.onerror = () => {
      // EventSource auto-reconnects; reflect the gap in the pill meanwhile.
      this.#connected = false;
    };

    // Watchdog: if no frame or beat has arrived within the stall window, drop the
    // connected flag so the reconnect pill shows even when onerror has not fired.
    this.#stallTimer = setInterval(() => this.tickWatchdog(), 2_000);
  }

  disconnect(): void {
    this.#source?.close();
    this.#source = undefined;
    if (this.#stallTimer) {
      clearInterval(this.#stallTimer);
      this.#stallTimer = undefined;
    }
  }

  reset(): void {
    this.#traces = [];
    this.#rail = [];
    this.#seen.clear();
    this.#connected = true;
    this.#lastBeat = Date.now();
  }
}

// App-wide singleton mirror. The layout mounts the rail/ticker/inspector against
// this; form pages read it to know a field's trace landed.
export const clientFeed = new ClientFeedStore();
