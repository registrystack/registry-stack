// BFF glue: turn a MockEvaluation into a REDACTED ProofTrace and a RailEvent, and
// tee them to the reactive feeds. Server-only (redaction lives here); imported by
// the /api/evaluate route and the SSE stream, never into a client bundle.

import type { MockEvaluation } from '$lib/providers/mock';
import type { ProofTrace, RailChannel, RailEvent } from '$lib/types';
import { proofFeed, railFeed } from '$lib/providers/feeds.svelte';
import { redactRequest, redactResponse, scrubString } from './redact';

let traceSeq = 0;

// Build a redacted ProofTrace from a full MockEvaluation. The depth-1 human copy
// is allowlist-safe by construction (it never embeds a raw identifier; the mock
// authors it). depth-2 bodies are run through the redactor. depth-3 crypto carries
// no raw identifier (dids, audit ids, algorithm).
export function buildRedactedTrace(
  ev: MockEvaluation,
  opts?: { fieldId?: string }
): ProofTrace {
  const seq = ++traceSeq;
  const redactedReq = redactRequest(ev.raw.request);
  const trace: ProofTrace = {
    id: ev.result.traceId,
    seq,
    ...(opts?.fieldId ? { fieldId: opts.fieldId } : {}),
    authority: ev.proof.authority,
    // depth 1: scrub defensively even though the mock authors these clean.
    headline: scrubString(ev.proof.headline),
    answered: scrubString(ev.proof.answered),
    notDisclosed: scrubString(ev.proof.notDisclosed),
    status: ev.proof.status,
    ts: new Date().toISOString(),
    // depth 2: redacted wire bodies (allowlist only).
    request: redactedReq,
    response: redactResponse({
      status: ev.raw.response.status,
      body: ev.raw.response.body as Record<string, unknown>
    }),
    // depth 3: crypto. Present for resolved AND denied traces (the denial is still
    // a signed, audited evaluation result).
    proof: ev.proof.crypto
  };
  return trace;
}

// Map a proof status to a rail channel + phase.
function railFromStatus(ev: MockEvaluation): { channel: RailChannel; phase: RailEvent['phase'] } {
  switch (ev.proof.status) {
    case 'denied':
      return { channel: 'denied', phase: 'denied' };
    case 'error':
      return { channel: 'denied', phase: 'denied' };
    case 'false':
      // a signed "no" is still a sealed verify, not a denial.
      return { channel: 'verify', phase: 'sealed' };
    case 'ok': {
      const disclosure = (ev.raw.request.body.disclosure ?? '') as string;
      const channel: RailChannel = disclosure === 'predicate' || disclosure === 'decision' ? 'verify' : 'fetch';
      return { channel, phase: 'sealed' };
    }
    default:
      return { channel: 'verify', phase: 'request' };
  }
}

export function buildRailEvent(ev: MockEvaluation): RailEvent {
  const { channel, phase } = railFromStatus(ev);
  return {
    id: `${ev.result.traceId}:${phase}`,
    authority: ev.proof.authority ?? 'civil',
    channel,
    phase,
    ts: new Date().toISOString()
  };
}

// Tee a redacted trace + rail event to the feeds. Returns the trace so the route
// can also serialize it for the SSE stream.
export function teeToFeeds(ev: MockEvaluation, opts?: { fieldId?: string }): ProofTrace {
  const trace = buildRedactedTrace(ev, opts);
  proofFeed.pushTrace(trace);
  railFeed.pushRailEvent(buildRailEvent(ev));
  return trace;
}

// SSE serialization: a single `event: trace\ndata: <json>\n\n` frame. The JSON is
// the already-redacted trace, so the wire bytes never carry raw identifiers.
export function serializeTraceEvent(trace: ProofTrace): string {
  // Final safety net: the trace is already redacted by buildRedactedTrace, but scrub
  // the serialized frame once more so a raw identifier or bearer can never reach the
  // wire even if a future change adds an un-redacted field. scrubString is a no-op on
  // already-clean input, so this is defense in depth, not a behavior change.
  const data = scrubString(JSON.stringify(trace));
  return `event: trace\ndata: ${data}\n\n`;
}

// SSE heartbeat as a real named event. It MUST be a named event (not a `: comment`):
// EventSource silently swallows comment lines, so a comment heartbeat never reaches
// the client and its stall watchdog would trip ~15s after the last trace even on a
// healthy feed. A `event: heartbeat` frame is delivered to the client's
// addEventListener('heartbeat', ...) handler, which refreshes the watchdog. The
// payload carries no identifier, only a timestamp.
export function heartbeatFrame(): string {
  return `event: heartbeat\ndata: ${Date.now()}\n\n`;
}

// Reset the trace counter (tests / "nothing shared yet" landing).
export function resetTraceSeq(): void {
  traceSeq = 0;
}
