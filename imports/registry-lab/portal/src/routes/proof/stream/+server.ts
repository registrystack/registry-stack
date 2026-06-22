// GET /proof/stream : Server-Sent Events feed of REDACTED ProofTrace events.
//
// The /api/evaluate route tees redacted traces to the in-process proofFeed store;
// this stream replays new traces to connected clients as `event: trace` frames,
// plus a heartbeat event every ~10s so a stalled feed is detectable client-side
// (the reconnect pill is driven elsewhere off the heartbeat gap).
//
// Server-only. Bodies are already redacted before they enter proofFeed, so the
// wire bytes never carry raw identifiers or bearer material.

import type { RequestHandler } from './$types';
import { proofFeed } from '$lib/providers/feeds.svelte';
import { heartbeatFrame, serializeTraceEvent } from '$lib/server/bff';

const HEARTBEAT_MS = 10_000;
const POLL_MS = 250;

export const GET: RequestHandler = () => {
  const encoder = new TextEncoder();
  let lastSent = 0;
  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let beatTimer: ReturnType<typeof setInterval> | undefined;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      const enqueue = (chunk: string) => {
        controller.enqueue(encoder.encode(chunk));
      };

      // Replay any traces already present (so a late connector still sees the
      // story), then poll for new ones. Polling the in-process store is the
      // Phase 0 transport; the live build pushes off an emitter.
      const flush = () => {
        const traces = proofFeed.traces;
        for (let i = lastSent; i < traces.length; i++) {
          enqueue(serializeTraceEvent(traces[i]));
        }
        lastSent = traces.length;
      };

      // Initial heartbeat so the client knows the channel is open.
      enqueue(heartbeatFrame());
      flush();

      pollTimer = setInterval(flush, POLL_MS);
      beatTimer = setInterval(() => enqueue(heartbeatFrame()), HEARTBEAT_MS);
    },
    cancel() {
      if (pollTimer) clearInterval(pollTimer);
      if (beatTimer) clearInterval(beatTimer);
    }
  });

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive'
    }
  });
};
