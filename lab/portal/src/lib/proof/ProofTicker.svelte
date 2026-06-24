<script lang="ts">
  import type { ProofTrace } from '$lib/types';
  import { IDENTITY_TRACE_ID } from '$lib/proof';

  type Props = {
    traces: ProofTrace[];
  };

  let { traces }: Props = $props();

  function statusIcon(trace: ProofTrace): string {
    switch (trace.status) {
      case 'ok':
        return '✓';
      case 'false':
        return '~';
      case 'denied':
        return '✗';
      case 'error':
        return '!';
      case 'in_flight':
        return '...';
    }
  }

  function statusWord(trace: ProofTrace): string {
    switch (trace.status) {
      case 'ok':
        return 'verified';
      case 'false':
        return 'false (signed)';
      case 'denied':
        return 'denied';
      case 'error':
        return 'error';
      case 'in_flight':
        return 'in flight';
    }
  }

  function authorityShort(trace: ProofTrace): string {
    // The identity-binding trace has no Notary authority (eSignet is the identity
    // provider, not one of the four Notaries), so name its issuer explicitly rather
    // than falling through to a bare "Unknown".
    if (trace.id === IDENTITY_TRACE_ID) {
      return 'eSignet';
    }
    switch (trace.authority) {
      case 'civil':
        return 'Civil';
      case 'social':
        return 'Social';
      case 'agri':
        return 'Agri';
      case 'certs':
        return 'Certs';
      default:
        return trace.authority ?? 'Unknown';
    }
  }

  function formatTs(ts: string): string {
    try {
      return new Date(ts).toLocaleTimeString('en-GB', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch {
      return ts;
    }
  }

  // Show traces newest-first in the ticker
  let sortedTraces = $derived(
    traces.slice().sort((a, b) => b.seq - a.seq)
  );
</script>

<!-- ARIA live-region: screen readers announce new entries as they arrive -->
<div
  class="proof-ticker"
  role="log"
  aria-live="polite"
  aria-label="Proof audit log"
  aria-atomic="false"
  aria-relevant="additions"
>
  <div class="ticker-inner">
    {#each sortedTraces as trace (trace.id)}
      <span class="tick-entry {trace.status}" aria-label="{formatTs(trace.ts)} {authorityShort(trace)} {statusWord(trace)} {trace.fieldId ?? ''}">
        <span class="tick-ts" aria-hidden="true">{formatTs(trace.ts)}</span>
        <span class="tick-sep" aria-hidden="true"> | </span>
        <span class="tick-authority" aria-hidden="true">{authorityShort(trace)}</span>
        <span class="tick-sep" aria-hidden="true"> </span>
        <span class="tick-icon" aria-hidden="true">{statusIcon(trace)}</span>
        <span class="tick-sep" aria-hidden="true"> </span>
        {#if trace.fieldId}
          <span class="tick-field" aria-hidden="true">{trace.fieldId}</span>
          <span class="tick-sep" aria-hidden="true"> </span>
        {/if}
        <span class="tick-status" aria-hidden="true">{statusWord(trace)}</span>
      </span>
    {/each}
  </div>
</div>

<style>
  .proof-ticker {
    /* IBM Plex Mono, readable from the back of a room */
    font-family: var(--font-mono);
    font-size: var(--text-lg);
    background: var(--color-chrome);
    color: #e8edf4;
    padding: var(--space-2) var(--space-4);
    overflow: hidden;
    white-space: nowrap;
    min-height: 2.5rem;
  }

  .ticker-inner {
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .tick-entry {
    display: inline-flex;
    align-items: baseline;
    gap: 0;
    padding: var(--space-1) 0;
    border-bottom: 1px solid color-mix(in srgb, #e8edf4 10%, transparent);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
  }

  .tick-ts {
    color: color-mix(in srgb, #e8edf4 50%, transparent);
    font-size: var(--text-base);
    flex-shrink: 0;
  }

  .tick-sep {
    color: color-mix(in srgb, #e8edf4 30%, transparent);
    flex-shrink: 0;
  }

  .tick-authority {
    font-weight: 700;
    color: #e8edf4;
    flex-shrink: 0;
  }

  .tick-icon {
    flex-shrink: 0;
  }

  /* Status-driven icon colour (always paired with text) */
  .tick-entry.ok .tick-icon {
    color: #7ed9a0; /* light green, readable on dark chrome bg */
  }

  .tick-entry.false .tick-icon {
    color: #f5c97a; /* amber */
  }

  .tick-entry.denied .tick-icon {
    color: #f28b85; /* red */
  }

  .tick-entry.error .tick-icon {
    color: #f28b85;
  }

  .tick-entry.in_flight .tick-icon {
    color: color-mix(in srgb, #e8edf4 60%, transparent);
    animation: blink 1s step-end infinite;
  }

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  .tick-field {
    color: color-mix(in srgb, #e8edf4 70%, transparent);
    font-style: italic;
    overflow: hidden;
    text-overflow: ellipsis;
    flex-shrink: 1;
  }

  .tick-status {
    color: #e8edf4;
    font-weight: 600;
    flex-shrink: 0;
  }
</style>
