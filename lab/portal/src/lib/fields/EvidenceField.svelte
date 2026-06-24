<script lang="ts">
  import type { ClaimResult, Field, FieldState } from '$lib/types';
  import { authorityName } from './authorities';
  import { reasonSentence } from './reasonCodes';
  import { presentationFor, stampsOnEntry, type Channel } from './states';
  import StatusIcon from './StatusIcon.svelte';

  let {
    field,
    result = null,
    elapsedMs = 0,
    onRetry,
    onRecheck,
    onResolve,
    onKeepWaiting,
    onTraceHover
  }: {
    field: Field;
    result?: ClaimResult | null;
    elapsedMs?: number;
    onRetry?: () => void;
    onRecheck?: () => void;
    onResolve?: () => void;
    onKeepWaiting?: () => void;
    onTraceHover?: (traceId: string) => void;
  } = $props();

  // A self field with no result is the IDLE input; everything else is driven by
  // result.state. We treat "no result" as idle so callers can render an empty
  // self field by passing result = null.
  const fieldState = $derived<FieldState>(result?.state ?? 'idle');
  const view = $derived(presentationFor(fieldState));
  const authority = $derived(authorityName(result?.authority));
  const elapsedSeconds = $derived(Math.max(0, Math.round(elapsedMs / 1000)));

  // The stamp animation plays once when a fetched/recovered value lands. We key
  // it off a $state flag toggled by an $effect so re-renders do not retrigger it
  // on unrelated prop changes.
  let stamped = $state(false);
  $effect(() => {
    if (stampsOnEntry(fieldState)) {
      stamped = false;
      // next microtask so the class is applied after the initial paint
      const id = requestAnimationFrame(() => {
        stamped = true;
      });
      return () => cancelAnimationFrame(id);
    }
    stamped = false;
  });

  function channelVar(channel: Channel): string {
    switch (channel) {
      case 'self':
        return 'var(--color-channel-self)';
      case 'verify':
        return 'var(--color-channel-verify)';
      case 'amber':
        return 'var(--color-channel-amber)';
      case 'fetch':
        return 'var(--color-channel-fetch)';
      case 'denied':
        return 'var(--color-channel-denied)';
      case 'neutral':
        return 'var(--color-channel-self)';
    }
  }

  const reason = $derived(reasonSentence(result?.reasonCode));

  function handleTraceHover() {
    if (result && onTraceHover) onTraceHover(result.traceId);
  }
</script>

<div
  class="evidence-field"
  data-state={fieldState}
  data-kind={field.kind}
  style={`--accent: ${channelVar(view.channel)};`}
>
  <span class="label" id={`${field.id}-label`}>{field.label}</span>

  {#if fieldState === 'idle'}
    <!-- IDLE / SELF: the empty self-entry input. -->
    <div class="chip chip-self chip-input">
      <StatusIcon icon="pencil" />
      <input
        class="self-input"
        type="text"
        placeholder={field.selfPlaceholder ?? 'Type your answer'}
        aria-labelledby={`${field.id}-label`}
      />
    </div>
  {:else if fieldState === 'prefilled'}
    <!-- PREFILLED IDENTITY: locked, self from eSignet. -->
    <div class="chip chip-self chip-locked" role="status">
      <span class="value">{result?.display}</span>
      <StatusIcon icon="lock" />
      <span class="badge">self - from eSignet</span>
    </div>
  {:else if fieldState === 'in_flight'}
    <!-- IN-FLIGHT: the authority is NAMED, never a bare "Loading...". -->
    <div class="chip chip-wait" role="status">
      <StatusIcon icon="spinner" spin />
      <span class="wait-text">Checking with {authority}...</span>
    </div>
  {:else if fieldState === 'slow'}
    <!-- SLOW: still a live call, not an error. Elapsed counter + reassurance. -->
    <div class="chip chip-wait" role="status">
      <StatusIcon icon="spinner" spin />
      <span class="wait-text">
        Still checking with {authority} ({elapsedSeconds}s) - it's a live call
      </span>
      {#if onKeepWaiting}
        <button class="action" type="button" onclick={onKeepWaiting}>keep waiting</button>
      {/if}
    </div>
  {:else if fieldState === 'verified'}
    <!-- VERIFIED: predicate true, GREEN. -->
    <div class="chip chip-verify" role="status">
      <span class="status-line">
        <StatusIcon icon="check" />
        <span class="value">{result?.display}</span>
      </span>
      <span class="badge">
        verified by {authority}{#if result?.asOf}&nbsp;·&nbsp;{result.asOf}{/if}
      </span>
      {#if result}
        <button
          class="proof-link"
          type="button"
          onmouseenter={handleTraceHover}
          onfocus={handleTraceHover}
        >
          ↳ {result.traceId} in proof inspector
        </button>
      {/if}
    </div>
  {:else if fieldState === 'false'}
    <!-- FALSE: predicate false, AMBER. KEEP the verified-by badge: a false answer
         is still proven. This is the negative control, not an error. -->
    <div class="chip chip-false" role="status">
      <span class="status-line">
        <StatusIcon icon="cross" />
        <span class="value">{result?.display}</span>
      </span>
      <span class="badge">
        verified by {authority}{#if result?.reasonCode}&nbsp;·&nbsp;reason <code class="reason-code">{result.reasonCode}</code>{/if}
      </span>
      {#if reason}
        <span class="reason-sentence">{reason}</span>
      {/if}
      <span class="footnote">a false answer is still proven</span>
      {#if result}
        <button
          class="proof-link"
          type="button"
          onmouseenter={handleTraceHover}
          onfocus={handleTraceHover}
        >
          ↳ {result.traceId} in proof inspector
        </button>
      {/if}
    </div>
  {:else if fieldState === 'fetched'}
    <!-- FETCHED + LOCKED: value pulled, BLUE, with the stamp animation. -->
    <div class="chip chip-fetch" class:stamped role="status">
      <span class="status-line">
        <span class="value">{result?.display}</span>
        <StatusIcon icon="lock" />
      </span>
      <span class="badge">
        fetched from {authority} · signed{#if result?.asOf}&nbsp;·&nbsp;fresh ({result.asOf}){/if}
      </span>
      {#if result}
        <button
          class="proof-link"
          type="button"
          onmouseenter={handleTraceHover}
          onfocus={handleTraceHover}
        >
          ↳ {result.traceId} in proof inspector
        </button>
      {/if}
    </div>
  {:else if fieldState === 'stale'}
    <!-- STALE: BLUE fetched value, amber freshness flag + Re-check. -->
    <div class="chip chip-fetch chip-stale" role="status">
      <span class="status-line">
        <span class="value">{result?.display}</span>
        <StatusIcon icon="lock" />
      </span>
      <span class="badge">fetched from {authority} · signed</span>
      <span class="stale-flag">
        <StatusIcon icon="warning" />
        updated {result?.asOf ?? 'earlier'} - older than the 6-month rule
      </span>
      {#if onRecheck}
        <button class="action" type="button" onclick={onRecheck}>Re-check</button>
      {/if}
    </div>
  {:else if fieldState === 'recovered'}
    <!-- RECOVERED: a retry just succeeded. The conversion moment. -->
    <div class="chip chip-verify chip-recovered" class:stamped role="status">
      <span class="status-line">
        <StatusIcon icon="check" />
        <span class="value">Recovered · {authority} answered</span>
      </span>
      {#if result?.display}
        <span class="value secondary">{result.display}</span>
      {/if}
      <span class="badge">⤴ retried just now</span>
      {#if result}
        <button
          class="proof-link"
          type="button"
          onmouseenter={handleTraceHover}
          onfocus={handleTraceHover}
        >
          ↳ {result.traceId} in proof inspector
        </button>
      {/if}
    </div>
  {:else if fieldState === 'error'}
    <!-- ERROR: calm, scoped to this field. Never a red wall, never a stack trace. -->
    <div class="chip chip-error" role="alert">
      <span class="status-line">
        <StatusIcon icon="warning" />
        <span class="wait-text">
          Couldn't reach {authority} just now. Other evidence is unaffected.
        </span>
      </span>
      {#if onRetry}
        <button class="action" type="button" onclick={onRetry}>Try again</button>
      {/if}
    </div>
  {:else if fieldState === 'ambiguous'}
    <!-- AMBIGUOUS: more than one record matched. Never collapses to a negative. -->
    <div class="chip chip-ambiguous" role="alert">
      <span class="status-line">
        <StatusIcon icon="warning" />
        <span class="wait-text">More than one record matched. We won't guess.</span>
      </span>
      {#if onResolve}
        <button class="action" type="button" onclick={onResolve}>Resolve</button>
      {/if}
    </div>
  {/if}
</div>

<style>
  .evidence-field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    font-family: var(--font-ui);
  }

  .label {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--color-chrome);
  }

  .chip {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    border: 1px solid color-mix(in srgb, var(--accent) 35%, transparent);
    background: var(--color-surface-raised);
    color: var(--color-chrome);
    font-size: var(--text-sm);
  }

  .status-line {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  .value {
    font-weight: 600;
    color: var(--accent);
  }

  .value.secondary {
    font-weight: 400;
    color: var(--color-chrome);
  }

  .badge {
    font-size: var(--text-xs);
    color: var(--accent);
  }

  .footnote {
    font-size: var(--text-xs);
    color: var(--color-channel-self);
    font-style: italic;
  }

  .reason-sentence {
    font-size: var(--text-xs);
    color: var(--color-chrome);
  }

  .reason-code {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
  }

  .wait-text {
    color: var(--color-chrome);
  }

  /* ---- self ---- */
  .chip-self {
    --accent: var(--color-channel-self);
    background: var(--color-surface);
  }

  .chip-input {
    flex-direction: row;
    align-items: center;
    gap: var(--space-2);
  }

  .self-input {
    flex: 1;
    border: none;
    background: transparent;
    font-family: var(--font-ui);
    font-size: var(--text-sm);
    color: var(--color-chrome);
  }

  .self-input:focus {
    outline: none;
  }

  .chip-input:focus-within {
    box-shadow: var(--ring-focus);
  }

  .chip-locked {
    flex-direction: row;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
  }

  .chip-locked .badge {
    margin-left: auto;
  }

  /* ---- waits ---- */
  .chip-wait {
    flex-direction: row;
    align-items: center;
    gap: var(--space-2);
    flex-wrap: wrap;
    --accent: var(--color-channel-self);
  }

  /* ---- stamp animation (fetched / recovered) ---- */
  .stamped {
    animation: stamp 50ms ease-out;
  }

  @keyframes stamp {
    from {
      transform: scale(1.04);
    }
    to {
      transform: scale(1);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .stamped {
      animation: none;
    }
  }

  /* ---- stale flag ---- */
  .stale-flag {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    font-size: var(--text-xs);
    color: var(--color-channel-amber);
  }

  .chip-stale {
    border-color: color-mix(in srgb, var(--color-channel-amber) 45%, transparent);
  }

  /* ---- actions and proof link ---- */
  .action {
    align-self: flex-start;
    margin-top: var(--space-1);
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--accent);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--accent);
    font-family: var(--font-ui);
    font-size: var(--text-xs);
    font-weight: 600;
    cursor: pointer;
  }

  .action:hover {
    background: color-mix(in srgb, var(--accent) 12%, transparent);
  }

  .action:focus-visible {
    outline: none;
    box-shadow: var(--ring-focus);
  }

  .proof-link {
    align-self: flex-start;
    padding: 0;
    border: none;
    background: transparent;
    color: var(--color-channel-fetch);
    font-family: var(--font-ui);
    font-size: var(--text-xs);
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .proof-link:hover,
  .proof-link:focus-visible {
    color: var(--color-chrome);
    outline: none;
  }
</style>
