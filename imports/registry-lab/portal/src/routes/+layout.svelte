<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { MinistryRail } from '$lib/rail';
  import { ProofInspector, ProofTicker } from '$lib/proof';
  import { clientFeed, ui } from '$lib/forms';
  import type { LayoutData } from './$types';

  let { children, data }: { children: import('svelte').Snippet; data: LayoutData } = $props();

  // The footer audit log is a drawer: collapsed to its most-recent rows by default,
  // expanded (and scrollable) on demand so the full proof history is reachable.
  let auditOpen = $state(false);

  // One app-wide SSE connection to the redacted proof feed. Browser only (onMount
  // never runs during SSR), so EventSource is safe here. The rail, ticker, and
  // inspector all read the client mirror; the BFF tees redacted traces server-side.
  onMount(() => {
    if (!data.proofFeedEnabled) {
      clientFeed.disconnect();
      return;
    }
    clientFeed.connect();
    return () => clientFeed.disconnect();
  });
</script>

<div class="portal">
  <!-- Synthetic data banner: always visible, never hidden. -->
  <div class="synthetic-banner" role="status" aria-live="polite">
    Synthetic demo data &middot; Republic of Solmara is a fictional nation.
  </div>

  <header class="rail-band">
    <a class="wordmark" href="/">Glass Government <span>Republic of Solmara</span></a>
    <div class="rail-region">
      <MinistryRail events={clientFeed.railEvents} />
    </div>
  </header>

  <div class="body">
    <main class="content">
      {@render children()}
    </main>
    <aside class="inspector-region" aria-label="Proof inspector">
      <ProofInspector
        traces={clientFeed.traces}
        activeTraceId={ui.activeTrace}
        connected={clientFeed.connected}
      />
    </aside>
  </div>

  <!-- Ambient audit log: a drawer pinned to the foot of the page. Collapsed to its
       most-recent rows by default (the form is the hero up top); expand + scroll for
       the full proof history, so older entries are never lost. -->
  <section class="ticker-band" class:open={auditOpen} aria-label="Proof audit log">
    <button
      type="button"
      class="ticker-handle"
      data-testid="audit-log-toggle"
      aria-expanded={auditOpen}
      aria-controls="proof-audit-log"
      onclick={() => (auditOpen = !auditOpen)}
    >
      <span class="handle-label">Proof audit log</span>
      <span class="handle-count">{clientFeed.traces.length}</span>
      <span class="handle-chevron" aria-hidden="true">{auditOpen ? '▾' : '▴'}</span>
      <span class="handle-hint">{auditOpen ? 'collapse' : 'expand'}</span>
    </button>
    <div class="ticker-scroll" id="proof-audit-log">
      <ProofTicker traces={clientFeed.traces} />
    </div>
  </section>
</div>

<style>
  .portal {
    --ticker-collapsed-h: 7.5rem;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    background: var(--color-surface);
  }

  .synthetic-banner {
    background-color: var(--color-chrome);
    color: #fff;
    font-family: var(--font-ui);
    font-size: var(--text-sm);
    text-align: center;
    padding: var(--space-2) var(--space-4);
    letter-spacing: 0.02em;
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .rail-band {
    display: flex;
    align-items: center;
    gap: var(--space-6);
    padding: var(--space-3) var(--space-6);
    background: var(--color-surface-raised);
    border-bottom: 1px solid color-mix(in srgb, var(--color-chrome) 12%, transparent);
  }

  .wordmark {
    display: flex;
    flex-direction: column;
    font-family: var(--font-ui);
    font-weight: 700;
    color: var(--color-chrome);
    text-decoration: none;
    line-height: 1.1;
    white-space: nowrap;
  }

  .wordmark span {
    font-size: var(--text-xs);
    font-weight: 500;
    color: var(--color-channel-self);
    letter-spacing: 0.04em;
  }

  .rail-region {
    flex: 1;
    min-width: 0;
  }

  /* The audit-log drawer, pinned to the foot of the viewport. Collapsed it shows its
     most-recent rows; opened it grows upward and the rows scroll, so the full history
     is reachable without the log ever dominating the page. */
  .ticker-band {
    position: sticky;
    bottom: 0;
    z-index: 50;
    display: flex;
    flex-direction: column;
    background: var(--color-chrome);
    color: #fff;
    border-top: 1px solid color-mix(in srgb, #e8edf4 12%, transparent);
    max-height: var(--ticker-collapsed-h);
  }

  .ticker-band.open {
    max-height: 42vh;
  }

  .ticker-handle {
    flex-shrink: 0;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    box-sizing: border-box;
    padding: var(--space-1) var(--space-4);
    background: color-mix(in srgb, #e8edf4 6%, var(--color-chrome));
    border: none;
    border-bottom: 1px solid color-mix(in srgb, #e8edf4 10%, transparent);
    color: #e8edf4;
    font-family: var(--font-ui);
    font-size: var(--text-xs);
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    cursor: pointer;
  }

  .ticker-handle:hover {
    background: color-mix(in srgb, #e8edf4 12%, var(--color-chrome));
  }

  .ticker-handle:focus-visible {
    outline: 2px solid var(--color-accent-seal);
    outline-offset: -2px;
  }

  .handle-count {
    font-family: var(--font-mono);
    color: color-mix(in srgb, #e8edf4 65%, transparent);
  }

  .handle-chevron {
    margin-left: auto;
  }

  .handle-hint {
    font-size: var(--text-xs);
    font-weight: 500;
    text-transform: none;
    letter-spacing: 0;
    color: color-mix(in srgb, #e8edf4 55%, transparent);
  }

  .ticker-scroll {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }

  .body {
    flex: 1;
    display: flex;
    align-items: flex-start;
    gap: var(--space-6);
    padding: var(--space-6);
    /* Clear the pinned collapsed drawer so it never covers the foot of the content. */
    padding-bottom: calc(var(--space-6) + var(--ticker-collapsed-h));
    max-width: 92rem;
    margin: 0 auto;
    width: 100%;
    box-sizing: border-box;
  }

  .content {
    flex: 1;
    min-width: 0;
  }

  .inspector-region {
    width: 24rem;
    flex-shrink: 0;
    position: sticky;
    top: var(--space-6);
    /* Leave room for the pinned collapsed drawer so the inspector never runs under it. */
    max-height: calc(100vh - var(--space-12) - var(--ticker-collapsed-h));
    overflow: auto;
  }

  @media (max-width: 64rem) {
    .body {
      flex-direction: column;
    }
    .inspector-region {
      width: 100%;
      position: static;
      max-height: none;
    }
  }
</style>
