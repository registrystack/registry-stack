<script lang="ts">
  import { ProofInspector, ProofTicker, CANNED_TRACES } from '$lib/proof/index.js';
  import type { ProofTrace } from '$lib/types';

  // All trace kinds: in_flight, ok (verified), ok (fetched), denied, identity
  const traces: ProofTrace[] = CANNED_TRACES;

  // Demo: simulate disconnected state toggle
  let connected = $state(true);

  function toggleConnected() {
    connected = !connected;
  }
</script>

<svelte:head>
  <title>Proof Inspector Gallery | Registry Lab Portal</title>
</svelte:head>

<main class="gallery-page">
  <header class="gallery-header">
    <h1>Proof Inspector Gallery</h1>
    <p class="gallery-desc">
      Demo of the proof inspector and ticker components with all trace types:
      in-flight (skeleton), verified, fetched, denied, and identity-binding (foundation).
    </p>
  </header>

  <div class="demo-controls">
    <button
      class="control-btn"
      onclick={toggleConnected}
      aria-pressed={!connected}
    >
      {connected ? 'Simulate: disconnect' : 'Simulate: reconnect'}
    </button>
    <span class="control-hint">
      (Disconnected state shows the "reconnecting to audit feed" pill)
    </span>
  </div>

  <div class="gallery-layout">
    <!-- Proof inspector: side panel -->
    <div class="inspector-wrapper">
      <ProofInspector {traces} {connected} />
    </div>

    <!-- Legend / trace index -->
    <section class="trace-legend" aria-label="Trace legend">
      <h2>Trace types in this demo</h2>
      <ul>
        <li>
          <span class="legend-badge in-flight">in_flight</span>
          event-1: in-flight skeleton with heartbeat (pinned at top)
        </li>
        <li>
          <span class="legend-badge ok">ok</span>
          event-2: verified (Agriculture, registered-farmer)
        </li>
        <li>
          <span class="legend-badge ok">ok</span>
          event-3: fetched (Social, household-composition)
        </li>
        <li>
          <span class="legend-badge denied">denied</span>
          event-4: denied (Civil, subject_mismatch - cross-person attempt)
        </li>
        <li>
          <span class="legend-badge identity">identity</span>
          event-0: identity-binding, pinned to bottom as the foundation
        </li>
      </ul>
      <p class="legend-note">
        Open each entry and expand "Request and response" to see depth 2 (wire level).
        Expand "Proof and credential" inside that for depth 3 (crypto table).
        The "Not disclosed:" line is always visible at depth 1 without any expansion.
      </p>
    </section>
  </div>

  <!-- Proof ticker: full-width, always present -->
  <section class="ticker-section" aria-label="Proof audit ticker">
    <h2 class="ticker-label">Proof ticker (always present, ARIA live-region)</h2>
    <ProofTicker {traces} />
  </section>
</main>

<style>
  .gallery-page {
    font-family: var(--font-ui);
    padding: var(--space-6) var(--space-8);
    max-width: 1200px;
    margin: 0 auto;
  }

  .gallery-header {
    margin-bottom: var(--space-6);
  }

  .gallery-header h1 {
    font-size: var(--text-2xl);
    color: var(--color-chrome);
    margin: 0 0 var(--space-2);
  }

  .gallery-desc {
    color: color-mix(in srgb, var(--color-chrome) 70%, transparent);
    font-size: var(--text-base);
    margin: 0;
  }

  .demo-controls {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    margin-bottom: var(--space-6);
    padding: var(--space-3) var(--space-4);
    background: var(--color-surface);
    border-radius: var(--radius-md);
    border: 1px solid color-mix(in srgb, var(--color-chrome) 15%, transparent);
  }

  .control-btn {
    background: var(--color-chrome);
    color: #fff;
    border: none;
    border-radius: var(--radius-sm);
    padding: var(--space-2) var(--space-4);
    font-family: var(--font-ui);
    font-size: var(--text-sm);
    cursor: pointer;
    transition: background var(--transition-fast);
  }

  .control-btn:hover {
    background: color-mix(in srgb, var(--color-chrome) 80%, transparent);
  }

  .control-btn:focus-visible {
    outline: none;
    box-shadow: var(--ring-focus);
  }

  .control-hint {
    font-size: var(--text-xs);
    color: color-mix(in srgb, var(--color-chrome) 50%, transparent);
    font-style: italic;
  }

  .gallery-layout {
    display: grid;
    grid-template-columns: 480px 1fr;
    gap: var(--space-8);
    align-items: start;
    margin-bottom: var(--space-8);
  }

  .inspector-wrapper {
    height: 680px;
    overflow: hidden;
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
  }

  .trace-legend {
    padding: var(--space-4);
    background: var(--color-surface);
    border-radius: var(--radius-md);
    border: 1px solid color-mix(in srgb, var(--color-chrome) 12%, transparent);
  }

  .trace-legend h2 {
    font-size: var(--text-base);
    font-weight: 700;
    color: var(--color-chrome);
    margin: 0 0 var(--space-4);
  }

  .trace-legend ul {
    list-style: none;
    padding: 0;
    margin: 0 0 var(--space-4);
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .trace-legend li {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: color-mix(in srgb, var(--color-chrome) 80%, transparent);
    line-height: 1.4;
  }

  .legend-badge {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    font-weight: 700;
    padding: 1px var(--space-2);
    border-radius: var(--radius-full);
    flex-shrink: 0;
  }

  .legend-badge.in-flight {
    background: color-mix(in srgb, var(--color-chrome) 10%, transparent);
    color: var(--color-chrome);
  }

  .legend-badge.ok {
    background: color-mix(in srgb, var(--color-channel-verify) 15%, transparent);
    color: var(--color-channel-verify);
  }

  .legend-badge.denied {
    background: color-mix(in srgb, var(--color-channel-denied) 15%, transparent);
    color: var(--color-channel-denied);
  }

  .legend-badge.identity {
    background: color-mix(in srgb, var(--color-accent-seal) 20%, transparent);
    color: color-mix(in srgb, var(--color-accent-seal) 80%, #000);
  }

  .legend-note {
    font-size: var(--text-xs);
    color: color-mix(in srgb, var(--color-chrome) 55%, transparent);
    font-style: italic;
    margin: 0;
    line-height: 1.5;
  }

  .ticker-section {
    border-top: 2px solid color-mix(in srgb, var(--color-chrome) 15%, transparent);
    padding-top: var(--space-4);
  }

  .ticker-label {
    font-size: var(--text-sm);
    font-weight: 600;
    color: color-mix(in srgb, var(--color-chrome) 60%, transparent);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0 0 var(--space-2);
  }
</style>
