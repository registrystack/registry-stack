<script lang="ts">
  // Gallery route: /gallery/rail
  // Demonstrates the MinistryRail component with the canned event sequence
  // covering all three motion signatures (verify/pulse, fetch/travel-stamp,
  // denied/bounce) and the two-hop delegation scenario.
  // A toggle lets reviewers see the animated vs reduced-motion views side by side.
  import { MinistryRail, CANNED_EVENTS } from '$lib/rail/index';
  import type { RailEvent } from '$lib/types';

  // Build sub-sequences for the step-by-step playback demo.
  let playStep = $state(0);
  const visibleEvents = $derived(CANNED_EVENTS.slice(0, playStep));

  function advance() {
    if (playStep < CANNED_EVENTS.length) playStep += 1;
  }

  function reset() {
    playStep = 0;
  }

  // Two-hop scenario isolated for a clearer side-by-side demonstration.
  const TWO_HOP_EVENTS: RailEvent[] = [
    {
      id: 'demo-4a',
      authority: 'social',
      channel: 'verify',
      phase: 'request',
      ts: '2026-06-21T12:04:20.000Z'
    },
    {
      id: 'demo-4b',
      authority: 'social',
      channel: 'verify',
      phase: 'sealed',
      ts: '2026-06-21T12:04:22.000Z'
    },
    {
      id: 'demo-4c',
      authority: 'civil',
      channel: 'fetch',
      phase: 'request',
      ts: '2026-06-21T12:04:23.000Z'
    },
    {
      id: 'demo-4d',
      authority: 'civil',
      channel: 'fetch',
      phase: 'sealed',
      ts: '2026-06-21T12:04:26.000Z'
    }
  ];
</script>

<div class="page">
  <header class="page-header">
    <h1>Ministry Rail Gallery</h1>
    <p class="subtitle">
      Visual system demonstration: motion signature is the PRIMARY channel cue;
      colour is secondary. Each channel is distinguishable without colour.
    </p>
    <div class="banner" role="status">
      Synthetic demo data - Republic of Solmara is a fictional nation.
    </div>
  </header>

  <main class="page-body">

    <!-- Section 1: step-by-step playback (animated) -->
    <section class="demo-section" aria-labelledby="s1-title">
      <h2 id="s1-title">Step-by-step playback (animated)</h2>
      <p>
        Advance through the canned event sequence one event at a time.
        Packets animate along edges; channel identity is encoded by motion
        shape (pulse vs travel-stamp vs bounce), not just colour.
      </p>

      <div class="rail-box">
        <MinistryRail events={visibleEvents} />
      </div>

      <div class="controls">
        <button
          class="btn"
          onclick={advance}
          disabled={playStep >= CANNED_EVENTS.length}
        >
          Next event ({playStep} / {CANNED_EVENTS.length})
        </button>
        <button class="btn btn-outline" onclick={reset}>Reset</button>
      </div>

      <div class="event-log" aria-live="polite" aria-label="Event log">
        {#if visibleEvents.length === 0}
          <p class="log-empty">No events yet.</p>
        {:else}
          <ol class="log-list">
            {#each visibleEvents as ev, i}
              <li class="log-item">
                <span class="log-seq">{i + 1}.</span>
                <span class="log-authority">{ev.authority}</span>
                <!-- Channel label is always present as text -->
                <span
                  class="log-channel"
                  data-channel={ev.channel}
                >{ev.channel}</span>
                <span class="log-phase">{ev.phase}</span>
              </li>
            {/each}
          </ol>
        {/if}
      </div>
    </section>

    <!-- Section 2: full canned sequence (all events) -->
    <section class="demo-section" aria-labelledby="s2-title">
      <h2 id="s2-title">Full canned sequence</h2>
      <p>
        Shows a verify (Agriculture), fetch (Social), denial (Civil), and
        two-hop delegation (Social then Civil) in one constellation.
      </p>

      <div class="rail-box">
        <MinistryRail events={CANNED_EVENTS} />
      </div>
    </section>

    <!-- Section 3: two-hop delegation isolated -->
    <section class="demo-section" aria-labelledby="s3-title">
      <h2 id="s3-title">Two-hop: Social verify then Civil fetch</h2>
      <p>
        Social Welfare verifies the guardianship link first; the Civil node
        is locked (idle) until that completes. Then Civil fetches the birth date.
        The gating is visible in the node states.
      </p>

      <div class="rail-box">
        <MinistryRail events={TWO_HOP_EVENTS} />
      </div>
    </section>

    <!-- Section 4: reduced-motion fallback demonstration -->
    <section class="demo-section" aria-labelledby="s4-title">
      <h2 id="s4-title">Reduced-motion fallback</h2>
      <p>
        When <code>prefers-reduced-motion: reduce</code> is active, the SVG
        animation layer is replaced by a numbered-sequence list. This instance
        always shows the list so reviewers can inspect the fallback without
        changing OS settings. Every event is present with its step number,
        authority, channel label (as text), and phase.
      </p>

      <!-- Force the reduced-motion list to be visible by overriding the media
           query in a local wrapper. This is the demo-only instance; real usage
           is purely CSS-driven. -->
      <div class="rail-box reduced-motion-demo">
        <MinistryRail events={CANNED_EVENTS} />
      </div>
    </section>

    <!-- Motion signature legend -->
    <section class="demo-section" aria-labelledby="s5-title">
      <h2 id="s5-title">Motion signature key</h2>
      <table class="legend-table" aria-label="Motion signature legend">
        <thead>
          <tr>
            <th scope="col">Channel</th>
            <th scope="col">Motion signature (primary)</th>
            <th scope="col">Colour (secondary)</th>
            <th scope="col">data-motion value</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>verify</td>
            <td>Pulse: the packet arrives at the target node and pulses in place (radial size oscillation)</td>
            <td><span class="swatch" style="background: var(--color-channel-verify)"></span> Green</td>
            <td><code>pulse-target</code></td>
          </tr>
          <tr>
            <td>fetch</td>
            <td>Travel-stamp: the packet travels along the edge from the citizen seat to the ministry, then a stamp ring radiates outward on arrival</td>
            <td><span class="swatch" style="background: var(--color-channel-fetch)"></span> Blue</td>
            <td><code>travel-stamp</code></td>
          </tr>
          <tr>
            <td>denied</td>
            <td>Bounce: the packet travels halfway toward the target node, then reverses back to the citizen seat. The node does NOT light.</td>
            <td><span class="swatch" style="background: var(--color-channel-denied)"></span> Red</td>
            <td><code>bounce</code></td>
          </tr>
        </tbody>
      </table>
    </section>

  </main>
</div>

<style>
  .page {
    max-width: 900px;
    margin: 0 auto;
    padding: var(--space-8) var(--space-4);
    font-family: var(--font-ui);
  }

  .page-header {
    margin-bottom: var(--space-8);
  }

  h1 {
    font-size: var(--text-2xl);
    font-weight: 700;
    color: var(--color-chrome);
    margin: 0 0 var(--space-2);
  }

  .subtitle {
    color: var(--color-channel-self);
    margin: 0 0 var(--space-4);
  }

  .banner {
    display: inline-block;
    padding: var(--space-2) var(--space-4);
    background: var(--color-accent-seal);
    color: var(--color-chrome);
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    font-weight: 600;
  }

  .demo-section {
    margin-bottom: var(--space-12);
    padding-bottom: var(--space-8);
    border-bottom: 1px solid rgb(0 0 0 / 0.08);
  }

  h2 {
    font-size: var(--text-xl);
    font-weight: 600;
    color: var(--color-chrome);
    margin: 0 0 var(--space-2);
  }

  p {
    color: var(--color-chrome);
    margin: 0 0 var(--space-4);
    font-size: var(--text-sm);
    line-height: 1.6;
  }

  .rail-box {
    background: var(--color-surface-raised);
    border: 1px solid rgb(0 0 0 / 0.08);
    border-radius: var(--radius-lg);
    padding: var(--space-6);
    display: flex;
    justify-content: center;
    box-shadow: var(--shadow-sm);
    margin-bottom: var(--space-4);
  }

  /* Force the reduced-motion list visible in this demo wrapper only.
     The real CSS shows/hides via media query. */
  .reduced-motion-demo :global(.rail-svg) {
    display: none;
  }

  .reduced-motion-demo :global(.sequence-list) {
    display: block;
  }

  .controls {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-4);
  }

  .btn {
    padding: var(--space-2) var(--space-4);
    background: var(--color-chrome);
    color: white;
    border: none;
    border-radius: var(--radius-md);
    font-size: var(--text-sm);
    font-family: var(--font-ui);
    cursor: pointer;
    transition: opacity var(--transition-fast);
  }

  .btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .btn-outline {
    background: transparent;
    color: var(--color-chrome);
    border: 1px solid var(--color-chrome);
  }

  .event-log {
    background: var(--color-surface);
    border: 1px solid rgb(0 0 0 / 0.08);
    border-radius: var(--radius-md);
    padding: var(--space-3) var(--space-4);
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    min-height: 3rem;
  }

  .log-empty {
    color: var(--color-channel-self);
    font-style: italic;
  }

  .log-list {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .log-item {
    display: flex;
    gap: var(--space-2);
    padding: 2px 0;
    align-items: center;
  }

  .log-seq {
    color: var(--color-channel-self);
    width: 1.5rem;
  }

  .log-authority {
    font-weight: 600;
    color: var(--color-chrome);
    min-width: 4rem;
  }

  .log-channel {
    padding: 1px 6px;
    border-radius: var(--radius-full);
    font-size: var(--text-xs);
    border: 1px solid currentColor;
  }

  .log-channel[data-channel="verify"] { color: var(--color-channel-verify); }
  .log-channel[data-channel="fetch"]  { color: var(--color-channel-fetch); }
  .log-channel[data-channel="denied"] { color: var(--color-channel-denied); }

  .log-phase {
    color: var(--color-channel-self);
  }

  /* Legend table */
  .legend-table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-sm);
  }

  .legend-table th,
  .legend-table td {
    border: 1px solid rgb(0 0 0 / 0.1);
    padding: var(--space-2) var(--space-3);
    text-align: left;
    vertical-align: top;
  }

  .legend-table th {
    background: var(--color-surface);
    font-weight: 600;
    color: var(--color-chrome);
  }

  .swatch {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 2px;
    vertical-align: middle;
    margin-right: var(--space-1);
  }

  code {
    font-family: var(--font-mono);
    font-size: var(--text-xs);
    background: var(--color-surface);
    padding: 1px 4px;
    border-radius: var(--radius-sm);
  }
</style>
