<script lang="ts">
  // The cross-person denial set-piece. A real denied evaluation (403
  // subject_mismatch, no source read), rendered as denial-as-success: the boundary
  // held. This is rendered with its own treatment, NOT the EvidenceField error
  // state, because a denial is a deliberate, signed "no", not a network failure.
  import { evaluateField } from '$lib/forms';

  let { slug }: { slug: string } = $props();

  let state = $state<'idle' | 'trying' | 'denied' | 'failed'>('idle');

  async function tryQuery() {
    state = 'trying';
    try {
      const r = await evaluateField({ slug, fieldId: 'denial', scenarioKey: 'denial' });
      // The provider returns the denial with reasonCode 'subject_mismatch'. The SSE
      // feed independently lights the rail (bounce) and the inspector (denial entry).
      state = r.reasonCode === 'subject_mismatch' ? 'denied' : 'failed';
    } catch {
      state = 'failed';
    }
  }
</script>

<section class="denial-beat" data-channel="denied">
  <h3>Security boundary check</h3>
  <p>Could Maria peek at someone else's record? Try to pull a stranger's data (query NID-1010).</p>

  {#if state === 'idle'}
    <button type="button" onclick={tryQuery} data-testid="denial-try">
      Try to pull someone else's record
    </button>
  {:else if state === 'trying'}
    <p class="trying" role="status">Asking the Civil Registry...</p>
  {:else if state === 'denied'}
    <div class="denied" role="status" data-testid="denial-result">
      <strong>Denied: blocked at the identity gate, no data touched.</strong>
      <span>
        The Notary refused before reading any record (403 subject_mismatch). The packet bounced;
        the stranger's record never lit.
      </span>
    </div>
  {:else}
    <div class="denied" role="alert">The check did not complete. Try again.</div>
  {/if}
</section>

<style>
  .denial-beat {
    margin-top: var(--space-8);
    padding: var(--space-4);
    border: 1px dashed color-mix(in srgb, var(--color-channel-denied) 50%, transparent);
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--color-channel-denied) 5%, transparent);
    font-family: var(--font-ui);
  }

  h3 {
    margin: 0 0 var(--space-1);
    font-size: var(--text-base);
    color: var(--color-chrome);
  }

  p {
    margin: 0 0 var(--space-3);
    font-size: var(--text-sm);
    color: var(--color-channel-self);
  }

  button {
    background: transparent;
    color: var(--color-channel-denied);
    border: 1px solid var(--color-channel-denied);
    border-radius: var(--radius-sm);
    font-family: var(--font-ui);
    font-size: var(--text-sm);
    font-weight: 600;
    padding: var(--space-2) var(--space-4);
    cursor: pointer;
  }

  button:focus-visible {
    outline: none;
    box-shadow: var(--ring-focus);
  }

  .denied {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    color: var(--color-channel-denied);
  }

  .denied strong {
    font-size: var(--text-base);
  }

  .denied span {
    color: var(--color-chrome);
    font-size: var(--text-sm);
  }

  .trying {
    color: var(--color-chrome);
    font-family: var(--font-mono);
    font-size: var(--text-sm);
  }
</style>
