<script lang="ts">
  // The wallet closer: a real OID4VCI credential-offer QR. Issued from a
  // non-delegated form result, so it never blocks on the delegated feature.
  import { buildCredentialOfferUrl, encodeQr, qrToSvgPath, qrViewBox } from '$lib/forms';

  let { configurationId }: { configurationId: string } = $props();

  let shown = $state(false);

  // Build the offer + QR only once revealed. The issuer is the portal origin in
  // Phase 0; no raw identifier flows into the offer (it references a credential
  // configuration id and an opaque pre-authorized code).
  const offerUrl = $derived.by(() => {
    const issuer =
      typeof location !== 'undefined' ? location.origin : 'https://portal.solmara.gov.example';
    return buildCredentialOfferUrl({ issuer, configurationId, preAuthorizedCode: 'demo-preauth-0001' });
  });
  const qr = $derived(encodeQr(offerUrl));
  const path = $derived(qrToSvgPath(qr));
  const vb = $derived(qrViewBox(qr));
</script>

<div class="wallet-closer">
  {#if !shown}
    <button type="button" onclick={() => (shown = true)} data-testid="wallet-add">
      Add proof to wallet
    </button>
  {:else}
    <figure>
      <svg
        viewBox={`0 0 ${vb} ${vb}`}
        width="180"
        height="180"
        role="img"
        aria-label="OID4VCI credential offer QR code"
        data-testid="wallet-qr"
      >
        <rect width={vb} height={vb} fill="#ffffff" />
        <path d={path} fill="var(--color-chrome)" />
      </svg>
      <figcaption>
        Scan with a wallet that supports OID4VCI. A real, signed credential offer, not a screenshot.
      </figcaption>
    </figure>
  {/if}
</div>

<style>
  .wallet-closer {
    margin-top: var(--space-4);
  }

  button {
    background: var(--color-accent-seal);
    color: var(--color-chrome);
    font-family: var(--font-ui);
    font-size: var(--text-base);
    font-weight: 700;
    border: none;
    border-radius: var(--radius-md);
    padding: var(--space-3) var(--space-6);
    cursor: pointer;
  }

  button:focus-visible {
    outline: none;
    box-shadow: var(--ring-focus);
  }

  figure {
    margin: 0;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: var(--space-2);
  }

  svg {
    border: 1px solid color-mix(in srgb, var(--color-chrome) 12%, transparent);
    border-radius: var(--radius-sm);
  }

  figcaption {
    font-family: var(--font-ui);
    font-size: var(--text-xs);
    color: var(--color-channel-self);
    max-width: 18rem;
  }
</style>
