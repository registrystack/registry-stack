<script lang="ts">
  import { EvidenceField } from '$lib/fields';
  import type { ClaimResult, Field } from '$lib/types';

  // Canned descriptors, one per provenance kind. The gallery exercises the
  // renderer in isolation so every lifecycle state is independently reachable
  // (Phase 0 DoD: "each state reachable" becomes falsifiable on one page).
  const selfField: Field = {
    id: 'g-self',
    label: 'Full legal name',
    kind: 'self',
    selfPlaceholder: 'Type your full legal name'
  };
  const verifyField: Field = {
    id: 'g-verify',
    label: 'Farmer registration',
    kind: 'verify',
    claim: 'registered-farmer',
    notary: 'agri'
  };
  const fetchField: Field = {
    id: 'g-fetch',
    label: 'Date of birth',
    kind: 'fetch',
    claim: 'date-of-birth',
    notary: 'civil'
  };
  const householdField: Field = {
    id: 'g-household',
    label: 'Household composition',
    kind: 'fetch',
    claim: 'household-composition',
    notary: 'social'
  };
  const decisionField: Field = {
    id: 'g-decision',
    label: 'Combined eligibility',
    kind: 'decision',
    notary: 'social',
    manual: true
  };

  type Case = {
    note: string; // what a reviewer should see
    field: Field;
    result: ClaimResult | null;
    elapsedMs?: number;
    actions?: boolean; // wire the action callbacks so buttons render
  };

  function noop() {
    /* gallery: actions are inert, present so the affordance renders */
  }

  const cases: Case[] = [
    {
      note: 'idle / self - empty input, slate, placeholder from field.selfPlaceholder',
      field: selfField,
      result: null
    },
    {
      note: 'prefilled - locked identity chip, "self - from eSignet"',
      field: selfField,
      result: { state: 'prefilled', display: 'Maria Santos · NID-2001', traceId: 'event-0' }
    },
    {
      note: 'in_flight - authority NAMED, never a bare "Loading..."',
      field: decisionField,
      result: { state: 'in_flight', display: '', authority: 'social', traceId: 'event-1' }
    },
    {
      note: 'slow - "(12s) - it\'s a live call" + keep waiting',
      field: decisionField,
      result: { state: 'slow', display: '', authority: 'social', traceId: 'event-1' },
      elapsedMs: 12000,
      actions: true
    },
    {
      note: 'verified - GREEN check, "verified by {authority} · {asOf}", proof link',
      field: verifyField,
      result: {
        state: 'verified',
        display: 'Verified - registered farmer',
        authority: 'agri',
        asOf: '2026-05',
        traceId: 'event-2'
      }
    },
    {
      note: 'false - AMBER, KEEPS the verified-by badge + reason code (a false answer is still proven)',
      field: verifyField,
      result: {
        state: 'false',
        display: 'Not eligible - voucher already redeemed',
        authority: 'agri',
        reasonCode: 'VR-RED-02',
        traceId: 'event-3'
      }
    },
    {
      note: 'fetched + locked - BLUE, lock, stamp animation on entry',
      field: fetchField,
      result: {
        state: 'fetched',
        display: '2019-03-14',
        authority: 'civil',
        asOf: 'today',
        traceId: 'event-4'
      }
    },
    {
      note: 'stale - BLUE + amber freshness flag + Re-check',
      field: householdField,
      result: {
        state: 'stale',
        display: '4 members · 1 child',
        authority: 'social',
        asOf: '2024-09',
        traceId: 'event-5'
      },
      actions: true
    },
    {
      note: 'recovered - "Recovered · {authority} answered", retried just now',
      field: fetchField,
      result: {
        state: 'recovered',
        display: '2019-03-14',
        authority: 'social',
        traceId: 'event-6'
      }
    },
    {
      note: 'error - calm, scoped, "Other evidence is unaffected." + Try again',
      field: householdField,
      result: { state: 'error', display: '', authority: 'social', traceId: 'event-7' },
      actions: true
    },
    {
      note: 'ambiguous - "More than one record matched. We won\'t guess." + Resolve (never a negative)',
      field: fetchField,
      result: { state: 'ambiguous', display: '', authority: 'civil', traceId: 'event-8' },
      actions: true
    }
  ];

  let lastHovered = $state<string | null>(null);
</script>

<main>
  <header>
    <h1>EvidenceField state gallery</h1>
    <p>
      Every lifecycle state rendered once with canned Field + ClaimResult data, so each
      state is independently reachable and visible on one page. Colour is never the only
      signal: each status pairs its channel colour with an icon and text.
    </p>
    {#if lastHovered}
      <p class="hover-readout">proof binding fired: <code>{lastHovered}</code></p>
    {/if}
  </header>

  <ul class="grid">
    {#each cases as c (c.field.id + '-' + (c.result?.state ?? 'idle'))}
      <li class="cell">
        <p class="cell-note">{c.note}</p>
        <EvidenceField
          field={c.field}
          result={c.result}
          elapsedMs={c.elapsedMs ?? 0}
          onRetry={c.actions ? noop : undefined}
          onRecheck={c.actions ? noop : undefined}
          onResolve={c.actions ? noop : undefined}
          onKeepWaiting={c.actions ? noop : undefined}
          onTraceHover={(traceId) => (lastHovered = traceId)}
        />
      </li>
    {/each}
  </ul>
</main>

<style>
  main {
    max-width: 64rem;
    margin: var(--space-12) auto;
    padding: 0 var(--space-6);
    font-family: var(--font-ui);
  }

  h1 {
    font-size: var(--text-2xl);
    font-weight: 600;
    color: var(--color-chrome);
    margin-bottom: var(--space-2);
  }

  header p {
    font-size: var(--text-sm);
    color: var(--color-channel-self);
    max-width: 46rem;
  }

  .hover-readout {
    margin-top: var(--space-2);
    color: var(--color-channel-fetch);
  }

  .hover-readout code {
    font-family: var(--font-mono);
  }

  .grid {
    list-style: none;
    padding: 0;
    margin: var(--space-8) 0 0;
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(20rem, 1fr));
    gap: var(--space-6);
  }

  .cell {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-4);
    background: var(--color-surface-raised);
    border: 1px solid color-mix(in srgb, var(--color-channel-self) 25%, transparent);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-sm);
  }

  .cell-note {
    font-size: var(--text-xs);
    color: var(--color-channel-self);
    margin: 0 0 var(--space-1);
  }
</style>
