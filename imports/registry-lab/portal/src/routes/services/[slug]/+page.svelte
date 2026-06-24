<script lang="ts">
  import { untrack } from 'svelte';
  import { EvidenceField } from '$lib/fields';
  import { autoFetchFields, clientFeed, buildIdentityTrace, evaluateField, ui } from '$lib/forms';
  import WalletCloser from '$lib/forms/WalletCloser.svelte';
  import DenialBeat from '$lib/forms/DenialBeat.svelte';
  import type { ClaimResult, Field } from '$lib/types';
  import type { PageData } from './$types';

  let { data }: { data: PageData } = $props();

  // The form is reactive: navigating between /services/[slug] reuses this component,
  // so everything derived from the form must recompute when the slug changes.
  const form = $derived(data.form);

  // Per-field current ClaimResult (null = idle self field / not yet started).
  let results = $state<Record<string, ClaimResult | null>>({});

  // Education delegated flow state.
  let consentGiven = $state(false);
  let guardianVerified = $state(false);

  function inFlight(field: Field): ClaimResult {
    return { state: 'in_flight', display: '', authority: field.notary, traceId: '' };
  }

  function errored(field: Field): ClaimResult {
    return { state: 'error', display: '', authority: field.notary, traceId: '' };
  }

  function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // Field partitions (derived so they track the slug).
  const identityField = $derived(
    form.fields.find((f) => f.kind === 'self' && f.id.includes('identity'))
  );
  const selfInputFields = $derived(
    form.fields.filter(
      (f) => f.kind === 'self' && !f.id.includes('identity') && f.id !== 'education-consent'
    )
  );
  const delegatedCivilFields = $derived(form.fields.filter((f) => f.delegated !== undefined));
  const bodyFields = $derived(
    form.fields.filter(
      (f) =>
        (f.kind === 'verify' || f.kind === 'fetch' || f.kind === 'decision') &&
        !f.manual &&
        f.delegated === undefined
    )
  );
  const manual = $derived(form.fields.find((f) => f.manual === true));
  const isEducation = $derived(form.slug === 'education-grant');
  const isCertificate = $derived(form.slug === 'civil-certificate');

  const guardianField: Field = {
    id: 'guardian-link-verified',
    label: 'Guardian link verified',
    kind: 'verify',
    notary: 'social'
  };

  const identityResult = $derived<ClaimResult>({
    state: 'prefilled',
    display: `${data.displayName} · ${data.subject}`,
    traceId: 'event-0'
  });

  // Run one field through the BFF. opts can carry an explicit scenario key (for the
  // guardian-link verify, whose field id differs from its scenario) or the delegated
  // gate boolean.
  async function runField(
    field: Field,
    slug: string,
    opts?: { scenarioKey?: string; guardianLinkVerified?: boolean }
  ): Promise<ClaimResult | null> {
    results[field.id] = inFlight(field);
    try {
      const r = await evaluateField({ slug, fieldId: field.id, ...opts });
      results[field.id] = r;
      return r;
    } catch {
      results[field.id] = errored(field);
      return null;
    }
  }

  // Auto-fetch every verify/fetch field CONCURRENTLY; stagger only the visual reveal
  // (the requests fire in parallel; the cascade is cosmetic so the eye can follow).
  async function runAutoFetch(fields: Field[], slug: string) {
    fields.forEach((field) => {
      results[field.id] = inFlight(field);
    });
    await Promise.all(
      fields.map(async (field, i) => {
        try {
          const r = await evaluateField({ slug, fieldId: field.id });
          await sleep(i * 550);
          results[field.id] = r;
        } catch {
          results[field.id] = errored(field);
        }
      })
    );
  }

  // Education: consent gates hop one (the social guardian-link verify); only once
  // that resolves verified are the delegated civil reads authorized (hop two).
  async function giveConsent() {
    consentGiven = true;
    const verify = await runField(guardianField, form.slug, { scenarioKey: 'caregiver-link' });
    if (verify && verify.state === 'verified') {
      guardianVerified = true;
      for (const f of delegatedCivilFields) {
        await runField(f, form.slug, { guardianLinkVerified: true });
      }
    }
  }

  // The manual climax button (social-cash combined-eligibility decision).
  async function runDecision() {
    if (manual) await runField(manual, form.slug);
  }

  // Per-slug load: reset state and kick off the right auto-fetch when the slug
  // changes (the component is reused across param changes, so onMount is not enough).
  // The effect tracks ONLY form.slug; a guard skips re-runs for the same slug and
  // untrack() keeps the state writes (and the writes inside runAutoFetch) from
  // retriggering the effect, which would otherwise loop. Effects do not run during
  // SSR, so the network calls and the seeded identity trace are browser-only.
  let loadedSlug = '';
  $effect(() => {
    const slug = form.slug;
    if (slug === loadedSlug) return;
    loadedSlug = slug;
    untrack(() => {
      results = {};
      consentGiven = false;
      guardianVerified = false;
      clientFeed.applyTrace(buildIdentityTrace(data.displayName));
      if (slug === 'education-grant') {
        // Only the non-delegated, non-gated fields auto-fetch now (household size).
        // The dependent selection + civil reads are gated behind consent.
        runAutoFetch(
          bodyFields.filter((f) => f.id !== 'caregiver-link'),
          slug
        );
      } else {
        runAutoFetch(autoFetchFields(form), slug);
      }
    });
  });
</script>

<section class="form">
  <header class="form-head">
    <a class="back" href="/services">All services</a>
    <h1>{form.title}</h1>
  </header>

  {#if identityField}
    {@const idf = identityField}
    <div class="field-row">
      <EvidenceField field={idf} result={identityResult} onTraceHover={(id) => ui.setActiveTrace(id)} />
    </div>
  {/if}

  {#if isEducation}
    <!-- Delegated two-hop set-piece. -->
    <div class="delegated">
      <div class="dependent">
        <h2>Your dependents</h2>
        <label class="dependent-pick">
          <input type="radio" name="dependent" checked />
          A child in my care: <strong>Miguel Santos &middot; NID-1001</strong>
        </label>
      </div>

      {#if !consentGiven}
        <div class="consent-card" data-testid="consent-card">
          <p class="consent-lead">Education Support Grant is asking to use, for this application only:</p>
          <table>
            <thead><tr><th>Authority</th><th>Data item</th><th>Purpose</th></tr></thead>
            <tbody>
              <tr><td>Civil Registry</td><td>Miguel's birth registration + date of birth</td><td>confirm the child and age</td></tr>
              <tr><td>Social Protection</td><td>your household composition</td><td>household-size eligibility</td></tr>
            </tbody>
          </table>
          <p class="not-disclosed">
            Not disclosed: Miguel's medical, school, or any other records. Those registries are never
            contacted (watch their nodes stay dark).
          </p>
          <button type="button" class="consent" onclick={giveConsent} data-testid="consent">I consent</button>
        </div>
      {/if}

      {#if consentGiven}
        <div class="field-row" data-testid="guardian-link">
          <EvidenceField
            field={guardianField}
            result={results['guardian-link-verified'] ?? inFlight(guardianField)}
            onTraceHover={(id) => ui.setActiveTrace(id)}
          />
        </div>

        <div class="civil-gate" class:unlocked={guardianVerified}>
          {#if !guardianVerified}
            <p class="locked-note" role="status" data-testid="civil-locked">
              Civil Registry will not answer until the guardian link is proven.
            </p>
          {/if}
          {#each delegatedCivilFields as field (field.id)}
            <div class="field-row">
              {#if guardianVerified}
                <EvidenceField
                  field={field}
                  result={results[field.id] ?? inFlight(field)}
                  onTraceHover={(id) => ui.setActiveTrace(id)}
                />
              {:else}
                <div class="locked-field">
                  <span class="lock-label">{field.label}</span>
                  <span class="lock-state">Locked until the link is proven</span>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}

      <!-- Household composition (Social, not delegated): auto-fetched on mount. -->
      {#each bodyFields.filter((f) => f.id !== 'caregiver-link') as field (field.id)}
        <div class="field-row">
          <EvidenceField field={field} result={results[field.id] ?? inFlight(field)} onTraceHover={(id) => ui.setActiveTrace(id)} />
        </div>
      {/each}
    </div>
  {:else}
    <!-- Generic form: the body fields auto-fill on mount. -->
    {#each bodyFields as field (field.id)}
      <div class="field-row">
        <EvidenceField field={field} result={results[field.id] ?? inFlight(field)} onTraceHover={(id) => ui.setActiveTrace(id)} />
      </div>
    {/each}
  {/if}

  <!-- Self-entry inputs (requested quantity / amount). -->
  {#each selfInputFields as field (field.id)}
    <div class="field-row">
      <EvidenceField field={field} result={null} />
    </div>
  {/each}

  <!-- The single manual climax button: combined-eligibility. -->
  {#if manual}
    {@const m = manual}
    <div class="decision">
      {#if results[m.id]}
        <div class="field-row">
          <EvidenceField field={m} result={results[m.id] ?? null} onTraceHover={(id) => ui.setActiveTrace(id)} />
        </div>
      {:else}
        <button type="button" class="check" onclick={runDecision} data-testid="check-eligibility">
          Check combined eligibility
        </button>
        <p class="decision-hint">Three authorities answer at once, and the result is signed with its reasons.</p>
      {/if}
    </div>
  {/if}

  {#if isCertificate}
    <WalletCloser configurationId="solmara-birth-certificate-vc" />
  {/if}

  {#if form.slug === 'social-cash'}
    <DenialBeat slug={form.slug} />
  {/if}
</section>

<style>
  .form {
    font-family: var(--font-ui);
    max-width: 40rem;
  }

  .form-head {
    margin-bottom: var(--space-6);
  }

  .back {
    font-size: var(--text-sm);
    color: var(--color-channel-fetch);
    text-decoration: none;
  }

  h1 {
    font-size: var(--text-2xl);
    font-weight: 700;
    color: var(--color-chrome);
    margin: var(--space-2) 0 0;
  }

  .field-row {
    margin-bottom: var(--space-4);
  }

  .delegated h2 {
    font-size: var(--text-lg);
    color: var(--color-chrome);
    margin: 0 0 var(--space-2);
  }

  .dependent-pick {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    font-size: var(--text-sm);
    color: var(--color-chrome);
    padding: var(--space-3);
    border: 1px solid color-mix(in srgb, var(--color-chrome) 14%, transparent);
    border-radius: var(--radius-md);
    margin-bottom: var(--space-4);
  }

  .consent-card {
    border: 1px solid var(--color-accent-seal);
    border-radius: var(--radius-md);
    padding: var(--space-4);
    margin-bottom: var(--space-4);
    background: var(--color-surface-raised);
  }

  .consent-lead {
    font-weight: 600;
    color: var(--color-chrome);
    margin: 0 0 var(--space-3);
  }

  .consent-card table {
    width: 100%;
    border-collapse: collapse;
    font-size: var(--text-sm);
    margin-bottom: var(--space-3);
  }

  .consent-card th {
    text-align: left;
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--color-channel-self);
    padding-bottom: var(--space-1);
  }

  .consent-card td {
    padding: var(--space-1) var(--space-2) var(--space-1) 0;
    color: var(--color-chrome);
    vertical-align: top;
  }

  .not-disclosed {
    font-size: var(--text-sm);
    color: var(--color-channel-amber);
    margin: 0 0 var(--space-3);
  }

  button.consent,
  button.check {
    background: var(--color-chrome);
    color: #fff;
    font-family: var(--font-ui);
    font-size: var(--text-base);
    font-weight: 600;
    border: none;
    border-radius: var(--radius-md);
    padding: var(--space-3) var(--space-6);
    cursor: pointer;
  }

  button.consent:focus-visible,
  button.check:focus-visible {
    outline: none;
    box-shadow: var(--ring-focus);
  }

  .civil-gate {
    border-left: 3px solid color-mix(in srgb, var(--color-ministry-civil) 50%, transparent);
    padding-left: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .civil-gate.unlocked {
    border-left-color: var(--color-ministry-civil);
  }

  .locked-note {
    font-size: var(--text-sm);
    color: var(--color-channel-self);
    font-style: italic;
    margin: 0 0 var(--space-3);
  }

  .locked-field {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    border: 1px dashed color-mix(in srgb, var(--color-chrome) 20%, transparent);
    border-radius: var(--radius-md);
    color: var(--color-channel-self);
    font-size: var(--text-sm);
  }

  .lock-state::before {
    content: '\1F512 ';
  }

  .decision-hint {
    font-size: var(--text-sm);
    color: var(--color-channel-self);
    margin: var(--space-2) 0 0;
  }
</style>
