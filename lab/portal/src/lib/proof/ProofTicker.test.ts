import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import ProofTicker from './ProofTicker.svelte';
import { CANNED_TRACES } from './canned-traces.js';
import { buildIdentityTrace } from '$lib/forms/identity';

describe('ProofTicker', () => {
  it('has role="log" as an ARIA live-region', () => {
    render(ProofTicker, { props: { traces: [] } });
    const ticker = screen.getByRole('log');
    expect(ticker).toBeInTheDocument();
  });

  it('has aria-live="polite"', () => {
    render(ProofTicker, { props: { traces: [] } });
    const ticker = screen.getByRole('log');
    expect(ticker).toHaveAttribute('aria-live', 'polite');
  });

  it('is labelled as the proof audit log', () => {
    render(ProofTicker, { props: { traces: [] } });
    expect(screen.getByRole('log', { name: /proof audit log/i })).toBeInTheDocument();
  });

  it('renders an entry for each trace', () => {
    render(ProofTicker, { props: { traces: CANNED_TRACES } });
    const ticker = screen.getByRole('log');
    // Each trace produces one entry with an aria-label containing its field id or authority
    const entries = ticker.querySelectorAll('.tick-entry');
    expect(entries.length).toBe(CANNED_TRACES.length);
  });

  it('is always present when mounted (even with zero traces)', () => {
    render(ProofTicker, { props: { traces: [] } });
    // The ticker DOM element must be present
    const ticker = screen.getByRole('log');
    expect(ticker).toBeInTheDocument();
  });

  it('renders status text for each trace', () => {
    render(ProofTicker, { props: { traces: CANNED_TRACES } });

    // The in-flight trace renders "in flight"
    const inFlightEntries = screen.getAllByText('in flight');
    expect(inFlightEntries.length).toBeGreaterThan(0);

    // The ok traces render "verified"
    const verifiedEntries = screen.getAllByText('verified');
    expect(verifiedEntries.length).toBeGreaterThan(0);

    // The denied trace renders "denied"
    const deniedEntries = screen.getAllByText('denied');
    expect(deniedEntries.length).toBeGreaterThan(0);
  });

  it('renders authority names', () => {
    render(ProofTicker, { props: { traces: CANNED_TRACES } });
    // Agriculture entries
    expect(screen.getAllByText('Agri').length).toBeGreaterThan(0);
    // Social entries
    expect(screen.getAllByText('Social').length).toBeGreaterThan(0);
    // Civil entries
    expect(screen.getAllByText('Civil').length).toBeGreaterThan(0);
  });

  it('labels the identity-binding trace as eSignet, never Unknown', () => {
    // The identity trace carries no Notary `authority` (eSignet is not one of the
    // four Notaries), so a naive authority lookup falls through to "Unknown". It
    // must instead name its issuer so the very first audit line reads honestly.
    render(ProofTicker, { props: { traces: [buildIdentityTrace('Maria Santos')] } });
    expect(screen.queryByText('Unknown')).toBeNull();
    expect(screen.getByText('eSignet')).toBeInTheDocument();
  });
});
