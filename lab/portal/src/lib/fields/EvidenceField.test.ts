import { render, screen, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';
import EvidenceField from './EvidenceField.svelte';
import type { ClaimResult, Field } from '$lib/types';

// ---- Fixtures ----------------------------------------------------------

const selfField: Field = {
  id: 'full-name',
  label: 'Full name',
  kind: 'self',
  selfPlaceholder: 'Type your full legal name'
};

const verifyField: Field = {
  id: 'farmer-status',
  label: 'Farmer registration',
  kind: 'verify',
  claim: 'registered-farmer',
  notary: 'agri'
};

const fetchField: Field = {
  id: 'date-of-birth',
  label: 'Date of birth',
  kind: 'fetch',
  claim: 'date-of-birth',
  notary: 'civil'
};

const decisionField: Field = {
  id: 'combined-eligibility',
  label: 'Combined eligibility',
  kind: 'decision',
  notary: 'social',
  manual: true
};

function result(partial: Partial<ClaimResult> & { state: ClaimResult['state'] }): ClaimResult {
  return {
    display: '',
    traceId: 'event-1',
    ...partial
  };
}

// ---- self -------------------------------------------------------------

describe('EvidenceField - self', () => {
  it('renders the idle input with the self placeholder when result is null', () => {
    render(EvidenceField, { field: selfField, result: null });
    const input = screen.getByPlaceholderText('Type your full legal name');
    expect(input).toBeInTheDocument();
  });

  it('renders the locked identity chip with "self - from eSignet" when prefilled', () => {
    render(EvidenceField, {
      field: selfField,
      result: result({ state: 'prefilled', display: 'Maria Santos · NID-2001' })
    });
    expect(screen.getByText('Maria Santos · NID-2001')).toBeInTheDocument();
    expect(screen.getByText(/self - from eSignet/i)).toBeInTheDocument();
  });
});

// ---- verify -----------------------------------------------------------

describe('EvidenceField - verify', () => {
  it('shows the GREEN verified badge naming the authority and the proof link', () => {
    render(EvidenceField, {
      field: verifyField,
      result: result({
        state: 'verified',
        display: 'Verified - registered farmer',
        authority: 'agri',
        asOf: '2026-05',
        traceId: 'event-2'
      })
    });
    expect(screen.getByText('Verified - registered farmer')).toBeInTheDocument();
    expect(screen.getByText(/verified by Agriculture/i)).toBeInTheDocument();
    expect(screen.getByText(/2026-05/)).toBeInTheDocument();
    expect(screen.getByText(/event-2 in proof inspector/i)).toBeInTheDocument();
  });

  it('a false predicate STILL shows the "verified by {authority}" badge plus reason code', () => {
    render(EvidenceField, {
      field: verifyField,
      result: result({
        state: 'false',
        display: 'Not eligible - voucher already redeemed',
        authority: 'agri',
        reasonCode: 'VR-RED-02'
      })
    });
    // The signed badge survives a negative answer (a false answer is still proven).
    expect(screen.getByText(/verified by Agriculture/i)).toBeInTheDocument();
    expect(screen.getByText('VR-RED-02')).toBeInTheDocument();
    // It must read as a signed "no", not as an error.
    expect(screen.queryByText(/Couldn't reach/i)).not.toBeInTheDocument();
  });
});

// ---- fetch ------------------------------------------------------------

describe('EvidenceField - fetch', () => {
  it('renders a locked, fetched value naming the authority', () => {
    render(EvidenceField, {
      field: fetchField,
      result: result({
        state: 'fetched',
        display: '2019-03-14',
        authority: 'civil',
        asOf: 'today'
      })
    });
    expect(screen.getByText('2019-03-14')).toBeInTheDocument();
    expect(screen.getByText(/fetched from Civil Registry/i)).toBeInTheDocument();
  });

  it('stale value keeps the fetched badge, adds a freshness warning and a Re-check action', async () => {
    const onRecheck = vi.fn();
    render(EvidenceField, {
      field: fetchField,
      result: result({
        state: 'stale',
        display: '4 members · 1 child',
        authority: 'social',
        asOf: '2024-09'
      }),
      onRecheck
    });
    expect(screen.getByText(/fetched from Social Welfare/i)).toBeInTheDocument();
    expect(screen.getByText(/older than the 6-month rule/i)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: /Re-check/i }));
    expect(onRecheck).toHaveBeenCalledOnce();
  });
});

// ---- decision / waits -------------------------------------------------

describe('EvidenceField - waits name the authority', () => {
  it('in_flight names the authority and never shows a bare "Loading..."', () => {
    render(EvidenceField, {
      field: decisionField,
      result: result({ state: 'in_flight', display: '', authority: 'social' })
    });
    expect(screen.getByText(/Social Welfare/i)).toBeInTheDocument();
    expect(screen.queryByText(/^Loading\.\.\.$/)).not.toBeInTheDocument();
  });

  it('slow shows the live-call reassurance with elapsed seconds and a keep-waiting action', async () => {
    const onKeepWaiting = vi.fn();
    render(EvidenceField, {
      field: decisionField,
      result: result({ state: 'slow', display: '', authority: 'social' }),
      elapsedMs: 12000,
      onKeepWaiting
    });
    expect(screen.getByText(/Still checking with Social Welfare/i)).toBeInTheDocument();
    expect(screen.getByText(/\(12s\)/)).toBeInTheDocument();
    expect(screen.getByText(/it's a live call/i)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: /keep waiting/i }));
    expect(onKeepWaiting).toHaveBeenCalledOnce();
  });
});

// ---- error & ambiguous branches --------------------------------------

describe('EvidenceField - error and ambiguous', () => {
  it('error is calm and scoped, reassures other evidence is unaffected, offers Try again', async () => {
    const onRetry = vi.fn();
    render(EvidenceField, {
      field: fetchField,
      result: result({ state: 'error', display: '', authority: 'social' }),
      onRetry
    });
    expect(screen.getByText(/Couldn't reach Social Welfare just now/i)).toBeInTheDocument();
    expect(screen.getByText(/Other evidence is unaffected/i)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: /Try again/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('ambiguous shows the Resolve affordance and never collapses to a negative', async () => {
    const onResolve = vi.fn();
    render(EvidenceField, {
      field: fetchField,
      result: result({ state: 'ambiguous', display: '', authority: 'civil' }),
      onResolve
    });
    expect(screen.getByText(/More than one record matched/i)).toBeInTheDocument();
    expect(screen.getByText(/We won't guess/i)).toBeInTheDocument();
    // It must not read as a denial/false answer.
    expect(screen.queryByText(/Not eligible/i)).not.toBeInTheDocument();
    const resolve = screen.getByRole('button', { name: /Resolve/i });
    expect(resolve).toBeInTheDocument();
    await fireEvent.click(resolve);
    expect(onResolve).toHaveBeenCalledOnce();
  });

  it('recovered announces the retry landed', () => {
    render(EvidenceField, {
      field: fetchField,
      result: result({
        state: 'recovered',
        display: '2019-03-14',
        authority: 'social'
      })
    });
    expect(screen.getByText(/Recovered · Social Welfare answered/i)).toBeInTheDocument();
    expect(screen.getByText(/retried just now/i)).toBeInTheDocument();
  });
});

// ---- colour is never the only signal ----------------------------------

describe('EvidenceField - colour-not-alone discipline', () => {
  const colouredStates: Array<{ state: ClaimResult['state']; display: string }> = [
    { state: 'verified', display: 'Verified - registered farmer' },
    { state: 'false', display: 'Not eligible' },
    { state: 'fetched', display: '2019-03-14' },
    { state: 'stale', display: '4 members' },
    { state: 'error', display: '' },
    { state: 'ambiguous', display: '' }
  ];

  for (const { state, display } of colouredStates) {
    it(`state "${state}" pairs its channel colour with an icon and text`, () => {
      const { container } = render(EvidenceField, {
        field: verifyField,
        result: result({ state, display, authority: 'agri', reasonCode: 'VR-RED-02' })
      });
      // An icon (svg) is present.
      expect(container.querySelector('svg')).not.toBeNull();
      // A non-empty text label is present (not colour alone).
      expect(container.textContent?.trim().length ?? 0).toBeGreaterThan(0);
    });
  }
});

// ---- proof binding ----------------------------------------------------

describe('EvidenceField - proof binding', () => {
  it('hovering the proof link fires onTraceHover with the traceId', async () => {
    const onTraceHover = vi.fn();
    render(EvidenceField, {
      field: verifyField,
      result: result({
        state: 'verified',
        display: 'Verified',
        authority: 'agri',
        traceId: 'event-7'
      }),
      onTraceHover
    });
    const link = screen.getByText(/event-7 in proof inspector/i);
    await fireEvent.mouseEnter(link);
    expect(onTraceHover).toHaveBeenCalledWith('event-7');
  });
});
