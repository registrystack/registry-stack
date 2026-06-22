import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import ProofInspector from './ProofInspector.svelte';
import { CANNED_TRACES } from './canned-traces.js';
import type { ProofTrace } from '$lib/types';

// Single trace with all depths populated
const verifiedTrace: ProofTrace = {
  id: 'event-2',
  seq: 2,
  fieldId: 'registered-farmer',
  authority: 'agri',
  headline: 'Confirmed by Agriculture: Maria did not have to prove this herself',
  answered: 'Agriculture answered: registered-farmer = true',
  notDisclosed: 'Only the yes/no, no farm details or parcel coordinates',
  status: 'ok',
  ts: '2026-06-21T12:04:09.000Z',
  request: {
    method: 'POST',
    url: 'https://agri-citizen-notary.solmara.example/v1/evaluations',
    body: {
      claim: 'registered-farmer',
      purpose: 'agri_subsidy',
      relationship: 'self'
    }
  },
  response: {
    status: 200,
    body: {
      registered: true,
      source_authority: 'Agriculture',
      as_of: '2026-05-01'
    }
  },
  proof: {
    signedBy: 'Agriculture Ministry Notary',
    algorithm: 'EdDSA/Ed25519',
    issuerKey: 'did:web:agri-citizen-notary.solmara.example',
    holderBound: 'NID-2001 (session-bound, not echoed)',
    credential: 'SD-JWT VC',
    auditId: 'AUD-20260621-AGR-0042'
  }
};

const denialTrace: ProofTrace = {
  id: 'event-4',
  seq: 4,
  fieldId: 'person-is-alive',
  authority: 'civil',
  headline: 'Denied by Civil Registry: subject mismatch, no data read',
  answered: 'Civil answered: person-is-alive = denied (subject_mismatch)',
  notDisclosed: 'No data was read; the query was rejected before any registry access',
  status: 'denied',
  ts: '2026-06-21T12:04:15.000Z',
  request: {
    method: 'POST',
    url: 'https://civil-citizen-notary.solmara.example/v1/evaluations',
    body: {
      claim: 'person-is-alive',
      purpose: 'social_cash',
      relationship: 'self'
    }
  },
  response: {
    status: 403,
    body: {
      error: 'subject_mismatch',
      source_authority: 'Civil Registry',
      message: 'Token subject does not match requested target'
    }
  }
};

describe('ProofInspector', () => {
  describe('Depth 1 - always visible without expansion', () => {
    it('renders the "Not disclosed:" line at depth 1 without any expansion', () => {
      render(ProofInspector, { props: { traces: [verifiedTrace] } });

      // The "Not disclosed:" label must be visible without expanding any accordion
      const labels = screen.getAllByText('Not disclosed:');
      expect(labels.length).toBeGreaterThan(0);

      // The not-disclosed text itself is always present in the DOM
      expect(
        screen.getByText('Only the yes/no, no farm details or parcel coordinates')
      ).toBeInTheDocument();
    });

    it('renders the headline at depth 1', () => {
      render(ProofInspector, { props: { traces: [verifiedTrace] } });
      expect(
        screen.getByText('Confirmed by Agriculture: Maria did not have to prove this herself')
      ).toBeInTheDocument();
    });

    it('renders the answered line at depth 1', () => {
      render(ProofInspector, { props: { traces: [verifiedTrace] } });
      expect(
        screen.getByText('Agriculture answered: registered-farmer = true')
      ).toBeInTheDocument();
    });

    it('renders "Not disclosed:" for all canned traces without expansion', () => {
      render(ProofInspector, { props: { traces: CANNED_TRACES } });
      // Every trace has a not-disclosed line; count the labels
      const labels = screen.getAllByText('Not disclosed:');
      expect(labels.length).toBe(CANNED_TRACES.length);
    });

    it('renders the denial trace "Not disclosed:" at depth 1', () => {
      render(ProofInspector, { props: { traces: [denialTrace] } });
      expect(
        screen.getByText('No data was read; the query was rejected before any registry access')
      ).toBeInTheDocument();
    });
  });

  describe('Bearer token redaction', () => {
    it('never renders a real bearer token in the DOM', async () => {
      const { container } = render(ProofInspector, { props: { traces: CANNED_TRACES } });

      // Expand depth 2 for the verified trace
      const expandBtns = screen.getAllByText(/Request and response/);
      for (const btn of expandBtns) {
        await fireEvent.click(btn);
      }

      const html = container.innerHTML;

      // Must never contain a raw token value. The only bearer-shaped text
      // should be the (redacted) placeholder dots.
      expect(html).not.toMatch(/Bearer [A-Za-z0-9+/=._-]{8,}/);

      // The redacted placeholder MUST be present after expanding
      expect(html).toContain('(redacted)');
    });

    it('renders redacted dots instead of a real token value', async () => {
      const { container } = render(ProofInspector, { props: { traces: [verifiedTrace] } });

      const expandBtn = screen.getByText(/Request and response/);
      await fireEvent.click(expandBtn);

      // Should find the redacted dots and the "(redacted)" label
      const redactedEl = container.querySelector('.redacted');
      expect(redactedEl).toBeInTheDocument();
      expect(container.innerHTML).toContain('(redacted)');
    });
  });

  describe('Copy-as-curl', () => {
    it('curl output contains $NOTARY_TOKEN placeholder, not a real token', async () => {
      const writtenTexts: string[] = [];
      const mockWriteText = vi.fn((text: string) => {
        writtenTexts.push(text);
        return Promise.resolve();
      });

      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText: mockWriteText },
        writable: true,
        configurable: true
      });

      render(ProofInspector, { props: { traces: [verifiedTrace] } });

      // Expand depth 2
      const expandBtn = screen.getByText(/Request and response/);
      await fireEvent.click(expandBtn);

      // Click the copy-as-curl button
      const copyBtn = screen.getByLabelText('Copy request as curl command');
      await fireEvent.click(copyBtn);

      expect(mockWriteText).toHaveBeenCalledOnce();

      const curlCmd = writtenTexts[0];

      // Must contain the placeholder token variable
      expect(curlCmd).toContain('$NOTARY_TOKEN');

      // Must NOT contain any real token material
      // Real tokens would be long base64 or JWT-format strings
      expect(curlCmd).not.toMatch(/Bearer [A-Za-z0-9+/=._-]{8,}/);

      // Must include the request method and URL
      expect(curlCmd).toContain('POST');
      expect(curlCmd).toContain(verifiedTrace.request.url);
    });
  });

  describe('Connected state', () => {
    it('does not show reconnecting pill when connected', () => {
      render(ProofInspector, { props: { traces: [], connected: true } });
      expect(screen.queryByText(/Reconnecting to audit feed/i)).not.toBeInTheDocument();
    });

    it('shows the reconnecting pill when disconnected', () => {
      render(ProofInspector, { props: { traces: [], connected: false } });
      expect(screen.getByText(/Reconnecting to audit feed/i)).toBeInTheDocument();
    });
  });

  describe('In-flight skeleton', () => {
    it('renders in-flight traces at the top with heartbeat indicator', () => {
      const inFlightTrace: ProofTrace = CANNED_TRACES.find(
        (t) => t.status === 'in_flight'
      )!;
      render(ProofInspector, { props: { traces: [inFlightTrace] } });

      // The heartbeat dot is rendered with aria-label "In flight"
      expect(screen.getByLabelText('In flight')).toBeInTheDocument();
    });
  });

  describe('All canned traces render', () => {
    it('renders all five canned traces without error', () => {
      const { container } = render(ProofInspector, { props: { traces: CANNED_TRACES } });
      // All 5 event ids should appear
      for (const trace of CANNED_TRACES) {
        expect(container.innerHTML).toContain(trace.id);
      }
    });
  });
});
