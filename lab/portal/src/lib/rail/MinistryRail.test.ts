import { render } from '@testing-library/svelte';
import { describe, it, expect } from 'vitest';
import MinistryRail from './MinistryRail.svelte';
import { CANNED_EVENTS } from './canned-events';
import type { RailEvent } from '$lib/types';

// NOTE: `events` is a reserved Svelte mount option in @testing-library/svelte,
// so all props must be passed under the `props` key to avoid collision.

// ---- helpers ----

const VERIFY_EVENT: RailEvent = {
  id: 'v1',
  authority: 'agri',
  channel: 'verify',
  phase: 'request',
  ts: '2026-06-21T12:00:00.000Z'
};

const FETCH_EVENT: RailEvent = {
  id: 'f1',
  authority: 'social',
  channel: 'fetch',
  phase: 'request',
  ts: '2026-06-21T12:00:01.000Z'
};

const DENIED_EVENT: RailEvent = {
  id: 'd1',
  authority: 'civil',
  channel: 'denied',
  phase: 'request',
  ts: '2026-06-21T12:00:02.000Z'
};

// ---- motion-signature tests ----
// Assertions use data-motion and data-channel attributes, NEVER colour, to
// verify channels are distinguishable without relying on visual hue.

describe('MinistryRail motion signatures', () => {
  it('verify channel carries data-motion="pulse-target" (not colour-only)', () => {
    const { container } = render(MinistryRail, { props: { events: [VERIFY_EVENT] } });
    const packet = container.querySelector('[data-channel="verify"][data-motion]');
    expect(packet).not.toBeNull();
    expect(packet?.getAttribute('data-motion')).toBe('pulse-target');
  });

  it('fetch channel carries data-motion="travel-stamp" (not colour-only)', () => {
    const { container } = render(MinistryRail, { props: { events: [FETCH_EVENT] } });
    const packet = container.querySelector('[data-channel="fetch"][data-motion]');
    expect(packet).not.toBeNull();
    expect(packet?.getAttribute('data-motion')).toBe('travel-stamp');
  });

  it('denied channel carries data-motion="bounce" (not colour-only)', () => {
    const { container } = render(MinistryRail, { props: { events: [DENIED_EVENT] } });
    const packet = container.querySelector('[data-channel="denied"][data-motion]');
    expect(packet).not.toBeNull();
    expect(packet?.getAttribute('data-motion')).toBe('bounce');
  });

  it('all three channels produce distinct data-motion values', () => {
    const { container } = render(MinistryRail, {
      props: { events: [VERIFY_EVENT, FETCH_EVENT, DENIED_EVENT] }
    });
    // Use selector that targets packet circles (not the stamp-ring or node elements)
    const packets = container.querySelectorAll('.packet[data-motion]');
    const motions = new Set(Array.from(packets).map((p) => p.getAttribute('data-motion')));
    expect(motions.has('pulse-target')).toBe(true);
    expect(motions.has('travel-stamp')).toBe(true);
    expect(motions.has('bounce')).toBe(true);
    expect(motions.size).toBe(3);
  });

  it('verify and fetch packets are distinguishable by motion attribute alone', () => {
    const { container } = render(MinistryRail, {
      props: { events: [VERIFY_EVENT, FETCH_EVENT] }
    });
    const verifyPacket = container.querySelector('[data-channel="verify"][data-motion]');
    const fetchPacket = container.querySelector('[data-channel="fetch"][data-motion]');
    expect(verifyPacket).not.toBeNull();
    expect(fetchPacket).not.toBeNull();
    expect(verifyPacket?.getAttribute('data-motion')).not.toBe(
      fetchPacket?.getAttribute('data-motion')
    );
  });

  it('denied packet data-motion="bounce" differs from verify and fetch', () => {
    const { container } = render(MinistryRail, {
      props: { events: [VERIFY_EVENT, DENIED_EVENT] }
    });
    const verifyPacket = container.querySelector('[data-channel="verify"][data-motion]');
    const deniedPacket = container.querySelector('[data-channel="denied"][data-motion]');
    expect(verifyPacket?.getAttribute('data-motion')).toBe('pulse-target');
    expect(deniedPacket?.getAttribute('data-motion')).toBe('bounce');
    expect(verifyPacket?.getAttribute('data-motion')).not.toBe(
      deniedPacket?.getAttribute('data-motion')
    );
  });
});

// ---- node data attributes (colour never the only signal) ----
// The SVG is aria-hidden to avoid overwhelming screen readers with visual-only
// layout. Node states are exposed via data-node + data-state attributes so
// tests can verify state without colour. The sequence list (always in DOM) is
// the accessible state narrative.

describe('MinistryRail node data attributes', () => {
  it('all expected ministry nodes are rendered with data-node attributes', () => {
    const { container } = render(MinistryRail, { props: { events: [] } });
    expect(container.querySelector('[data-node="civil"]')).not.toBeNull();
    expect(container.querySelector('[data-node="agri"]')).not.toBeNull();
    expect(container.querySelector('[data-node="social"]')).not.toBeNull();
    expect(container.querySelector('[data-node="certs"]')).not.toBeNull();
    expect(container.querySelector('[data-node="health"]')).not.toBeNull();
  });

  it('idle nodes carry data-state="idle"', () => {
    const { container } = render(MinistryRail, { props: { events: [] } });
    const civil = container.querySelector('[data-node="civil"]');
    expect(civil?.getAttribute('data-state')).toBe('idle');
  });

  it('sealed event advances node to data-state="sealed"', () => {
    const sealedEvent: RailEvent = {
      id: 's1',
      authority: 'agri',
      channel: 'verify',
      phase: 'sealed',
      ts: '2026-06-21T12:00:05.000Z'
    };
    const { container } = render(MinistryRail, { props: { events: [sealedEvent] } });
    const agri = container.querySelector('[data-node="agri"]');
    expect(agri?.getAttribute('data-state')).toBe('sealed');
  });

  it('denied event advances node to data-state="denied" (not colour-only)', () => {
    const deniedFinalEvent: RailEvent = {
      id: 'df1',
      authority: 'civil',
      channel: 'denied',
      phase: 'denied',
      ts: '2026-06-21T12:00:06.000Z'
    };
    const { container } = render(MinistryRail, { props: { events: [deniedFinalEvent] } });
    const civil = container.querySelector('[data-node="civil"]');
    // State must be "denied" - this is the non-colour signal
    expect(civil?.getAttribute('data-state')).toBe('denied');
  });

  it('health node stays dark (idle) when no health events are provided', () => {
    const { container } = render(MinistryRail, { props: { events: CANNED_EVENTS } });
    const health = container.querySelector('[data-node="health"]');
    expect(health?.getAttribute('data-state')).toBe('idle');
  });

  it('renders a distinct glyph for Certs so it does not read as a Civil duplicate', () => {
    // Certs intentionally shares the Civil colour (served by the Civil Registry),
    // so the glyph must carry the difference: two blue 'C' circles otherwise read
    // as an accidental duplicate.
    const { container } = render(MinistryRail, { props: { events: [] } });
    const certsGlyph = container
      .querySelector('[data-node="certs"] text')
      ?.textContent?.trim();
    const civilGlyph = container
      .querySelector('[data-node="civil"] text')
      ?.textContent?.trim();
    expect(certsGlyph).toBeTruthy();
    expect(certsGlyph).not.toBe(civilGlyph);
  });

  it('request event sets node to data-state="in_flight"', () => {
    const { container } = render(MinistryRail, { props: { events: [VERIFY_EVENT] } });
    const agri = container.querySelector('[data-node="agri"]');
    expect(agri?.getAttribute('data-state')).toBe('in_flight');
  });

  it('captions the citizen seat so first-time viewers know the centre is the citizen', () => {
    const { container } = render(MinistryRail, { props: { events: [] } });
    const caption = container.querySelector('.citizen-label');
    expect(caption).not.toBeNull();
    expect(caption?.textContent?.trim()).toBe('Maria');
  });
});

// ---- reduced-motion fallback ----
// The sequence list renders in DOM at all times; CSS shows it under
// prefers-reduced-motion. Tests assert DOM presence and content without
// triggering the media query (jsdom doesn't support it).

describe('MinistryRail reduced-motion fallback', () => {
  it('renders a numbered-sequence list in the DOM with an aria-label', () => {
    const { container } = render(MinistryRail, { props: { events: CANNED_EVENTS } });
    const list = container.querySelector('.sequence-list');
    expect(list).not.toBeNull();
    expect(list?.getAttribute('aria-label')).toBeTruthy();
  });

  it('sequence list contains one item per event', () => {
    const { container } = render(MinistryRail, { props: { events: CANNED_EVENTS } });
    const items = container.querySelectorAll('.sequence-step');
    expect(items.length).toBe(CANNED_EVENTS.length);
  });

  it('each sequence item carries data-channel and data-phase (order is legible)', () => {
    const { container } = render(MinistryRail, {
      props: { events: [VERIFY_EVENT, FETCH_EVENT, DENIED_EVENT] }
    });
    const items = container.querySelectorAll('.sequence-step');
    expect(items[0]?.getAttribute('data-channel')).toBe('verify');
    expect(items[1]?.getAttribute('data-channel')).toBe('fetch');
    expect(items[2]?.getAttribute('data-channel')).toBe('denied');
  });

  it('each sequence item has a visible step number', () => {
    const { container } = render(MinistryRail, {
      props: { events: [VERIFY_EVENT, FETCH_EVENT] }
    });
    const nums = container.querySelectorAll('.step-num');
    expect(nums.length).toBe(2);
    expect(nums[0]?.textContent?.trim()).toBe('1.');
    expect(nums[1]?.textContent?.trim()).toBe('2.');
  });

  it('each sequence item has a visible channel label in text (not only colour)', () => {
    const { container } = render(MinistryRail, {
      props: { events: [VERIFY_EVENT, FETCH_EVENT, DENIED_EVENT] }
    });
    const channelLabels = container.querySelectorAll('.step-channel');
    const texts = Array.from(channelLabels).map((el) => el.textContent?.trim());
    expect(texts).toContain('verify');
    expect(texts).toContain('fetch');
    expect(texts).toContain('denied');
  });

  it('empty events list shows the empty-state message', () => {
    const { container } = render(MinistryRail, { props: { events: [] } });
    const empty = container.querySelector('.sequence-empty');
    expect(empty).not.toBeNull();
  });

  it('two-hop events appear in order: Social first, then Civil', () => {
    const twoHop: RailEvent[] = [
      { id: 'h1', authority: 'social', channel: 'verify', phase: 'request', ts: '2026-06-21T12:00:00.000Z' },
      { id: 'h2', authority: 'social', channel: 'verify', phase: 'sealed',  ts: '2026-06-21T12:00:02.000Z' },
      { id: 'h3', authority: 'civil',  channel: 'fetch',  phase: 'request', ts: '2026-06-21T12:00:03.000Z' },
      { id: 'h4', authority: 'civil',  channel: 'fetch',  phase: 'sealed',  ts: '2026-06-21T12:00:05.000Z' }
    ];
    const { container } = render(MinistryRail, { props: { events: twoHop } });
    const items = container.querySelectorAll('.sequence-step');
    expect(items[0]?.getAttribute('data-authority')).toBe('social');
    expect(items[2]?.getAttribute('data-authority')).toBe('civil');
  });

  it('sequence step text names the authority (not just colour)', () => {
    const { container } = render(MinistryRail, { props: { events: [VERIFY_EVENT] } });
    const stepText = container.querySelector('.step-text');
    // Should include the human-readable authority name
    expect(stepText?.textContent).toMatch(/agriculture/i);
  });
});

// ---- canned events coverage ----

describe('CANNED_EVENTS covers all required scenarios', () => {
  it('contains at least one verify event', () => {
    expect(CANNED_EVENTS.some((e) => e.channel === 'verify')).toBe(true);
  });

  it('contains at least one fetch event', () => {
    expect(CANNED_EVENTS.some((e) => e.channel === 'fetch')).toBe(true);
  });

  it('contains at least one denied event', () => {
    expect(CANNED_EVENTS.some((e) => e.channel === 'denied')).toBe(true);
  });

  it('contains a two-hop sequence (social then civil)', () => {
    const socialVerify = CANNED_EVENTS.findIndex(
      (e) => e.authority === 'social' && e.channel === 'verify'
    );
    const civilFetch = CANNED_EVENTS.findIndex(
      (e) => e.authority === 'civil' && e.channel === 'fetch'
    );
    expect(socialVerify).toBeGreaterThanOrEqual(0);
    expect(civilFetch).toBeGreaterThan(socialVerify);
  });
});
