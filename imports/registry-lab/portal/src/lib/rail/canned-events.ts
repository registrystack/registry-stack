// Canned RailEvent[] for the rail gallery demo and unit tests.
// Covers: verify (pulse), fetch (travel-stamp), denied (bounce-back),
// and a two-hop sequence (Social verify then Civil fetch).
import type { RailEvent } from '$lib/types';

export const CANNED_EVENTS: RailEvent[] = [
  // --- simple verify: agriculture registered-farmer
  {
    id: 'rail-1a',
    authority: 'agri',
    channel: 'verify',
    phase: 'request',
    ts: '2026-06-21T12:04:05.000Z'
  },
  {
    id: 'rail-1b',
    authority: 'agri',
    channel: 'verify',
    phase: 'sealed',
    ts: '2026-06-21T12:04:09.000Z'
  },

  // --- simple fetch: social household-composition
  {
    id: 'rail-2a',
    authority: 'social',
    channel: 'fetch',
    phase: 'request',
    ts: '2026-06-21T12:04:10.000Z'
  },
  {
    id: 'rail-2b',
    authority: 'social',
    channel: 'fetch',
    phase: 'sealed',
    ts: '2026-06-21T12:04:13.000Z'
  },

  // --- denial: cross-person query NID-1010 against Civil
  {
    id: 'rail-3a',
    authority: 'civil',
    channel: 'denied',
    phase: 'request',
    ts: '2026-06-21T12:04:14.000Z'
  },
  {
    id: 'rail-3b',
    authority: 'civil',
    channel: 'denied',
    phase: 'denied',
    ts: '2026-06-21T12:04:15.000Z'
  },

  // --- two-hop: Social verifies guardianship, then Civil fetches birth date
  {
    id: 'rail-4a',
    authority: 'social',
    channel: 'verify',
    phase: 'request',
    ts: '2026-06-21T12:04:20.000Z'
  },
  {
    id: 'rail-4b',
    authority: 'social',
    channel: 'verify',
    phase: 'sealed',
    ts: '2026-06-21T12:04:22.000Z'
  },
  {
    id: 'rail-4c',
    authority: 'civil',
    channel: 'fetch',
    phase: 'request',
    ts: '2026-06-21T12:04:23.000Z'
  },
  {
    id: 'rail-4d',
    authority: 'civil',
    channel: 'fetch',
    phase: 'sealed',
    ts: '2026-06-21T12:04:26.000Z'
  }
];
