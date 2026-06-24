import type { FieldState } from '$lib/types';

// The channel a state belongs to. Drives the load-bearing accent colour, which
// is ALWAYS paired with an icon and text (colour is never the only signal).
export type Channel = 'self' | 'verify' | 'amber' | 'fetch' | 'denied' | 'neutral';

// The icon glyph drawn for a state. The component maps each name to an inline
// SVG so the icon is a real, non-colour signal next to every status.
export type StatusIcon =
  | 'lock' // locked identity / fetched value
  | 'check' // a true predicate / a recovered success
  | 'cross' // a false predicate (signed "no")
  | 'spinner' // an active wait
  | 'warning' // stale, error, ambiguous (caution, not failure)
  | 'pencil'; // self-entry idle input

// The visual treatment for one state, derived purely from the FieldState.
export type StatePresentation = {
  channel: Channel;
  icon: StatusIcon;
  // ARIA role for the status region: 'status' for routine updates, 'alert' for
  // attention-needing states (error / ambiguous), so SR users are nudged.
  ariaRole: 'status' | 'alert';
  // Whether the field reads as locked (a settled, authoritative value).
  locked: boolean;
};

const PRESENTATION: Record<FieldState, StatePresentation> = {
  idle: { channel: 'self', icon: 'pencil', ariaRole: 'status', locked: false },
  prefilled: { channel: 'self', icon: 'lock', ariaRole: 'status', locked: true },
  in_flight: { channel: 'neutral', icon: 'spinner', ariaRole: 'status', locked: false },
  slow: { channel: 'neutral', icon: 'spinner', ariaRole: 'status', locked: false },
  verified: { channel: 'verify', icon: 'check', ariaRole: 'status', locked: false },
  false: { channel: 'amber', icon: 'cross', ariaRole: 'status', locked: false },
  fetched: { channel: 'fetch', icon: 'lock', ariaRole: 'status', locked: true },
  stale: { channel: 'fetch', icon: 'lock', ariaRole: 'status', locked: true },
  recovered: { channel: 'verify', icon: 'check', ariaRole: 'status', locked: false },
  error: { channel: 'neutral', icon: 'warning', ariaRole: 'alert', locked: false },
  ambiguous: { channel: 'neutral', icon: 'warning', ariaRole: 'alert', locked: false }
};

export function presentationFor(state: FieldState): StatePresentation {
  return PRESENTATION[state];
}

// States where a fresh value/answer just settled and should play the stamp
// animation (a seal hitting paper). Reduced-motion falls back to a discrete
// state change; the component honours the media query.
export function stampsOnEntry(state: FieldState): boolean {
  return state === 'fetched' || state === 'recovered';
}
