// Shared client UI state. Small on purpose: the field <-> proof binding crosses a
// layout boundary (the proof-link lives in a form field; the ProofInspector lives
// in the root layout chrome), so the active trace id lives in one shared store the
// field sets on hover and the inspector reads to highlight. Svelte 5 runes.

class UiStore {
  // The trace id the user is currently hovering (or undefined). The inspector
  // highlights and scrolls to this entry; the field pulses its own link.
  activeTrace = $state<string | undefined>(undefined);

  setActiveTrace(id: string | undefined): void {
    this.activeTrace = id;
  }
}

export const ui = new UiStore();
